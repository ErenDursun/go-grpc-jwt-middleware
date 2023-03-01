package jwt_test

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/ErenDursun/go-grpc-jwt-middleware/jwt"
	extJwt "github.com/golang-jwt/jwt/v4"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type HMACTestSuite struct {
	suite.Suite

	goodAuthToken   string
	badAuthToken    string
	brokenAuthToken string

	healthCheckReq *grpc_health_v1.HealthCheckRequest
	bufDialer      func(context.Context, string) (net.Conn, error)
	client         grpc_health_v1.HealthClient
	client2        grpc_health_v1.HealthClient
}

func (suite *HMACTestSuite) SetupSuite() {
	claims := extJwt.MapClaims{
		"foo": "bar",
		"nbf": float64(time.Date(2023, 01, 01, 12, 0, 0, 0, time.UTC).Unix()),
	}
	suite.goodAuthToken = newSignedToken(extJwt.SigningMethodHS256, claims, []byte("good_secret"))
	suite.badAuthToken = newSignedToken(extJwt.SigningMethodHS256, claims, []byte("bad_secret"))
	suite.brokenAuthToken = "broken_auth_token"

	authFunc := jwt.NewAuthFunc([]byte("good_secret"))

	srvOpts := []grpc.ServerOption{
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authFunc)),
		// TODO add certs: https://go.dev/src/crypto/tls/generate_cert.go
	}

	srv := grpc.NewServer(srvOpts...)
	s := &assertingServer{
		assertFunc: func(ctx context.Context) {
			unassertedToken := ctx.Value(jwt.DefaultContextKey)
			if assert.IsType(suite.T(), &extJwt.Token{}, unassertedToken) {
				token := unassertedToken.(*extJwt.Token)
				assert.Equal(suite.T(), claims, token.Claims, "claims from goodAuthToken must be passed around")
				// TODO assert SignatureMethod, etc...
			}
		},
	}
	grpc_health_v1.RegisterHealthServer(srv, s)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()

	suite.bufDialer = func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	suite.healthCheckReq = &grpc_health_v1.HealthCheckRequest{}
}

func (suite *HMACTestSuite) SetupTest() {
	conn, err := grpc.DialContext(context.TODO(), "bufnet", grpc.WithContextDialer(suite.bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		suite.FailNowf("failed to dial bufnet", "%w", err)
	}
	// defer conn.Close()
	suite.client = grpc_health_v1.NewHealthClient(conn)

	// client with per RPC credentials
	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: suite.goodAuthToken}}
	newDialOpts := []grpc.DialOption{
		grpc.WithContextDialer(suite.bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(grpcCreds),
		grpc.WithBlock(),
	}
	conn2, err := grpc.DialContext(context.TODO(), "bufnet", newDialOpts...)
	if err != nil {
		suite.FailNowf("failed to dial bufnet:", "%w", err)
	}
	// defer conn2.Close()
	suite.client2 = grpc_health_v1.NewHealthClient(conn2)
}

func (suite *HMACTestSuite) TearDownSuite() {
	// TODO
}

func TestHMACTestSuite(t *testing.T) {
	suite.Run(t, new(HMACTestSuite))
}

func (suite *HMACTestSuite) TestUnary_NoAuth() {
	// given

	// when
	_, err := suite.client.Check(context.TODO(), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *HMACTestSuite) TestUnary_BrokenAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.brokenAuthToken), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *HMACTestSuite) TestUnary_BadAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.badAuthToken), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *HMACTestSuite) TestUnary_GoodAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.goodAuthToken), suite.healthCheckReq)

	// then
	require.NoError(suite.T(), err, "no error must occur")
}

func (s *HMACTestSuite) TestUnary_GoodAuthWithPerRpcCredentials() {
	_, err := s.client2.Check(context.TODO(), s.healthCheckReq)
	require.NoError(s.T(), err, "no error must occur")
}

func (s *HMACTestSuite) TestStream_NoAuth() {
	stream, err := s.client.Watch(context.TODO(), s.healthCheckReq)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	assert.Equal(s.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (s *HMACTestSuite) TestStream_BrokenAuth() {
	stream, err := s.client.Watch(ctxWithToken(context.TODO(), "bearer", s.brokenAuthToken), s.healthCheckReq)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	assert.Equal(s.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (s *HMACTestSuite) TestStream_BadAuth() {
	stream, err := s.client.Watch(ctxWithToken(context.TODO(), "bearer", s.badAuthToken), s.healthCheckReq)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	assert.Equal(s.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (s *HMACTestSuite) TestStream_GoodAuth() {
	stream, err := s.client.Watch(ctxWithToken(context.TODO(), "Bearer", s.goodAuthToken), s.healthCheckReq)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	pong, err := stream.Recv()
	require.NoError(s.T(), err, "no error must occur")
	require.NotNil(s.T(), pong, "pong must not be nil")
}

// func (s *HMACTestSuite) TestStream_GoodAuthWithPerRpcCredentials() {
// 	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: s.goodAuthToken}}
// 	client := s.NewClient(grpc.WithPerRPCCredentials(grpcCreds))
// 	stream, err := client.PingList(context.TODO(), s.healthCheckReq)
// 	require.NoError(s.T(), err, "should not fail on establishing the stream")
// 	pong, err := stream.Recv()
// 	require.NoError(s.T(), err, "no error must occur")
// 	require.NotNil(s.T(), pong, "pong must not be nil")
// }
