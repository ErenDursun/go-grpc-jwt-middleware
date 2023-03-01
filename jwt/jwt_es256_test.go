package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type ES256TestSuite struct {
	suite.Suite

	goodAuthToken   string
	badAuthToken    string
	brokenAuthToken string

	helloReq  *grpc_health_v1.HealthCheckRequest
	bufDialer func(context.Context, string) (net.Conn, error)
	client    grpc_health_v1.HealthClient
	// client2 pb.GreeterClient
}

// TODO
func (suite *ES256TestSuite) SetupSuite() {
	claims := extJwt.MapClaims{
		"foo": "bar",
		"nbf": float64(time.Date(2023, 01, 01, 12, 0, 0, 0, time.UTC).Unix()),
	}
	goodKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.goodAuthToken = newSignedToken(extJwt.SigningMethodES256, claims, goodKey)
	badKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.badAuthToken = newSignedToken(extJwt.SigningMethodES256, claims, badKey)
	suite.brokenAuthToken = "broken_auth_token"

	authFunc := jwt.NewAuthFuncWithConfig(
		jwt.Config{
			SigningMethod: extJwt.SigningMethodES256.Name,
			SigningKey:    &goodKey.PublicKey,
		},
	)

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

	suite.helloReq = &grpc_health_v1.HealthCheckRequest{}
}

func (suite *ES256TestSuite) SetupTest() {
	conn, err := grpc.DialContext(context.TODO(), "bufnet", grpc.WithContextDialer(suite.bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		suite.FailNowf("failed to dial bufnet", "%w", err)
	}
	// defer conn.Close()
	suite.client = grpc_health_v1.NewHealthClient(conn)

	// client with per RPC credentials
	// grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: goodAuthToken}}
	// conn2, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(grpcCreds))
	// if err != nil {
	// 	t.Fatalf("Failed to dial bufnet: %v", err)
	// }
	// defer conn2.Close()
	// suite.client2 := pb.NewGreeterClient(conn2)
}

func TestES256TestSuite(t *testing.T) {
	suite.Run(t, new(ES256TestSuite))
}

func (suite *ES256TestSuite) TestUnary_NoAuth() {
	// given

	// when
	_, err := suite.client.Check(context.TODO(), suite.helloReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_BrokenAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.brokenAuthToken), suite.helloReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_BadAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.badAuthToken), suite.helloReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_GoodAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.goodAuthToken), suite.helloReq)

	// then
	require.NoError(suite.T(), err, "no error must occur")
}

// func (s *ES256TestSuite) TestUnary_GoodAuthWithPerRpcCredentials() {
// 	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
// 	signedToken, _ := token.SignedString(s.key)
// 	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: signedToken}}
// 	client := s.NewClient(grpc.WithPerRPCCredentials(grpcCreds))
// 	_, err := client.SayHello(context.TODO(), helloReq)
// 	require.NoError(s.T(), err, "no error must occur")
// }
