package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"testing"
	"time"

	"github.com/ErenDursun/go-grpc-jwt-middleware/jwt"
	extJwt "github.com/golang-jwt/jwt/v5"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type ES256TestSuite struct {
	suite.Suite

	goodAuthToken   string
	badAuthToken    string
	brokenAuthToken string

	healthCheckReq              *grpc_health_v1.HealthCheckRequest
	bufDialer                   func(context.Context, string) (net.Conn, error)
	client                      grpc_health_v1.HealthClient
	clientWithPerRPCCredentials grpc_health_v1.HealthClient
	clientTLSCreds              credentials.TransportCredentials
}

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

	certPEM, keyPEM, err := generateCertAndKey([]string{"localhost"})
	if err != nil {
		log.Fatalf("unable to generate test certificate/key: %v", err.Error())
	}

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(certPEM) {
		suite.FailNow("failed to append certificate")
	}
	suite.clientTLSCreds = credentials.NewTLS(&tls.Config{ServerName: "localhost", RootCAs: cp})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("unable to load test TLS certificate: %v", err)
	}
	serverTLSCreds := credentials.NewServerTLSFromCert(&cert)

	srvOpts := []grpc.ServerOption{
		grpc.StreamInterceptor(auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(auth.UnaryServerInterceptor(authFunc)),
		grpc.Creds(serverTLSCreds),
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

func (suite *ES256TestSuite) SetupTest() {
	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(suite.bufDialer),
		grpc.WithTransportCredentials(suite.clientTLSCreds),
	}
	conn, err := grpc.NewClient("localhost", dialOpts...)
	if err != nil {
		suite.FailNowf("failed to dial localhost", "%w", err)
	}
	// defer conn.Close()
	suite.client = grpc_health_v1.NewHealthClient(conn)

	// client with per RPC credentials
	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: suite.goodAuthToken}}
	dialOpts2 := []grpc.DialOption{
		grpc.WithContextDialer(suite.bufDialer),
		grpc.WithTransportCredentials(suite.clientTLSCreds),
		grpc.WithPerRPCCredentials(grpcCreds),
	}
	conn2, err := grpc.NewClient("localhost", dialOpts2...)
	if err != nil {
		suite.FailNowf("failed to dial localhost:", "%w", err)
	}
	// defer conn2.Close()
	suite.clientWithPerRPCCredentials = grpc_health_v1.NewHealthClient(conn2)
}

func TestES256TestSuite(t *testing.T) {
	suite.Run(t, new(ES256TestSuite))
}

func (suite *ES256TestSuite) TestUnary_NoAuth() {
	// given

	// when
	_, err := suite.client.Check(context.TODO(), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_BrokenAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.brokenAuthToken), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_BadAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.badAuthToken), suite.healthCheckReq)

	// then
	assert.Error(suite.T(), err, "there must be an error")
	assert.Equal(suite.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (suite *ES256TestSuite) TestUnary_GoodAuth() {
	// given

	// when
	_, err := suite.client.Check(ctxWithToken(context.TODO(), "bearer", suite.goodAuthToken), suite.healthCheckReq)

	// then
	require.NoError(suite.T(), err, "no error must occur")
}

func (s *ES256TestSuite) TestUnary_GoodAuthWithPerRpcCredentials() {
	// given

	// when
	_, err := s.clientWithPerRPCCredentials.Check(context.TODO(), s.healthCheckReq)

	// then
	require.NoError(s.T(), err, "no error must occur")
}
