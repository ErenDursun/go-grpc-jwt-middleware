package jwt_test

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type assertingServer struct {
	grpc_health_v1.UnimplementedHealthServer

	assertFunc func(ctx context.Context)
}

func (s *assertingServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	s.assertFunc(ctx)
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (s *assertingServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	s.assertFunc(stream.Context())
	_ = stream.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
	return nil
}

func newSignedToken(method jwt.SigningMethod, claims jwt.Claims, secret any) string {
	token := jwt.NewWithClaims(method, claims)
	signedToken, _ := token.SignedString(secret)
	return signedToken
}

func ctxWithToken(ctx context.Context, scheme string, token string) context.Context {
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v", scheme, token))
	nCtx := metautils.NiceMD(md).ToOutgoing(ctx)
	return nCtx
}

// fakeOAuth2TokenSource implements a fake oauth2.TokenSource for the purpose of credentials test.
type fakeOAuth2TokenSource struct {
	accessToken string
}

func (ts *fakeOAuth2TokenSource) Token() (*oauth2.Token, error) {
	t := &oauth2.Token{
		AccessToken: ts.accessToken,
		Expiry:      time.Now().Add(1 * time.Minute),
		TokenType:   "bearer",
	}
	return t, nil
}
