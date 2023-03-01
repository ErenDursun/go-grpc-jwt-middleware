package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/ErenDursun/go-grpc-jwt-middleware/jwt"
	extJwt "github.com/golang-jwt/jwt/v4"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func ExampleNewAuthFunc() {
	// secret
	secret := []byte("some_secret")

	// server
	authFunc := jwt.NewAuthFunc(secret)
	svr := grpc.NewServer(
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authFunc)),
	)
	defer svr.Stop()

	grpc_health_v1.RegisterHealthServer(svr, &grpc_health_v1.UnimplementedHealthServer{})

	lis, _ := net.Listen("tcp", ":8080")

	go func() {
		_ = svr.Serve(lis)
	}()

	time.Sleep(3 * time.Second)

	// client
	claims := extJwt.MapClaims{
		"foo": "bar",
		"nbf": float64(time.Date(2023, 01, 01, 12, 0, 0, 0, time.UTC).Unix()),
	}

	token := extJwt.NewWithClaims(extJwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString(secret)

	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v", "Bearer", signedToken))
	ctxWithToken := metautils.NiceMD(md).ToOutgoing(context.TODO())

	conn, _ := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := grpc_health_v1.NewHealthClient(conn)

	response, err := client.Check(ctxWithToken, &grpc_health_v1.HealthCheckRequest{})
	fmt.Printf("r: %v, e: %v\n", response, err)
	// Output: r: <nil>, e: rpc error: code = Unimplemented desc = method Check not implemented
}

func ExampleNewAuthFuncWithConfig() {
	// secret
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// server
	authFunc := jwt.NewAuthFuncWithConfig(
		jwt.Config{
			SigningMethod: extJwt.SigningMethodES256.Name,
			SigningKey:    &key.PublicKey,
		},
	)
	svr := grpc.NewServer(
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(authFunc)),
	)
	defer svr.Stop()

	grpc_health_v1.RegisterHealthServer(svr, &grpc_health_v1.UnimplementedHealthServer{})

	lis, _ := net.Listen("tcp", ":8080")

	go func() {
		_ = svr.Serve(lis)
	}()

	time.Sleep(3 * time.Second)

	// client
	claims := extJwt.MapClaims{
		"foo": "bar",
		"nbf": float64(time.Date(2023, 01, 01, 12, 0, 0, 0, time.UTC).Unix()),
	}

	token := extJwt.NewWithClaims(extJwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v", "Bearer", signedToken))
	ctxWithToken := metautils.NiceMD(md).ToOutgoing(context.TODO())

	conn, _ := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := grpc_health_v1.NewHealthClient(conn)

	response, err := client.Check(ctxWithToken, &grpc_health_v1.HealthCheckRequest{})
	fmt.Printf("r: %v, e: %v\n", response, err)
	// Output: r: <nil>, e: rpc error: code = Unimplemented desc = method Check not implemented
}
