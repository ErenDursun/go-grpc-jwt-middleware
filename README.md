# Go gRPC JWT Auth Middleware

![Go workflow](https://github.com/ErenDursun/go-grpc-jwt-middleware/actions/workflows/go.yml/badge.svg)

A simple JWT authentication middleware for gRPC based on [grpc-ecosystem/go-grpc-middleware](https://github.com/grpc-ecosystem/go-grpc-middleware/v2) and [golang-jwt/jwt](https://github.com/golang-jwt/jwt).

## Examples

Full examples can be found in [example_test.go](jwt/example_test.go).

### 'HMAC' Authentication
```go
package main

import (
	"net"

	"github.com/ErenDursun/go-grpc-jwt-middleware/jwt"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	secret := []byte("some_secret")

	authFunc := jwt.NewAuthFunc(secret)

	svr := grpc.NewServer(
		grpc.StreamInterceptor(auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(auth.UnaryServerInterceptor(authFunc)),
	)

	grpc_health_v1.RegisterHealthServer(svr, &grpc_health_v1.UnimplementedHealthServer{})

	lis, _ := net.Listen("tcp", ":8080")

	_ = svr.Serve(lis)
}
```

### 'ES256' Authentication
```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"

	"github.com/ErenDursun/go-grpc-jwt-middleware/jwt"
	extJwt "github.com/golang-jwt/jwt/v5"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	authFunc := jwt.NewAuthFuncWithConfig(
		jwt.Config{
			SigningMethod: extJwt.SigningMethodES256.Name,
			SigningKey:    &key.PublicKey,
		},
	)

	svr := grpc.NewServer(
		grpc.StreamInterceptor(auth.StreamServerInterceptor(authFunc)),
		grpc.UnaryInterceptor(auth.UnaryServerInterceptor(authFunc)),
	)

	grpc_health_v1.RegisterHealthServer(svr, &grpc_health_v1.UnimplementedHealthServer{})

	lis, _ := net.Listen("tcp", ":8080")

	_ = svr.Serve(lis)
}
```
