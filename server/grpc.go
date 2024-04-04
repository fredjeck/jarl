package server

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"

	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type GrpcAuthz struct {
	grpcServer *grpc.Server
	port       int
	listenOn   string
	ready      chan bool
	state      ServingStatus
	grpcV2     *JarlAuthzServerV2
	grpcV3     *JarlAuthzServerV3
}

func NewGrpcAuthz(listenOn string) *GrpcAuthz {
	return &GrpcAuthz{
		listenOn: listenOn,
		ready:    make(chan bool),
		state:    Stopped,
	}
}

func (srv *GrpcAuthz) Start(wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		srv.state = Stopped
		slog.Info("jarl http grpc server stopped")
	}()

	listener, err := net.Listen("tcp", srv.listenOn)
	if err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
		return
	}
	// Store the port for test only.
	srv.port = listener.Addr().(*net.TCPAddr).Port

	srv.grpcServer = grpc.NewServer()
	authv2.RegisterAuthorizationServer(srv.grpcServer, &JarlAuthzServerV2{})
	authv3.RegisterAuthorizationServer(srv.grpcServer, &JarlAuthzServerV3{})
	grpc_health_v1.RegisterHealthServer(srv.grpcServer, health.NewServer())
	srv.ready <- true
	srv.state = Serving

	slog.Info(fmt.Sprintf("starting jarl grpc authz server at '%s", listener.Addr()))
	if err := srv.grpcServer.Serve(listener); err != nil {
		slog.Error(fmt.Sprintf("failed to start jarl grpc authz server at '%s'", listener.Addr()), slog.Any("error", err))
	}
}

func (srv *GrpcAuthz) Stop() {
	slog.Info("stopping jarl grpc authz server")
	srv.grpcServer.Stop()
}
