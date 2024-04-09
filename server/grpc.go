package server

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/fredjeck/jarl/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// GRPCAuthzServer implements an Envoy custom GRPC V2 and V3 authorization filter
type GRPCAuthzServer struct {
	grpcServer    *grpc.Server
	configuration *Configuration
	port          int
	ready         chan bool
	state         ServingStatus
	grpcV2        *GRPCAuthzServerV2
	grpcV3        *GRPCAuthzServerV3
}

// NewGRPCAuthzServer instantiates a new GRPC AuthZ serer but does not start it
func NewGRPCAuthzServer(configuration *Configuration) *GRPCAuthzServer {
	return &GRPCAuthzServer{
		configuration: configuration,
		ready:         make(chan bool),
		state:         Stopped,
	}
}

// Start starts the server starts serving inbound connections
func (srv *GRPCAuthzServer) Start(wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		srv.state = Stopped
		slog.Info("jarl http grpc server stopped")
	}()

	listener, err := net.Listen("tcp", srv.configuration.GRPCListenOn)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to bind jarl GRPC authz server to '%v", srv.configuration.GRPCListenOn), slog.Any(logging.KeyError, err))
		return
	}
	// Store the port for test only.
	srv.port = listener.Addr().(*net.TCPAddr).Port

	srv.grpcServer = grpc.NewServer()
	authv2.RegisterAuthorizationServer(srv.grpcServer, &GRPCAuthzServerV2{AuthzHeader: srv.configuration.HTTPAuthZHeader, Authorizations: srv.configuration.Authorizations})
	authv3.RegisterAuthorizationServer(srv.grpcServer, &GRPCAuthzServerV3{AuthzHeader: srv.configuration.HTTPAuthZHeader, Authorizations: srv.configuration.Authorizations})
	grpc_health_v1.RegisterHealthServer(srv.grpcServer, health.NewServer())
	srv.ready <- true
	srv.state = Serving

	slog.Info(fmt.Sprintf("starting jarl GRPC authz server at '%s", listener.Addr()))
	if err := srv.grpcServer.Serve(listener); err != nil {
		slog.Error(fmt.Sprintf("failed to start jarl grpc authz server at '%s'", listener.Addr()), slog.Any(logging.KeyError, err))
	}
}

// Stop stops listening for GRPC connections
func (srv *GRPCAuthzServer) Stop() {
	slog.Info("stopping jarl grpc authz server")
	srv.grpcServer.Stop()
}
