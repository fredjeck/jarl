// Package server - Jarl Authz Server
package server

import (
	"fmt"
	"log/slog"
	"sync"
)

const (
	allowedValue   = "allow"
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"
	// NOT IMPLEMENTED YET overrideHeader    = "x-ext-authz-additional-header-override"
	// NOT IMPLEMENTED YET overrideGRPCValue = "grpc-additional-header-override-value"
	resultAllowed = "allowed"
	resultDenied  = "denied"
)

// ServingStatus indicates the serving status of the Authz servers
type ServingStatus int

const (
	Serving ServingStatus = iota // Serving fine
	Stopped                      // Stopped for some reasons - check logs for details
)

// JarlAuthzServer implements the ext_authz v2/v3 gRPC and HTTP Envoy check request API.
type JarlAuthzServer struct {
	grpcServer *GRPCAuthzServer
	httpServer *HTTPAuthzServer
}

// Start starts listening for inbound Authz connections on both HTTP and GRPC ports
func (s *JarlAuthzServer) Start() {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.httpServer.Start(&wg, s.Healthy)
	go s.grpcServer.Start(&wg)
	wg.Wait()
}

// Healthy returns true if both servers are running
func (s *JarlAuthzServer) Healthy() (bool, string) {
	if s.grpcServer.state == Serving && s.httpServer.state == Serving {
		return true, "healthy"
	}

	return false, fmt.Sprintf("grpc up: %t http up: %t", s.grpcServer.state == Serving, s.httpServer.state == Serving)
}

// Stop stops the underlying HTTP and GRPC servers
func (s *JarlAuthzServer) Stop() {
	s.grpcServer.Stop()
	s.httpServer.Stop()
}

// NewJarlAuthzServer instantiates a new Authz server based on the provided configuration
func NewJarlAuthzServer(conf *Configuration) *JarlAuthzServer {
	slog.Info(fmt.Sprintf("configuring jarl using headers['%s'] as authz content attribute", conf.HTTPAuthZHeader))
	return &JarlAuthzServer{
		grpcServer: NewGRPCAuthzServer(conf),
		httpServer: NewHTTPAuthzServer(conf),
	}
}

func truncate(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<truncated>"
	}
	return body
}
