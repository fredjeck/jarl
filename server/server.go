package server

import (
	"flag"
	"fmt"
	"sync"
)

const (
	checkHeader       = "x-ext-authz"
	allowedValue      = "allow"
	resultHeader      = "x-ext-authz-check-result"
	receivedHeader    = "x-ext-authz-check-received"
	overrideHeader    = "x-ext-authz-additional-header-override"
	overrideGRPCValue = "grpc-additional-header-override-value"
	resultAllowed     = "allowed"
	resultDenied      = "denied"
)

// ServingStatus indicates the serving status of the Authz servers
type ServingStatus int

const (
	Serving ServingStatus = iota // Serving fine
	Stopped                      // Stopped for some reasons - check logs for details
)

var (
	serviceAccount = flag.String("allow_service_account", "a",
		"allowed service account, matched against the service account in the source principal from the client certificate")
	denyBody = fmt.Sprintf("denied by ext_authz for not found header `%s: %s` in the request", checkHeader, allowedValue)
)

// ExtAuthzServer implements the ext_authz v2/v3 gRPC and HTTP check request API.
type JarlAuthzServer struct {
	grpcServer *GrpcAuthz
	httpServer *HttpAuthz
}

func returnIfNotTooLong(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<too-long>"
	}
	return body
}

func (s *JarlAuthzServer) Run() {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.httpServer.Start(&wg, s.Healthy)
	go s.grpcServer.Start(&wg)
	wg.Wait()
}

func (s *JarlAuthzServer) Healthy() bool {
	return true
}

func (s *JarlAuthzServer) Stop() {
	s.grpcServer.Stop()
	s.httpServer.Stop()
}

func NewJarlAuthzServer(httpListenAddr string, grpcListenAddr string) *JarlAuthzServer {
	return &JarlAuthzServer{
		grpcServer: NewGrpcAuthz(grpcListenAddr),
		httpServer: NewHttpAuthz(httpListenAddr),
	}
}
