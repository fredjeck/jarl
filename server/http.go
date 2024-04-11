package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/fredjeck/jarl/logging"
)

// HTTPAuthzServer implements an Envoy custom HTTP authorization filter
// Please note that HTTP authorization server has been disabled - old code can be found in tag 0.0.1-alpha
// HTTP Server is only kept for health check purposes
type HTTPAuthzServer struct {
	httpServer    *http.Server
	configuration *Configuration
	port          int
	ready         chan bool
	state         ServingStatus
}

// NewHTTPAuthzServer instantiates a new HTTPAuthzServer but does not start it
func NewHTTPAuthzServer(configuration *Configuration) *HTTPAuthzServer {
	return &HTTPAuthzServer{
		ready:         make(chan bool),
		state:         Stopped,
		configuration: configuration,
	}
}

// Start starts the HTTPAuthzServer
func (srv *HTTPAuthzServer) Start(wg *sync.WaitGroup, healthFunc func() (bool, string)) {
	defer func() {
		wg.Done()
		srv.state = Stopped
		slog.Info("jarl http Authz server stopped")
	}()

	listener, err := net.Listen("tcp", srv.configuration.HTTPListenOn)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to bind jarl HTTP authz server to '%v", srv.configuration.HTTPListenOn), slog.Any(logging.KeyError, err))
	}

	// Store the port for test only.
	srv.port = listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/healtz", handleHealth(healthFunc))

	srv.httpServer = &http.Server{Handler: mux}
	select {
	case srv.ready <- true:
		slog.Info(fmt.Sprintf("advertised status to test case listeners"))
	default:
		slog.Info(fmt.Sprintf("no HTTP test cases listener found...skipping"))
	}
	srv.state = Serving
	slog.Info(fmt.Sprintf("starting jarl http authz server at '%s", listener.Addr()))

	if err := srv.httpServer.Serve(listener); err != nil {
		slog.Error(fmt.Sprintf("failed to start jarl http authz server at '%v'", srv.configuration.HTTPListenOn), slog.Any(logging.KeyError, err))
	}
}

// Stop stops listening for inbound connections and closes the underlying http server
func (srv *HTTPAuthzServer) Stop() {
	slog.Info("stopping jarl http authz server")
	if err := srv.httpServer.Close(); err != nil {
		slog.Error("failed to stop jarl http authz server", slog.Any(logging.KeyError, err))
	}
}

// Kubernetes Healt probe
func handleHealth(healthFunc func() (bool, string)) func(w http.ResponseWriter, r *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		healthy, desc := healthFunc()
		if healthy {
			response.WriteHeader(http.StatusOK)
		} else {
			response.WriteHeader(http.StatusBadRequest)
		}
		response.Write([]byte(desc))
	}
}
