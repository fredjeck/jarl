package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/fredjeck/jarl/config"
	"github.com/fredjeck/jarl/logging"
)

// HTTPAuthzServer implements an Envoy custom HTTP authorization filter
type HTTPAuthzServer struct {
	httpServer    *http.Server
	configuration *config.Configuration
	port          int
	ready         chan bool
	state         ServingStatus
}

// NewHTTPAuthzServer instantiates a new HTTPAuthzServer but does not start it
func NewHTTPAuthzServer(configuration *config.Configuration) *HTTPAuthzServer {
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
	mux.HandleFunc("/", handleCheck(srv.configuration.HTTPAuthZHeader, srv.configuration.Authorizations))

	srv.httpServer = &http.Server{Handler: mux}
	srv.ready <- true // for testing
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

// Handles authorization requests
func handleCheck(authzHeader string, authorization map[string]*config.Authorization) func(w http.ResponseWriter, r *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		// body, err := io.ReadAll(request.Body)
		// if err != nil {
		// 	log.Printf("[HTTP] read body failed: %v", err)
		// }
		// l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, truncate(string(body)))

		auth, ok := authorization[request.Header.Get(authzHeader)]
		if !ok || !auth.IsAllowed(request.URL.String(), config.HttpMethod(request.Method)) {
			deny(response)

		} else {
			allow(response)
		}
	}
}

func allow(response http.ResponseWriter) {
	//log.Printf("[HTTP][allowed]: %s", l)
	response.Header().Set(resultHeader, resultAllowed)
	// response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
	// response.Header().Set(receivedHeader, l)
	response.WriteHeader(http.StatusOK)
}

func deny(response http.ResponseWriter) {
	//log.Printf("[HTTP][allowed]: %s", l)
	response.Header().Set(resultHeader, resultDenied)
	// response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
	// response.Header().Set(receivedHeader, l)
	response.WriteHeader(http.StatusForbidden)
	//_, _ = response.Write([]byte(denyBody))
}
