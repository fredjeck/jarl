package server

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"
)

func handleHealth(healthFunc func() bool) func(w http.ResponseWriter, r *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		if healthFunc() {
			response.WriteHeader(http.StatusOK)
		} else {
			response.WriteHeader(http.StatusBadRequest)
		}
	}
}

// Handles the clients file tokenization requests
func handleCheck() func(w http.ResponseWriter, r *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			log.Printf("[HTTP] read body failed: %v", err)
		}
		l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))
		if allowedValue == request.Header.Get(checkHeader) {
			log.Printf("[HTTP][allowed]: %s", l)
			response.Header().Set(resultHeader, resultAllowed)
			response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
			response.Header().Set(receivedHeader, l)
			response.WriteHeader(http.StatusOK)
		} else {
			log.Printf("[HTTP][denied]: %s", l)
			response.Header().Set(resultHeader, resultDenied)
			response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
			response.Header().Set(receivedHeader, l)
			response.WriteHeader(http.StatusForbidden)
			_, _ = response.Write([]byte(denyBody))
		}
	}
}

type HttpAuthz struct {
	httpServer *http.Server
	port       int
	listenOn   string
	ready      chan bool
	state      ServingStatus
}

func NewHttpAuthz(listenOn string) *HttpAuthz {
	return &HttpAuthz{
		listenOn: listenOn,
		ready:    make(chan bool),
		state:    Stopped,
	}
}

func (srv *HttpAuthz) Start(wg *sync.WaitGroup, healthFunc func() bool) {
	defer func() {
		wg.Done()
		srv.state = Stopped
		slog.Info("jarl http Authz server stopped")
	}()

	listener, err := net.Listen("tcp", srv.listenOn)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to bind jarl http authz server to '%v", srv.listenOn), slog.Any("error", err))
	}
	// Store the port for test only.
	srv.port = listener.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/healtz", handleHealth(healthFunc))
	mux.HandleFunc("/", handleCheck())
	srv.httpServer = &http.Server{Handler: mux}
	srv.ready <- true
	srv.state = Serving
	slog.Info(fmt.Sprintf("starting jarl http authz server at '%s", listener.Addr()))
	if err := srv.httpServer.Serve(listener); err != nil {
		slog.Error(fmt.Sprintf("failed to start jarl http authz server at '%v'", srv.listenOn), slog.Any("error", err))
	}
}

func (srv *HttpAuthz) Stop() {
	slog.Info("stopping jarl http authz server")
	if err := srv.httpServer.Close(); err != nil {
		slog.Error("failed to stop jarl http authz server", slog.Any("error", err))
	}
}
