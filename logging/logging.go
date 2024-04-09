// Package logging provides slog wrappers for jarl logging
package logging

import (
	"fmt"
	"log/slog"
	"os"

	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	KeyError    = "error"             // KeyError represents the error attribute in structured logs
	KeyMethod   = "http.method"       // KeyMethod is the logging key for the http method
	KeyPath     = "http.path"         // KeyPath is the logging key for the inbound request path
	KeyHeaders  = "http.headers"      // KeyHeaders is the logging key for http headers
	KeyHost     = "http.host"         // KeyHost is the logging key for the inbound request host
	KeyContext  = "request.context"   // KeyContext is the request attributes
	KeyAllow    = "request.allow"     // KeyAllow is the logging key for the request outcome
	KeyClientID = "request.client.id" // KeyClientID is the logging key for the header identifier value
	KeyProtocol = "request.protocol"  // KeyProtocol is the logging key for the GRPC protocol version
	KeyReason   = "reason"            // KeyReason is the logging key for the deny reason
)

// Setup configures the logging environment
func Setup() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	var logger *slog.Logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}

// Context holds the request context for unified logging purposes
type Context struct {
	Protocol       string
	Host           string
	Path           string
	Method         string
	ClientID       string
	Headers        map[string]string
	RequestContext interface{}
}

// AuthV3LoggingContext creates a logging context from an AuthV3 CheckRequest
func AuthV3LoggingContext(request *authv3.CheckRequest) *Context {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	return &Context{
		Protocol:       "V3",
		Host:           httpAttrs.Host,
		Path:           httpAttrs.Path,
		Method:         httpAttrs.Method,
		ClientID:       "",
		Headers:        httpAttrs.Headers,
		RequestContext: request.GetAttributes(),
	}
}

// AuthV2LoggingContext creates a logging context from an AuthV2 CheckRequest
func AuthV2LoggingContext(request *authv2.CheckRequest) *Context {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	return &Context{
		Protocol:       "V2",
		Host:           httpAttrs.Host,
		Path:           httpAttrs.Path,
		Method:         httpAttrs.Method,
		ClientID:       "",
		Headers:        httpAttrs.Headers,
		RequestContext: request.GetAttributes(),
	}
}

// LogRequest logs an inbout request details
func LogRequest(allow bool, reason string, context *Context) {
	outcome := "allowed"
	msg := fmt.Sprintf("%s %s %s for '%s'", context.Method, context.Path, outcome, context.ClientID)
	if !allow {
		outcome = "denied"
	}

	slog.Info(msg,
		slog.Bool(KeyAllow, allow),
		slog.String(KeyReason, reason),
		slog.String(KeyHost, context.Host),
		slog.String(KeyPath, context.Path),
		slog.String(KeyMethod, context.Method),
		slog.String(KeyClientID, context.ClientID),
		slog.Any(KeyHeaders, context.Headers),
		slog.String(KeyProtocol, context.Protocol),
		slog.Any(KeyContext, context.RequestContext),
	)
}
