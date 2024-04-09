package server

import (
	"context"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/fredjeck/jarl/config"
	"github.com/fredjeck/jarl/logging"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// GRPCAuthzServerV3 implements Envoy custom GRPC V3 authorization filter
type GRPCAuthzServerV3 struct {
	AuthzHeader    string
	Authorizations map[string]*config.Authorization
}

// Allows the requests by returning a positive outcoume
func (s *GRPCAuthzServerV3) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: truncate(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

// Denies the inbound request
func (s *GRPCAuthzServerV3) deny(request *authv3.CheckRequest, reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   reason,
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: truncate(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v3 check request.
func (s *GRPCAuthzServerV3) Check(_ context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := request.GetAttributes()
	method := config.HttpMethod(attrs.Request.Http.Method)
	// Determine whether to allow or deny the request.
	clientID, headerExists := attrs.GetRequest().GetHttp().GetHeaders()[s.AuthzHeader]

	reason := ""
	allowed := true

	if headerExists {
		auth, authFound := s.Authorizations[clientID]
		if !authFound || !auth.IsAllowed(attrs.Request.Http.Path, method) {
			allowed = false
			if !authFound {
				reason = fmt.Sprintf("no authz configuration defined for %s", clientID)
			} else {
				reason = fmt.Sprintf("%s is not authorized to access %s %s", clientID, method, attrs.Request.Http.Path)
			}
		}
	} else {
		allowed = false
		reason = fmt.Sprintf("missing authz configuration header %s", s.AuthzHeader)
	}

	logging.LogRequest(allowed, reason, logging.AuthV3LoggingContext(request))
	if allowed {
		return s.allow(request), nil
	}
	return s.deny(request, "missing authz header"), nil
}
