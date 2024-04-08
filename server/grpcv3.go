package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/fredjeck/jarl/config"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// GRPCAuthzServerV3 implements Envoy custom GRPC V3 authorization filter
type GRPCAuthzServerV3 struct {
	AuthzHeader    string
	Authorizations map[string]*config.Authorization
}

// Logs the request
func (s *GRPCAuthzServerV3) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
	slog.Info(fmt.Sprintf("gRPCv3 request %s", allow), slog.String("outcome", allow), slog.Any("attributes", request.GetAttributes()), slog.Any("path", httpAttrs.GetPath()))
}

// Allows the requests by returning a positive outcoume
func (s *GRPCAuthzServerV3) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("allowed", request)
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
					// {
					// 	Header: &corev3.HeaderValue{
					// 		Key:   overrideHeader,
					// 		Value: overrideGRPCValue,
					// 	},
					// },
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

// Denies the inbound request
func (s *GRPCAuthzServerV3) deny(request *authv3.CheckRequest, reason string) *authv3.CheckResponse {
	s.logRequest("denied", request)
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
					// {
					// 	Header: &corev3.HeaderValue{
					// 		Key:   overrideHeader,
					// 		Value: overrideGRPCValue,
					// 	},
					// },
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
	checkHeaderValue, contains := attrs.GetRequest().GetHttp().GetHeaders()[s.AuthzHeader]
	if contains {
		auth, ok := s.Authorizations[checkHeaderValue]
		if !ok || !auth.IsAllowed(attrs.Request.Http.Path, method) {
			return s.deny(request, fmt.Sprintf("%s is not authorized to access %s %s", checkHeaderValue, method, attrs.Request.Http.Path)), nil
		}
		return s.allow(request), nil
	}
	return s.deny(request, "missing authorization header"), nil
}
