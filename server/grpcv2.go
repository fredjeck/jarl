package server

import (
	"context"
	"fmt"
	"log"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	typev2 "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/fredjeck/jarl/config"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// GRPCAuthzServerV2 implements Envoy custom GRPC V3 authorization filter
type GRPCAuthzServerV2 struct {
	AuthzHeader    string
	Authorizations map[string]*config.Authorization
}

func (s *GRPCAuthzServerV2) logRequest(allow string, request *authv2.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv2][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *GRPCAuthzServerV2) allow(request *authv2.CheckRequest) *authv2.CheckResponse {
	s.logRequest("allowed", request)
	return &authv2.CheckResponse{
		HttpResponse: &authv2.CheckResponse_OkResponse{
			OkResponse: &authv2.OkHttpResponse{
				Headers: []*corev2.HeaderValueOption{
					{
						Header: &corev2.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					// {
					// 	Header: &corev2.HeaderValue{
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

func (s *GRPCAuthzServerV2) deny(request *authv2.CheckRequest, reason string) *authv2.CheckResponse {
	s.logRequest("denied", request)
	return &authv2.CheckResponse{
		HttpResponse: &authv2.CheckResponse_DeniedResponse{
			DeniedResponse: &authv2.DeniedHttpResponse{
				Status: &typev2.HttpStatus{Code: typev2.StatusCode_Forbidden},
				Body:   reason,
				Headers: []*corev2.HeaderValueOption{
					{
						Header: &corev2.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev2.HeaderValue{
							Key:   receivedHeader,
							Value: request.GetAttributes().String(),
						},
					},
					// {
					// 	Header: &corev2.HeaderValue{
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

// Check implements gRPC v2 check request.
func (s *GRPCAuthzServerV2) Check(_ context.Context, request *authv2.CheckRequest) (*authv2.CheckResponse, error) {
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
