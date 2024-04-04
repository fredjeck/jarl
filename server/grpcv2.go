package server

import (
	"context"
	"log"
	"strings"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	typev2 "github.com/envoyproxy/go-control-plane/envoy/type"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

type JarlAuthzServerV2 struct{}

func (s *JarlAuthzServerV2) logRequest(allow string, request *authv2.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv2][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *JarlAuthzServerV2) allow(request *authv2.CheckRequest) *authv2.CheckResponse {
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
					{
						Header: &corev2.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *JarlAuthzServerV2) deny(request *authv2.CheckRequest) *authv2.CheckResponse {
	s.logRequest("denied", request)
	return &authv2.CheckResponse{
		HttpResponse: &authv2.CheckResponse_DeniedResponse{
			DeniedResponse: &authv2.DeniedHttpResponse{
				Status: &typev2.HttpStatus{Code: typev2.StatusCode_Forbidden},
				Body:   denyBody,
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
					{
						Header: &corev2.HeaderValue{
							Key:   overrideHeader,
							Value: overrideGRPCValue,
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v2 check request.
func (s *JarlAuthzServerV2) Check(_ context.Context, request *authv2.CheckRequest) (*authv2.CheckResponse, error) {
	attrs := request.GetAttributes()

	// Determine whether to allow or deny the request.
	allow := false
	checkHeaderValue, contains := attrs.GetRequest().GetHttp().GetHeaders()[checkHeader]
	if contains {
		allow = checkHeaderValue == allowedValue
	} else {
		allow = attrs.Source != nil && strings.HasSuffix(attrs.Source.Principal, "/sa/"+*serviceAccount)
	}

	if allow {
		return s.allow(request), nil
	}

	return s.deny(request), nil
}
