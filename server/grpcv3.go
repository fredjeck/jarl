package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

type JarlAuthzServerV3 struct {
}

func (s *JarlAuthzServerV3) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
	slog.Info(fmt.Sprintf("gRPCv3 request %s", allow), slog.String("outcome", allow), slog.Any("attributes", request.GetAttributes()), slog.Any("path", httpAttrs.GetPath()))
}

func (s *JarlAuthzServerV3) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
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
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
					{
						Header: &corev3.HeaderValue{
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

func (s *JarlAuthzServerV3) deny(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("denied", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   denyBody,
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
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
					{
						Header: &corev3.HeaderValue{
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

// Check implements gRPC v3 check request.
func (s *JarlAuthzServerV3) Check(_ context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
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
