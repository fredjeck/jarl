package server

import (
	"context"
	"fmt"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	typev2 "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/fredjeck/jarl/authz"
	"github.com/fredjeck/jarl/logging"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// GRPCAuthzServerV2 implements Envoy custom GRPC V3 authorization filter
type GRPCAuthzServerV2 struct {
	AuthzHeader    string
	Authorizations *authz.Authorizations
}

func (s *GRPCAuthzServerV2) allow(request *authv2.CheckRequest) *authv2.CheckResponse {
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
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *GRPCAuthzServerV2) deny(request *authv2.CheckRequest, reason string) *authv2.CheckResponse {
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
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v2 check request.
func (s *GRPCAuthzServerV2) Check(_ context.Context, request *authv2.CheckRequest) (*authv2.CheckResponse, error) {
	attrs := request.GetAttributes()
	httpAttrs := attrs.GetRequest().GetHttp()
	method := authz.HTTPMethod(attrs.Request.Http.Method)
	// Determine whether to allow or deny the request.
	clientID, headerExists := httpAttrs.GetHeaders()[s.AuthzHeader]

	reason := ""
	allowed := true

	if headerExists {
		al, err := s.Authorizations.IsAllowed(httpAttrs.Host, clientID, attrs.Request.Http.Path, method)
		if err != nil {
			reason = err.Error()
		}
		allowed = al
	} else {
		allowed = false
		deniedCounter.WithLabelValues("missing").Inc()
		reason = fmt.Sprintf("missing authz configuration header %s", s.AuthzHeader)
	}

	ctx := logging.AuthV2LoggingContext(request)
	ctx.ClientID = clientID
	logging.LogRequest(allowed, reason, ctx)
	if allowed {
		allowedCounter.Inc()
		return s.allow(request), nil
	}
	deniedCounter.WithLabelValues(clientID).Inc()
	return s.deny(request, "missing authz header"), nil
}
