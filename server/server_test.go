// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/fredjeck/jarl/config"
	"github.com/fredjeck/jarl/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

const checkHeader = "x-ext-authz"

const clientA = `
clientID: clientA
mode: allow
paths:
  - path: /pokemon/.*?
    methods: GET, PUT
`

var testCases = []struct {
	name     string
	url      string
	method   string
	clientID string
	want     int
}{
	{
		name:     "Allow GET",
		url:      "/pokemon/pikachu",
		clientID: "clientA",
		method:   http.MethodGet,
		want:     int(codes.OK),
	},
	{
		name:     "Deny DELETE",
		url:      "/pokemon/pikachu",
		clientID: "clientA",
		method:   http.MethodDelete,
		want:     int(codes.PermissionDenied),
	},
	{
		name:     "Deny client",
		url:      "/pokemon/pikachu",
		clientID: "clientB",
		method:   http.MethodGet,
		want:     int(codes.PermissionDenied),
	},
}

var cases = []struct {
	name     string
	isGRPCV3 bool
	isGRPCV2 bool
	header   string
	want     int
}{
	{
		name:   "HTTP-allow",
		header: "allow",
		want:   http.StatusOK,
	},
	{
		name:   "HTTP-deny",
		header: "deny",
		want:   http.StatusForbidden,
	},
	{
		name:     "GRPCv3-allow",
		isGRPCV3: true,
		header:   "allow",
		want:     int(codes.OK),
	},
	{
		name:     "GRPCv3-deny",
		isGRPCV3: true,
		header:   "deny",
		want:     int(codes.PermissionDenied),
	},
	{
		name:     "GRPCv2-allow",
		isGRPCV2: true,
		header:   "allow",
		want:     int(codes.OK),
	},
	{
		name:     "GRPCv2-deny",
		isGRPCV2: true,
		header:   "deny",
		want:     int(codes.PermissionDenied),
	},
}

func grpcV3Request(grpcV3Client authv3.AuthorizationClient, header string) (*authv3.CheckResponse, error) {
	return grpcV3Client.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:    "localhost",
					Path:    "/check",
					Headers: map[string]string{checkHeader: header},
				},
			},
		},
	})
}

func grpcV3PathRequest(grpcV3Client authv3.AuthorizationClient, clientID string, path string, method string) (*authv3.CheckResponse, error) {
	return grpcV3Client.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:    "localhost",
					Path:    path,
					Method:  method,
					Headers: map[string]string{checkHeader: clientID},
				},
			},
		},
	})
}

func grpcV2PathRequest(grpcV2Client authv2.AuthorizationClient, clientID string, path string, method string) (*authv2.CheckResponse, error) {
	return grpcV2Client.Check(context.Background(), &authv2.CheckRequest{
		Attributes: &authv2.AttributeContext{
			Request: &authv2.AttributeContext_Request{
				Http: &authv2.AttributeContext_HttpRequest{
					Host:    "localhost",
					Path:    path,
					Method:  method,
					Headers: map[string]string{checkHeader: clientID},
				},
			},
		},
	})
}

func grpcV2Request(grpcV2Client authv2.AuthorizationClient, header string) (*authv2.CheckResponse, error) {
	return grpcV2Client.Check(context.Background(), &authv2.CheckRequest{
		Attributes: &authv2.AttributeContext{
			Request: &authv2.AttributeContext_Request{
				Http: &authv2.AttributeContext_HttpRequest{
					Host:    "localhost",
					Path:    "/check",
					Headers: map[string]string{checkHeader: header},
				},
			},
		},
	})
}

func TestExtAuthz(t *testing.T) {

	logging.Setup()

	authz := make(map[string]*config.Authorization)
	ca, err := config.NewAuthorizationFromYaml([]byte(clientA))
	authz["clientA"] = ca

	server := NewJarlAuthzServer(&config.Configuration{
		HTTPListenOn:    "localhost:0",
		GRPCListenOn:    "localhost:0",
		HTTPAuthZHeader: checkHeader,
		Authorizations:  authz,
	})
	// Start the test server on random port.
	go server.Start()

	// Prepare the HTTP request.
	_ = <-server.httpServer.ready
	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/check", server.httpServer.port), nil)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Prepare the gRPC request.
	_ = <-server.grpcServer.ready
	conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", server.grpcServer.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = conn.Close() }()
	grpcV3Client := authv3.NewAuthorizationClient(conn)
	grpcV2Client := authv2.NewAuthorizationClient(conn)

	runExtendedTestCases(t, grpcV2Client, grpcV3Client, httpReq)
}

func runExtendedTestCases(t *testing.T, grpcV2Client authv2.AuthorizationClient, grpcV3Client authv3.AuthorizationClient, httpReq *http.Request) {
	var got int
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := grpcV3PathRequest(grpcV3Client, tc.clientID, tc.url, tc.method)
			if err != nil {
				t.Errorf(err.Error())
			} else {
				got = int(resp.Status.Code)
			}
			if got != tc.want {
				t.Errorf("'%s' want %d but got %d", tc.name, tc.want, got)
			}

			respv2, err := grpcV2PathRequest(grpcV2Client, tc.clientID, tc.url, tc.method)
			if err != nil {
				t.Errorf(err.Error())
			} else {
				got = int(respv2.Status.Code)
			}
			if got != tc.want {
				t.Errorf("'%s' want %d but got %d", tc.name, tc.want, got)
			}
		})
	}
}

func runTestCases(t *testing.T, grpcV2Client authv2.AuthorizationClient, grpcV3Client authv3.AuthorizationClient, httpReq *http.Request) {
	httpClient := &http.Client{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			if tc.isGRPCV3 {
				resp, err := grpcV3Request(grpcV3Client, tc.header)
				if err != nil {
					t.Errorf(err.Error())
				} else {
					got = int(resp.Status.Code)
				}
			} else if tc.isGRPCV2 {
				resp, err := grpcV2Request(grpcV2Client, tc.header)
				if err != nil {
					t.Errorf(err.Error())
				} else {
					got = int(resp.Status.Code)
				}
			} else {
				httpReq.Header.Set(checkHeader, tc.header)
				resp, err := httpClient.Do(httpReq)
				if err != nil {
					t.Errorf(err.Error())
				} else {
					got = resp.StatusCode
					resp.Body.Close()
				}
			}
			if got != tc.want {
				t.Errorf("want %d but got %d", tc.want, got)
			}
		})
	}
}
