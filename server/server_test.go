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
	"log"
	"net/http"
	"testing"
	"time"

	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/fredjeck/jarl/authz"
	"github.com/fredjeck/jarl/logging"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

const checkHeader = "x-forwarded-sub"

const clientA = `
clientID: clientA
mode: allow
hosts:
  - localhost
paths:
  - path: /pokemon/.*?
    methods: GET, PUT
`

const clientB = `
clientID: clientB
mode: deny
paths:
  - path: /pokemon/.*?
`

type testCase struct {
	name     string
	host     string
	url      string
	method   string
	clientID string
	want     int
}

var testCases = []testCase{
	{
		name:     "Allow GET",
		host:     "localhost",
		url:      "/pokemon/pikachu",
		clientID: "clientA",
		method:   http.MethodGet,
		want:     int(codes.OK),
	},
	{
		name:     "Allow PUT",
		host:     "localhost",
		url:      "/pokemon/tortank",
		clientID: "clientA",
		method:   http.MethodPut,
		want:     int(codes.OK),
	},
	{
		name:     "Deny DELETE",
		host:     "localhost",
		url:      "/pokemon/ditto",
		clientID: "clientA",
		method:   http.MethodDelete,
		want:     int(codes.PermissionDenied),
	},
	{
		name:     "Deny URL",
		host:     "localhost",
		url:      "/berries",
		clientID: "clientA",
		method:   http.MethodDelete,
		want:     int(codes.PermissionDenied),
	},
	{
		name:     "Deny URL",
		host:     "localhost",
		url:      "/pokemon/pikachu",
		clientID: "clientB",
		method:   http.MethodGet,
		want:     int(codes.PermissionDenied),
	},
	{
		name:     "Allow URL",
		host:     "localhost",
		url:      "/encounters",
		clientID: "clientB",
		method:   http.MethodGet,
		want:     int(codes.OK),
	},
	{
		name:     "Deny Client",
		host:     "localhost",
		url:      "/gyms",
		clientID: "clientC",
		method:   http.MethodGet,
		want:     int(codes.PermissionDenied),
	},
}

func TestHealth(t *testing.T) {
	logging.Setup()

	server := NewJarlAuthzServer(&Configuration{
		HTTPListenOn:    "localhost:0",
		GRPCListenOn:    "localhost:0",
		HTTPAuthZHeader: checkHeader,
		Authorizations:  authz.NewAuthorizations(),
	})

	// Start the test server on random port.
	go server.Start()

	waitForServer(server)

	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/healthz", server.httpServer.port), nil)
	if err != nil {
		t.Fatalf(err.Error())
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, 200, resp.StatusCode)
}

func TestExtAuthz(t *testing.T) {

	logging.Setup()

	a := authz.NewAuthorizations()
	client, err := authz.NewAuthorizationFromYaml([]byte(clientA))
	a.Add(client)
	client, err = authz.NewAuthorizationFromYaml([]byte(clientB))
	a.Add(client)

	server := NewJarlAuthzServer(&Configuration{
		HTTPListenOn:    "localhost:0",
		GRPCListenOn:    "localhost:0",
		HTTPAuthZHeader: checkHeader,
		Authorizations:  a,
	})
	// Start the test server on random port.
	go server.Start()

	waitForServer(server)

	conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", server.grpcServer.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer func() { _ = conn.Close() }()
	grpcV3Client := authv3.NewAuthorizationClient(conn)
	grpcV2Client := authv2.NewAuthorizationClient(conn)

	runTestCases(t, grpcV2Client, grpcV3Client)
}

func runTestCases(t *testing.T, grpcV2Client authv2.AuthorizationClient, grpcV3Client authv3.AuthorizationClient) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runGrpcV2Request(t, tc, grpcV2Client)
			runGrpcV3Request(t, tc, grpcV3Client)
		})
	}
}

func runGrpcV3Request(t *testing.T, tc testCase, grpcV3Client authv3.AuthorizationClient) {
	resp, err := grpcV3Client.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:    tc.host,
					Path:    tc.url,
					Method:  tc.method,
					Headers: map[string]string{checkHeader: tc.clientID},
				},
			},
		},
	})

	if err != nil {
		t.Errorf(err.Error())
	}

	if int(resp.Status.Code) != tc.want {
		t.Errorf("'%s' want %d but got %d", tc.name, tc.want, int(resp.Status.Code))
	}
	return
}

func runGrpcV2Request(t *testing.T, tc testCase, grpcV2Client authv2.AuthorizationClient) {
	resp, err := grpcV2Client.Check(context.Background(), &authv2.CheckRequest{
		Attributes: &authv2.AttributeContext{
			Request: &authv2.AttributeContext_Request{
				Http: &authv2.AttributeContext_HttpRequest{
					Host:    "localhost",
					Path:    tc.url,
					Method:  tc.method,
					Headers: map[string]string{checkHeader: tc.clientID},
				},
			},
		},
	})

	if err != nil {
		t.Errorf(err.Error())
	}

	if int(resp.Status.Code) != tc.want {
		t.Errorf("'%s' want %d but got %d", tc.name, tc.want, int(resp.Status.Code))
	}
	return
}

// waitForServer waits until the server is healty and serving requests
func waitForServer(server *JarlAuthzServer) {
	backoff := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		healthy, _ := server.Healthy()
		if !healthy {
			time.Sleep(backoff)
			continue
		}
		return
	}
	log.Fatalf("Server not started after 10 attempts")
}
