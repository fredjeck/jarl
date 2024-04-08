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

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fredjeck/jarl/config"
	"github.com/fredjeck/jarl/logging"
	"github.com/fredjeck/jarl/server"
)

var (
	httpPort      = flag.String("http", "8000", "HTTP server port")
	grpcPort      = flag.String("grpc", "9000", "gRPC server port")
	header        = flag.String("header", "x-forwarded-sub", "HTTP Header key identifying the connected client")
	configuration = flag.String("clients", "/var/run/jarl/clients", "Folder containing the clients configurations")
)

func main() {

	logging.Setup()

	flag.Parse()

	conf := &config.Configuration{
		HTTPListenOn:             fmt.Sprintf(":%s", *httpPort),
		GRPCListenOn:             fmt.Sprintf(":%s", *grpcPort),
		HTTPAuthZHeader:          *header,
		ClientsConfigurationPath: *configuration,
	}

	auths, err := config.LoadAllAuthorizations(*configuration)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to load client configurations from '%s'", *configuration), slog.Any("error", logging.KeyError))
		os.Exit(1)
	}
	conf.Authorizations = auths

	s := server.NewJarlAuthzServer(conf)
	go s.Start()
	defer s.Stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
