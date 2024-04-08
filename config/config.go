// Package config provides configuration support for the Jarl server
package config

// Configuration stores the configuration options for the Jarl server
type Configuration struct {
	HTTPListenOn             string                    // HTTPListenOn stores the InetAddr on which the HTTP Server is listening for inbound connections
	GRPCListenOn             string                    // GRPCListenOn stores the InetAddr on which the HTTP Server is listening for inbound connections
	ClientsConfigurationPath string                    // ClientsConfigurationPath stores the path where the client configurations are stored
	HTTPAuthZHeader          string                    // HTTPAuthZHeader contains the name of the http header element which will be matchted for clientID
	Authorizations           map[string]*Authorization // Authorizations stores the configured authorizations
}
