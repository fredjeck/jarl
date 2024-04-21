# Jarl

> *noun* /ja:l/ - a Norse or Danish chief.

Jarl is a custom authorization system for Istio compatible with the [Envoy ext_authz_filer](https://www.envoyproxy.io/docs/envoy/v1.16.0/intro/arch_overview/security/ext_authz_filter) based on the [istio provided example](https://github.com/istio/istio/tree/master/samples/extauthz)

Jarl supports authorization check request using the gRPC v2/v3 (port 9000) API 

# Docker image

Official docker image can be found on dockehub : [fredjeck/jarl](https://hub.docker.com/repository/docker/fredjeck/jarl/general)

# Configuration

At startup Jarl will load all the provided client authorizationf files located at **/var/run/jarl/configuation** which shall be provided as a mount point.

Client configurations are simple yaml files defining the paths the client is allowed or denied to access

```yaml
clientID: client # identifier found in the specified header field which will be used by Jarl to map the configuration
hosts: # list of allowed inbound hosts
  - localhost
  - my.gateway.com
mode: allow # allow / deny - if allow is set then only the listed paths are allowed, if deny is selected Jarl will allow all the paths except the ones listed below
paths: # list of paths for this client
  - /pokemon/pikachu # Shorthand notation no http method is checkd
  - path: /pokemon
    methods: GET, POST # List of HTTP methods allowed for the path
  - path: /pokemon/tortank
    methods: POST
  - /pokemon/ditto
  - path: /encounters
    methods: POST		
  - path: /berries
    methods: DELETE
```

## Command line arguments

- _-h_ : http server port, default 8000
- _-g_ : grpc server port, default 9000
- _-a_ : http header field name which should contain the client authentication
- _-c_ : path to the folder where client configuration can be found

## Supported docker environment variables

```docker
ENV PORT_GRPC=9000 # GRPC port
ENV PORT_HTTP=8000 # HTTP port
ENV AUTHZ_HEADER=x-forwarded-sub # Header element containing authorization element
```

## Modes

For a given client ID Jarl can either work in *deny* or *allow* mode :
- *deny* : will accept all the incoming connections for the specified client except the specified paths and HTTP methods
- *allow* : will deny all the incoming connections excepts for the endpoints specified in the configuration file

## Health check

Jarl support both standard GRPC health check and HTTP health check at the **/healthz** url

## Metrics

Jarl implements prometheus support for metrics via the **"/metrics"**