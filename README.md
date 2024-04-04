# Jarl

> *noun* /ja:l/ - a Norse or Danish chief.

Jarl is a custom authorization system for Istio compatible with the [Envoy ext_authz_filer](https://www.envoyproxy.io/docs/envoy/v1.16.0/intro/arch_overview/security/ext_authz_filter) based on the [istio provided example](https://github.com/istio/istio/tree/master/samples/extauthz)

Jarl supports authorization check request using either HTTP (port 8000) or gRPC v2/v3 (port 9000) API 