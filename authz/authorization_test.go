package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendSinglePath(t *testing.T) {
	auth := NewAuthorization()

	auth.ConfigurePath("/Pokemon", "")

	endpoints, ok := auth.Endpoints[HTTPMethodAll]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)
}

func TestAppendMultiplePaths(t *testing.T) {
	auth := NewAuthorization()

	auth.ConfigurePath("/Pokemon", "")
	auth.ConfigurePath("/Pokemon/Ditto", "")
	auth.ConfigurePath("/Pokemon/Pikachu", "")

	endpoints, ok := auth.Endpoints[HTTPMethodAll]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)
}

func TestAppendMultipleMethods(t *testing.T) {
	auth := NewAuthorization()

	auth.ConfigurePath("/Pokemon", "get, post")
	auth.ConfigurePath("/Pokemon/Ditto", "get, post, options")
	auth.ConfigurePath("/Pokemon/Pikachu", "post")

	endpoints, ok := auth.Endpoints[HTTPMethodGet]
	assert.True(t, ok)
	assert.Len(t, endpoints, 2)

	endpoints, ok = auth.Endpoints[HTTPMethodPost]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)

	endpoints, ok = auth.Endpoints[HTTPMethodOptions]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)
}

func TestAppendInvalidMethods(t *testing.T) {
	auth := NewAuthorization()

	auth.ConfigurePath("/Pokemon", "notknown, notvalid")
	auth.ConfigurePath("/Pokemon/Ditto", "woopsie")

	assert.Len(t, auth.Endpoints, 0)
}

func TestAppendInvalidEnpoints(t *testing.T) {
	auth := NewAuthorization()

	auth.ConfigurePath("[\\]", "get")
	auth.ConfigurePath("[ab", "put")

	assert.Len(t, auth.Endpoints, 0)
}

func TestLoadFromValidYaml(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - /pokemon/pikachu
  - path: /pokemon
    methods: GET, POST
  - path: /pokemon/tortank
    methods: POST
  - /pokemon/ditto
  - path: /encounters
    methods: POST		
  - path: /berries
    methods: DELETE
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)

	endpoints, ok := auth.Endpoints[HTTPMethodGet]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)

	endpoints, ok = auth.Endpoints[HTTPMethodPost]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)

	endpoints, ok = auth.Endpoints[HTTPMethodDelete]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)

	endpoints, ok = auth.Endpoints[HTTPMethodAll]
	assert.True(t, ok)
	assert.Len(t, endpoints, 2)

}

func TestLoadMalformedYaml(t *testing.T) {
	yml := `
clientID: client
	mode: allow
paths:
  		- /pokemon/pikachu
`

	_, err := NewAuthorizationFromYaml([]byte(yml))
	assert.Error(t, err)
}

func TestLoadMissingClientIDYaml(t *testing.T) {
	yml := `
mode: allow
paths:
  - /pokemon/pikachu
`

	_, err := NewAuthorizationFromYaml([]byte(yml))
	assert.ErrorIs(t, err, ErrMissingClientID)
}

func TestLoadInvalidModeYaml(t *testing.T) {
	yml := `
clientID: client
mode: depeche
paths:
  - /pokemon/pikachu
`

	_, err := NewAuthorizationFromYaml([]byte(yml))
	assert.ErrorIs(t, err, ErrInvalidMode)
}

func TestMissingModeYaml(t *testing.T) {
	yml := `
clientID: client
paths:
  - /pokemon/pikachu
`

	_, err := NewAuthorizationFromYaml([]byte(yml))
	assert.ErrorIs(t, err, ErrInvalidMode)
}

func TestLoadMissingPathYaml(t *testing.T) {
	yml := `
clientID: client
mode: deny
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 0)
}

func TestLoadInvalidPathConstructYaml(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - 6
  - methods: GET, POST
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 0)
}

func TestLoadUnusualPathConstructYaml(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - path: /pokemon/pikachu
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 1)
}

func TestLoadInvalidPathYaml(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - [\\]
  - )()
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 0)
}

func TestPathIsAllowed(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - path: /api/pokemon/.*?
    methods: get
  - path: /api/encounter
    methods: put
  - path: /api/pokemon/pikachu
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.True(t, auth.IsAllowed("localhost", "/api/pokemon/ditto", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodGet))
	assert.True(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodPut))
	assert.True(t, auth.IsAllowed("localhost", "/api/pokemon/pikachu", HTTPMethodPut))
}

func TestPathIsDisallowed(t *testing.T) {
	yml := `
clientID: client
mode: deny
paths:
  - path: /api/encounter
    methods: put
  - path: /api/pokemon/pikachu
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.True(t, auth.IsAllowed("localhost", "/api/pokemon/ditto", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodPut))
	assert.True(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("localhost", "/api/pokemon/pikachu", HTTPMethodPut))
}

func TestHTTPMethodParsing(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - path: /api/encounter
    methods: GET,HEAD,POST,PUT,DELETE,CONNECT,OPTIONS,TRACE,PATCH,UNKNOWN
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 9)
}

func TestHTTPMethodOptimization(t *testing.T) {
	yml := `
clientID: client
mode: allow
paths:
  - path: /api/encounter
    methods: GET,HEAD,POST,PUT,DELETE,CONNECT,OPTIONS,TRACE,PATCH,UNKNOWN, ALL
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Endpoints, 1)
}

func TestHosts(t *testing.T) {
	yml := `
clientID: client
mode: allow
hosts:
  - localhost
  - 127.0.0.1
paths:
  - /api/encounter
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.Len(t, auth.Hosts, 2)
}

func TestHostisAllwed(t *testing.T) {
	yml := `
clientID: client
mode: allow
hosts:
  - localhost
paths:
  - path: /api/pokemon/.*?
    methods: get
  - path: /api/encounter
    methods: put
  - path: /api/pokemon/pikachu
`

	auth, err := NewAuthorizationFromYaml([]byte(yml))
	assert.NoError(t, err)
	assert.True(t, auth.IsAllowed("localhost", "/api/pokemon/ditto", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("jarl.com", "/api/pokemon/ditto", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodGet))
	assert.False(t, auth.IsAllowed("jarl.com", "/api/pokemon/ditto", HTTPMethodGet))
	assert.True(t, auth.IsAllowed("localhost", "/api/encounter", HTTPMethodPut))
	assert.True(t, auth.IsAllowed("localhost", "/api/pokemon/pikachu", HTTPMethodPut))
	assert.False(t, auth.IsAllowed("jarl.com", "/api/encounter", HTTPMethodPut))
	assert.False(t, auth.IsAllowed("jarl.com", "/api/pokemon/pikachu", HTTPMethodPut))
}
