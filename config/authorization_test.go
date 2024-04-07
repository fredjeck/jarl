package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendSinglePath(t *testing.T) {
	auth := NewAuthorization()

	auth.AppendPath("/Pokemon", "")

	endpoints, ok := auth.Endpoints[HttpMethodAll]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)
}

func TestAppendMultiplePaths(t *testing.T) {
	auth := NewAuthorization()

	auth.AppendPath("/Pokemon", "")
	auth.AppendPath("/Pokemon/Ditto", "")
	auth.AppendPath("/Pokemon/Pikachu", "")

	endpoints, ok := auth.Endpoints[HttpMethodAll]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)
}

func TestAppendMultipleMethods(t *testing.T) {
	auth := NewAuthorization()

	auth.AppendPath("/Pokemon", "get, post")
	auth.AppendPath("/Pokemon/Ditto", "get, post, options")
	auth.AppendPath("/Pokemon/Pikachu", "post")

	endpoints, ok := auth.Endpoints[HttpMethodGet]
	assert.True(t, ok)
	assert.Len(t, endpoints, 2)

	endpoints, ok = auth.Endpoints[HttpMethodPost]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)

	endpoints, ok = auth.Endpoints[HttpMethodOptions]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)
}

func TestAppendInvalidMethods(t *testing.T) {
	auth := NewAuthorization()

	auth.AppendPath("/Pokemon", "notknown, notvalid")
	auth.AppendPath("/Pokemon/Ditto", "woopsie")

	assert.Len(t, auth.Endpoints, 0)
}

func TestAppendInvalidEnpoints(t *testing.T) {
	auth := NewAuthorization()

	auth.AppendPath("[\\]", "get")
	auth.AppendPath("[ab", "put")

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

	endpoints, ok := auth.Endpoints[HttpMethodGet]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)

	endpoints, ok = auth.Endpoints[HttpMethodPost]
	assert.True(t, ok)
	assert.Len(t, endpoints, 3)

	endpoints, ok = auth.Endpoints[HttpMethodDelete]
	assert.True(t, ok)
	assert.Len(t, endpoints, 1)

	endpoints, ok = auth.Endpoints[HttpMethodAll]
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
	assert.True(t, auth.IsAllowed("/api/pokemon/ditto", HttpMethodGet))
	assert.False(t, auth.IsAllowed("/api/encounter", HttpMethodGet))
	assert.True(t, auth.IsAllowed("/api/encounter", HttpMethodPut))
	assert.True(t, auth.IsAllowed("/api/pokemon/pikachu", HttpMethodPut))
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
	assert.True(t, auth.IsAllowed("/api/pokemon/ditto", HttpMethodGet))
	assert.False(t, auth.IsAllowed("/api/encounter", HttpMethodPut))
	assert.True(t, auth.IsAllowed("/api/encounter", HttpMethodGet))
	assert.False(t, auth.IsAllowed("/api/pokemon/pikachu", HttpMethodPut))
}

func TestHttpMethodParsing(t *testing.T) {
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

func TestHttpMethodOptimization(t *testing.T) {
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
