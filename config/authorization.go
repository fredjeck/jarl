package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// HTTPMethod is a wrapper aroun http.Method
type HTTPMethod string

var (
	HTTPMethodGet     HTTPMethod = "GET"     // HTTPMethodGet HTTP GET
	HTTPMethodHead    HTTPMethod = "HEAD"    // HTTPMethodHead HTTP HEAD
	HTTPMethodPost    HTTPMethod = "POST"    // HTTPMethodPost HTTP POST
	HTTPMethodPut     HTTPMethod = "PUT"     // HTTPMethodPut HTTP PUT
	HTTPMethodDelete  HTTPMethod = "DELETE"  // HTTPMethodDelete HTTP DELETE
	HTTPMethodConnect HTTPMethod = "CONNECT" // HTTPMethodConnect HTTP CONNECT
	HTTPMethodOptions HTTPMethod = "OPTIONS" // HTTPMethodOptions HTTP OPTIONS
	HTTPMethodTrace   HTTPMethod = "TRACE"   // HTTPMethodTrace HTTP TRACE
	HTTPMethodPatch   HTTPMethod = "PATCH"   // HTTPMethodPatch HTTP PATCH
	HTTPMethodAll     HTTPMethod = "ALL"     // HTTPMethodAll HTTP All
	HTTPMethodUnknown HTTPMethod = "UNKNOWN" // HTTPMethodUnknown when parsing fails
)

// ParseHTTPMethod translates the provided string to an HTTPMethod and makes sure the method is supported
func ParseHTTPMethod(method string) HTTPMethod {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET":
		return HTTPMethodGet
	case "HEAD":
		return HTTPMethodHead
	case "POST":
		return HTTPMethodPost
	case "PUT":
		return HTTPMethodPut
	case "DELETE":
		return HTTPMethodDelete
	case "CONNECT":
		return HTTPMethodConnect
	case "OPTIONS":
		return HTTPMethodOptions
	case "TRACE":
		return HTTPMethodTrace
	case "PATCH":
		return HTTPMethodPatch
	case "ALL":
		return HTTPMethodAll
	case "UNKNOWN":
		return HTTPMethodUnknown
	default:
		return HTTPMethodUnknown
	}
}

const (
	modeAllow = "allow"
	modeDeny  = "deny"
)

// Authorization is the internal representation of a client configuration
type Authorization struct {
	ClientID  string
	Allow     bool
	Endpoints map[HTTPMethod][]*regexp.Regexp
}

// NewAuthorization creates a new authorization
func NewAuthorization() *Authorization {
	return &Authorization{
		Endpoints: make(map[HTTPMethod][]*regexp.Regexp),
	}
}

var (
	// ErrMissingClientID is returned when the ClientID is missing
	ErrMissingClientID = errors.New("clientID cannot be empty")
	// ErrInvalidMode is an unknown mode is specified
	ErrInvalidMode = errors.New("mode is mandatory and should either be 'allow' or 'reject'")
)

// NewAuthorizationFromYaml Geneates a new authorization configration from the provided yaml content
func NewAuthorizationFromYaml(contents []byte) (*Authorization, error) {
	auth := NewAuthorization()

	var yamlMap map[string]interface{}
	err := yaml.Unmarshal([]byte(contents), &yamlMap)
	if err != nil {
		return nil, err
	}

	cid, ok := yamlMap["clientID"]
	if !ok {
		return nil, ErrMissingClientID
	}
	auth.ClientID = cid.(string)

	m, ok := yamlMap["mode"]
	if !ok {
		return nil, ErrInvalidMode
	}

	mode := strings.ToLower(m.(string))
	if len(mode) == 0 || (mode != modeAllow && mode != modeDeny) {
		return nil, ErrInvalidMode
	}
	auth.Allow = mode == modeAllow

	paths, ok := yamlMap["paths"]
	if ok {
		for _, v := range paths.([]interface{}) {
			switch v.(type) {
			case string:
				if err := auth.ConfigurePath(v.(string), ""); err != nil {
					slog.Warn("incompatible path detected", slog.Any("error", err))
					continue
				}
				continue
			case map[string]interface{}:
				construct := v.(map[string]interface{})
				p, ok := construct["path"]
				if !ok {
					continue
				}
				path := p.(string)

				methods := ""
				m, ok := construct["methods"]
				if ok {
					methods = m.(string)
				}

				if err := auth.ConfigurePath(path, methods); err != nil {
					slog.Warn("incompatible path detected", slog.Any("error", err))
					continue
				}
				continue
			default:
				slog.Error(fmt.Sprintf("unsupported path construct detected for clientID '%s': %v", auth.ClientID, v))
				continue
			}
		}
	}

	if len(auth.Endpoints) == 0 {
		outcome := "refused"
		if !auth.Allow {
			outcome = "allowed"
		}
		slog.Warn(fmt.Sprintf("no paths defined for clientID '%s' - authorization will always be %s in mode '%s'", auth.ClientID, outcome, mode))
	}

	return auth, nil
}

// IsAllowed returns true if the provided path access should be granted
func (auth *Authorization) IsAllowed(path string, method HTTPMethod) bool {

	endpoints, ok := auth.Endpoints[method]
	if ok {
		for _, p := range endpoints {
			if p.MatchString(path) {
				return auth.Allow
			}
		}
	}

	endpoints, ok = auth.Endpoints[HTTPMethodAll]
	if !ok {
		return !auth.Allow
	}

	for _, p := range endpoints {
		if p.MatchString(path) {
			return auth.Allow
		}
	}
	return !auth.Allow
}

// ConfigurePath configures the provided path for the given methods
func (auth *Authorization) ConfigurePath(path string, methods string) error {
	supportedMethods := make([]HTTPMethod, 0)
	lowercased := strings.ToLower(methods)

	if len(methods) == 0 || strings.Contains(lowercased, "all") {
		// If the user specifies all, we avoid injecting other method types
		supportedMethods = append(supportedMethods, HTTPMethodAll)
	} else {
		for _, m := range strings.Split(lowercased, ",") {
			method := ParseHTTPMethod(m)
			if method == HTTPMethodUnknown {
				slog.Warn(fmt.Sprintf("http method '%s' is not a supported method and will be ignored for clientID '%s'", method, auth.ClientID))
				continue
			}
			supportedMethods = append(supportedMethods, method)
		}
	}

	rx, err := regexp.Compile(path)
	if err != nil {
		return fmt.Errorf("path '%s' is not a valid regex and will be ignored for clientID '%s' : %w", path, auth.ClientID, err)
	}

	for _, method := range supportedMethods {
		endpoints, ok := auth.Endpoints[method]
		if !ok {
			endpoints = make([]*regexp.Regexp, 0)
		}
		auth.Endpoints[method] = append(endpoints, rx)
	}
	return nil
}

// LoadAllAuthorizations loads all the client authorization yaml files from the provided directory
func LoadAllAuthorizations(dir string) (map[string]*Authorization, error) {

	fileInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}

	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("'%s' is not a directory", dir)
	}

	authz := make(map[string]*Authorization)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if the file is a regular file and has a YAML extension
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yaml") || strings.HasSuffix(info.Name(), ".yml")) {
			content, err := os.ReadFile(path)
			if err != nil {
				fmt.Println("Error:", err)

			}
			conf, err := NewAuthorizationFromYaml(content)
			if err != nil {
				slog.Error(fmt.Sprintf("unable to load '%s' see details for errors", path), slog.Any("error", err))
			}
			authz[conf.ClientID] = conf
		}

		return nil
	})

	if err != nil {
		slog.Error(fmt.Sprintf("an error occured while load authorization files from '%s' see details for errors", dir), slog.Any("error", err))
	}

	return authz, nil
}
