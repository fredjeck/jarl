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

type HttpMethod string

var (
	HttpMethodGet     HttpMethod = "GET"
	HttpMethodHead    HttpMethod = "HEAD"
	HttpMethodPost    HttpMethod = "POST"
	HttpMethodPut     HttpMethod = "PUT"
	HttpMethodDelete  HttpMethod = "DELETE"
	HttpMethodConnect HttpMethod = "CONNECT"
	HttpMethodOptions HttpMethod = "OPTIONS"
	HttpMethodTrace   HttpMethod = "TRACE"
	HttpMethodPatch   HttpMethod = "PATCH"
	HttpMethodAll     HttpMethod = "ALL"
	HttpMethodUnknown HttpMethod = "UNKNOWN"
)

func ParseHttpMethod(method string) HttpMethod {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET":
		return HttpMethodGet
	case "HEAD":
		return HttpMethodHead
	case "POST":
		return HttpMethodPost
	case "PUT":
		return HttpMethodPut
	case "DELETE":
		return HttpMethodDelete
	case "CONNECT":
		return HttpMethodConnect
	case "OPTIONS":
		return HttpMethodOptions
	case "TRACE":
		return HttpMethodTrace
	case "PATCH":
		return HttpMethodPatch
	case "ALL":
		return HttpMethodAll
	case "UNKNOWN":
		return HttpMethodUnknown
	default:
		return HttpMethodUnknown
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
	Endpoints map[HttpMethod][]*regexp.Regexp
}

func NewAuthorization() *Authorization {
	return &Authorization{
		Endpoints: make(map[HttpMethod][]*regexp.Regexp),
	}
}

var (
	// ErrMissingClientID is returned when the ClientID is missing
	ErrMissingClientID = errors.New("clientID cannot be empty")
	// ErrInvalidMode is an unknown mode is specified
	ErrInvalidMode = errors.New("mode is mandatory and should either be 'allow' or 'reject'")
)

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
				if err := auth.AppendPath(v.(string), ""); err != nil {
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

				if err := auth.AppendPath(path, methods); err != nil {
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

// IsPathAuthorized returns true if the provided path access should be granted
func (auth *Authorization) IsAllowed(path string, method HttpMethod) bool {

	endpoints, ok := auth.Endpoints[method]
	if ok {
		for _, p := range endpoints {
			if p.MatchString(path) {
				return auth.Allow
			}
		}
	}

	endpoints, ok = auth.Endpoints[HttpMethodAll]
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

func (auth *Authorization) AppendPath(path string, methods string) error {
	supportedMethods := make([]HttpMethod, 0)
	lowercased := strings.ToLower(methods)

	if len(methods) == 0 || strings.Contains(lowercased, "all") {
		// If the user specifies all, we avoid injecting other method types
		supportedMethods = append(supportedMethods, HttpMethodAll)
	} else {
		for _, m := range strings.Split(lowercased, ",") {
			method := ParseHttpMethod(m)
			if method == HttpMethodUnknown {
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
