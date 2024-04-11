// Package authz contains all authorizations related content
package authz

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Authorizations is a collection of multiple client authorizations
type Authorizations struct {
	authorizations map[string]*Authorization
}

// NewAuthorizations instantiates a new Authorizations object
func NewAuthorizations() *Authorizations {
	return &Authorizations{
		authorizations: make(map[string]*Authorization),
	}
}

// Add appends the provided auth configuration to the collection
func (a *Authorizations) Add(auth *Authorization) error {
	if len(auth.ClientID) == 0 {
		return errors.New("cannot add an empty clientID")
	}
	a.authorizations[auth.ClientID] = auth
	return nil
}

// IsAllowed ensures the provided clientID is configured for accessing the provided path with the given method
func (a *Authorizations) IsAllowed(clientID string, path string, method HTTPMethod) (bool, error) {

	if len(a.authorizations) == 0 {
		return true, nil // No configuration found we allow a passthrough
	}

	reason := ""
	allowed := true

	auth, authFound := a.authorizations[clientID]
	if !authFound || !auth.IsAllowed(path, method) {
		allowed = false
		if !authFound {
			reason = fmt.Sprintf("no authz configuration defined for %s", clientID)
		} else {
			reason = fmt.Sprintf("%s is not authorized to access %s %s", clientID, method, path)
		}
	}

	if !allowed {
		return false, errors.New(reason)
	}
	return true, nil
}

// LoadAll loads all the client authorization yaml files from the provided directory
func LoadAll(dir string) (*Authorizations, error) {

	fileInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}

	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("'%s' is not a directory", dir)
	}

	authz := NewAuthorizations()

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
			slog.Info(fmt.Sprintf("%s (aliases: %s) - loaded authorizations from '%s'", conf.ClientID, conf.Aliases, path))
			authz.authorizations[conf.ClientID] = conf
			for _, alias := range conf.Aliases {
				authz.authorizations[alias] = conf
			}
		}

		return nil
	})

	if err != nil {
		slog.Error(fmt.Sprintf("an error occured while load authorization files from '%s' see details for errors", dir), slog.Any("error", err))
	}

	if len(authz.authorizations) == 0 {
		slog.Warn(fmt.Sprintf("no configuration files could be loaded from '%s' jar will accept all requests", dir))
	}

	return authz, nil
}
