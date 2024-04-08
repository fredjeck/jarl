// Package logging provides slog wrappers for jarl logging
package logging

import (
	"log/slog"
	"os"
)

const (
	KeyError = "error" // KeyError represents the error attribute in structured logs
)

// Setup configures the logging environment
func Setup() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	var logger *slog.Logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}
