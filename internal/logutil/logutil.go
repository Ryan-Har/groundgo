package logutil

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

// NewTimingLogger returns a closure that logs a debug message with duration when called.
// Pass in the logger, a start time, a message, and any initial fields.
func NewTimingLogger(logger *slog.Logger, start time.Time, msg string, initialFields ...any) func() {
	return func() {
		elapsed := time.Since(start)
		finalFields := append(initialFields, "duration", elapsed.String())
		logger.Debug(msg, finalFields...)
	}
}

// NewTimingLoggerWithLevel allows you to specify the log level for timing logs
func NewTimingLoggerWithLevel(logger *slog.Logger, level slog.Level, start time.Time, msg string, initialFields ...any) func() {
	return func() {
		elapsed := time.Since(start)
		finalFields := append(initialFields, "duration", elapsed.String())
		logger.Log(context.Background(), level, msg, finalFields...)
	}
}

// LogAndWrapErr logs an error with context fields and wraps it with a message.
// It returns a wrapped error (with %w) so errors.Is / errors.As still work.
func LogAndWrapErr(logger *slog.Logger, msg string, err error, fields ...any) error {
	if err == nil {
		return nil
	}
	// We conventionally put the error field at the end
	allFields := append(fields, "err", err)
	logger.Error(msg, allFields...)
	return fmt.Errorf("%s: %w", msg, err)
}

// DebugAndWrapErr logs an error at debug level with context fields and wraps it with a message.
// It returns a wrapped error (with %w) so errors.Is / errors.As still work.
func DebugAndWrapErr(logger *slog.Logger, msg string, err error, fields ...any) error {
	if err == nil {
		return nil
	}
	// We conventionally put the error field at the end
	allFields := append(fields, "err", err)
	logger.Debug(msg, allFields...)
	return fmt.Errorf("%s: %w", msg, err)
}

// WithFields returns a new logger with the given fields pre-populated
func WithFields(logger *slog.Logger, fields ...any) *slog.Logger {
	return logger.With(fields...)
}

// WithCaller adds caller information (file:line) to the logger
// skip refers to the number of callers up to log
func WithCaller(logger *slog.Logger, skip int) *slog.Logger {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return logger
	}
	return logger.With("caller", fmt.Sprintf("%s:%d", file, line))
}

// LogDuration is a helper that measures and logs the duration of a function call
func LogDuration(logger *slog.Logger, msg string, fn func(), fields ...any) {
	start := time.Now()
	fn()
	elapsed := time.Since(start)
	finalFields := append(fields, "duration", elapsed.String())
	logger.Debug(msg, finalFields...)
}

// LogDurationWithError measures duration and handles potential errors from the function
func LogDurationWithError(logger *slog.Logger, msg string, fn func() error, fields ...any) error {
	start := time.Now()
	err := fn()
	elapsed := time.Since(start)

	finalFields := append(fields, "duration", elapsed.String())

	if err != nil {
		finalFields = append(finalFields, "err", err)
		logger.Error(msg+" failed", finalFields...)
		return err
	}

	logger.Debug(msg+" completed", finalFields...)
	return nil
}

// ConditionalLog only logs if the condition is true
func ConditionalLog(logger *slog.Logger, condition bool, level slog.Level, msg string, fields ...any) {
	if condition {
		logger.Log(context.Background(), level, msg, fields...)
	}
}

// LogSlowOperation logs a warning if an operation takes longer than the threshold
func LogSlowOperation(logger *slog.Logger, threshold time.Duration, msg string, fn func(), fields ...any) {
	start := time.Now()
	fn()
	elapsed := time.Since(start)

	finalFields := append(fields, "duration", elapsed.String(), "threshold", threshold.String())

	if elapsed > threshold {
		logger.Warn(msg+" was slow", finalFields...)
	} else {
		logger.Debug(msg+" completed", finalFields...)
	}
}
