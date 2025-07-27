package logutil

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Helper function to create a logger that writes to a buffer for testing
func createTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestNewTimingLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	start := time.Now()
	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	timingLogger := NewTimingLogger(logger, start, "test operation", "key", "value")
	timingLogger()

	output := buf.String()
	if !strings.Contains(output, "test operation") {
		t.Errorf("Expected log to contain 'test operation', got: %s", output)
	}
	if !strings.Contains(output, "duration") {
		t.Errorf("Expected log to contain 'duration', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("Expected log to contain 'key=value', got: %s", output)
	}
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("Expected log to be DEBUG level, got: %s", output)
	}
}

func TestNewTimingLoggerWithLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	start := time.Now()
	time.Sleep(10 * time.Millisecond)

	timingLogger := NewTimingLoggerWithLevel(logger, slog.LevelInfo, start, "info operation")
	timingLogger()

	output := buf.String()
	if !strings.Contains(output, "info operation") {
		t.Errorf("Expected log to contain 'info operation', got: %s", output)
	}
	if !strings.Contains(output, "level=INFO") {
		t.Errorf("Expected log to be INFO level, got: %s", output)
	}
}

func TestLogAndWrapErr_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	originalErr := errors.New("original error")
	wrappedErr := LogAndWrapErr(logger, "operation failed", originalErr, "user", "john")

	// Check the error is properly wrapped
	if wrappedErr == nil {
		t.Fatal("Expected wrapped error, got nil")
	}
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("Expected wrapped error to be identifiable with errors.Is")
	}
	if !strings.Contains(wrappedErr.Error(), "operation failed") {
		t.Errorf("Expected wrapped error to contain message, got: %s", wrappedErr.Error())
	}

	// Check logging occurred
	output := buf.String()
	if !strings.Contains(output, "operation failed") {
		t.Errorf("Expected log to contain 'operation failed', got: %s", output)
	}
	if !strings.Contains(output, "user=john") {
		t.Errorf("Expected log to contain 'user=john', got: %s", output)
	}
	if !strings.Contains(output, "err=\"original error\"") {
		t.Errorf("Expected log to contain error, got: %s", output)
	}
	if !strings.Contains(output, "level=ERROR") {
		t.Errorf("Expected log to be ERROR level, got: %s", output)
	}
}

func TestLogAndWrapErr_WithNilError(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	result := LogAndWrapErr(logger, "operation failed", nil, "user", "john")

	if result != nil {
		t.Errorf("Expected nil result for nil error, got: %v", result)
	}

	// Should not log anything
	output := buf.String()
	if output != "" {
		t.Errorf("Expected no log output for nil error, got: %s", output)
	}
}

// TestDebugAndWrapErr_WithError tests the function when a valid error is provided.
// It checks that the error is wrapped correctly and that the correct debug log is produced.
func TestDebugAndWrapErr_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	originalErr := errors.New("original debug error")
	wrappedErr := DebugAndWrapErr(logger, "debug operation failed", originalErr, "request_id", "xyz-123")

	// 1. Check if the error is properly wrapped
	if wrappedErr == nil {
		t.Fatal("Expected wrapped error, got nil")
	}
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("Expected wrapped error to be identifiable with errors.Is")
	}
	if !strings.Contains(wrappedErr.Error(), "debug operation failed") {
		t.Errorf("Expected wrapped error to contain message, got: %s", wrappedErr.Error())
	}

	// 2. Check if the logging occurred correctly
	output := buf.String()
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("Expected log to be DEBUG level, got: %s", output)
	}
	if !strings.Contains(output, "msg=\"debug operation failed\"") {
		t.Errorf("Expected log to contain 'debug operation failed', got: %s", output)
	}
	if !strings.Contains(output, "request_id=xyz-123") {
		t.Errorf("Expected log to contain 'request_id=xyz-123', got: %s", output)
	}
	if !strings.Contains(output, "err=\"original debug error\"") {
		t.Errorf("Expected log to contain the error string, got: %s", output)
	}
}

// TestDebugAndWrapErr_WithNilError tests the function when a nil error is provided.
// It ensures that the function returns nil and does not produce any logs.
func TestDebugAndWrapErr_WithNilError(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	result := DebugAndWrapErr(logger, "this should not be logged", nil, "user", "jane")

	// 1. Check for nil result
	if result != nil {
		t.Errorf("Expected nil result for nil error, got: %v", result)
	}

	// 2. Check that nothing was logged
	output := buf.String()
	if output != "" {
		t.Errorf("Expected no log output for nil error, got: %s", output)
	}
}

func TestWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	enrichedLogger := WithFields(logger, "service", "api", "version", "1.0")
	enrichedLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "service=api") {
		t.Errorf("Expected log to contain 'service=api', got: %s", output)
	}
	if !strings.Contains(output, "version=1.0") {
		t.Errorf("Expected log to contain 'version=1.0', got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected log to contain 'test message', got: %s", output)
	}
}

func TestWithCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	// Test skip=0 (should report this line)
	callerLogger := WithCaller(logger, 0)
	callerLogger.Info("test with caller")

	output := buf.String()
	if !strings.Contains(output, "caller=") {
		t.Errorf("Expected log to contain 'caller=', got: %s", output)
	}
	if !strings.Contains(output, "logutil_test.go:") {
		t.Errorf("Expected log to contain filename, got: %s", output)
	}
}

func TestLogDuration(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	executed := false
	fn := func() {
		time.Sleep(10 * time.Millisecond)
		executed = true
	}

	LogDuration(logger, "test function", fn, "param", "value")

	if !executed {
		t.Error("Expected function to be executed")
	}

	output := buf.String()
	if !strings.Contains(output, "test function") {
		t.Errorf("Expected log to contain 'test function', got: %s", output)
	}
	if !strings.Contains(output, "duration") {
		t.Errorf("Expected log to contain 'duration', got: %s", output)
	}
	if !strings.Contains(output, "param=value") {
		t.Errorf("Expected log to contain 'param=value', got: %s", output)
	}
}

func TestLogDurationWithError_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	executed := false
	fn := func() error {
		time.Sleep(10 * time.Millisecond)
		executed = true
		return nil
	}

	err := LogDurationWithError(logger, "test operation", fn, "param", "value")

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if !executed {
		t.Error("Expected function to be executed")
	}

	output := buf.String()
	if !strings.Contains(output, "test operation completed") {
		t.Errorf("Expected log to contain 'test operation completed', got: %s", output)
	}
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("Expected log to be DEBUG level, got: %s", output)
	}
}

func TestLogDurationWithError_Failure(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	expectedErr := errors.New("test error")
	fn := func() error {
		time.Sleep(10 * time.Millisecond)
		return expectedErr
	}

	err := LogDurationWithError(logger, "test operation", fn)

	if err != expectedErr {
		t.Errorf("Expected original error to be returned, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test operation failed") {
		t.Errorf("Expected log to contain 'test operation failed', got: %s", output)
	}
	if !strings.Contains(output, "level=ERROR") {
		t.Errorf("Expected log to be ERROR level, got: %s", output)
	}
	if !strings.Contains(output, "err=\"test error\"") {
		t.Errorf("Expected log to contain error, got: %s", output)
	}
}

func TestConditionalLog_True(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	ConditionalLog(logger, true, slog.LevelInfo, "conditional message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "conditional message") {
		t.Errorf("Expected log to contain 'conditional message', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("Expected log to contain 'key=value', got: %s", output)
	}
}

func TestConditionalLog_False(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	ConditionalLog(logger, false, slog.LevelInfo, "conditional message", "key", "value")

	output := buf.String()
	if output != "" {
		t.Errorf("Expected no log output when condition is false, got: %s", output)
	}
}

func TestLogSlowOperation_Fast(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	threshold := 100 * time.Millisecond
	fn := func() {
		time.Sleep(10 * time.Millisecond) // Fast operation
	}

	LogSlowOperation(logger, threshold, "test operation", fn, "param", "value")

	output := buf.String()
	if !strings.Contains(output, "test operation completed") {
		t.Errorf("Expected log to contain 'test operation completed', got: %s", output)
	}
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("Expected log to be DEBUG level for fast operation, got: %s", output)
	}
	if !strings.Contains(output, "threshold=100ms") {
		t.Errorf("Expected log to contain threshold, got: %s", output)
	}
}

func TestLogSlowOperation_Slow(t *testing.T) {
	var buf bytes.Buffer
	logger := createTestLogger(&buf)

	threshold := 10 * time.Millisecond
	fn := func() {
		time.Sleep(50 * time.Millisecond) // Slow operation
	}

	LogSlowOperation(logger, threshold, "test operation", fn, "param", "value")

	output := buf.String()
	if !strings.Contains(output, "test operation was slow") {
		t.Errorf("Expected log to contain 'test operation was slow', got: %s", output)
	}
	if !strings.Contains(output, "level=WARN") {
		t.Errorf("Expected log to be WARN level for slow operation, got: %s", output)
	}
	if !strings.Contains(output, "param=value") {
		t.Errorf("Expected log to contain 'param=value', got: %s", output)
	}
}
