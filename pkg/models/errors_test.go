package models

import (
	"errors"
	"fmt"
	"testing"
)

func TestValidationError(t *testing.T) {
	msg := "invalid input"
	err := NewValidationError(msg)

	// Check Error() output
	if got := err.Error(); got != msg {
		t.Errorf("Error() = %v, want %v", got, msg)
	}

	// Check errors.As works
	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Error("expected errors.As to succeed for ValidationError")
	}
}

func TestTransformationError(t *testing.T) {
	msg := "transform failed"
	err := NewTransformationError(msg)

	if got := err.Error(); got != msg {
		t.Errorf("Error() = %v, want %v", got, msg)
	}

	var tErr *TransformationError
	if !errors.As(err, &tErr) {
		t.Error("expected errors.As to succeed for TransformationError")
	}
}

func TestDatabaseError(t *testing.T) {
	base := fmt.Errorf("sql: connection refused")
	err := NewDatabaseError(base)

	// Check Error() contains message
	if got := err.Error(); got == "" || got == base.Error() {
		// We expect "database error: <base>"
		if got != "database error: "+base.Error() {
			t.Errorf("Error() = %v, want prefix 'database error:'", got)
		}
	}

	// Check errors.As works
	var dErr *DatabaseError
	if !errors.As(err, &dErr) {
		t.Error("expected errors.As to succeed for DatabaseError")
	}

	// Check errors.Unwrap works
	if !errors.Is(err, base) {
		t.Error("expected errors.Is to match underlying error")
	}
}
