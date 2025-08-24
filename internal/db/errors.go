package db

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/mattn/go-sqlite3"
)

// DuplicateKeyError represents a database constraint violation error
type DuplicateKeyError struct {
	Field string // The field that caused the constraint violation
	Value string // The value that was duplicated (optional, might be sensitive)
	err   error  // The underlying database error
}

func (e *DuplicateKeyError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("duplicate key violation: %s already exists", e.Field)
	}
	return "duplicate key violation"
}

// Unwrap returns the underlying error for error chain support
func (e *DuplicateKeyError) Unwrap() error {
	return e.err
}

// GetField returns the field that caused the violation
func (e *DuplicateKeyError) GetField() string {
	return e.Field
}

// NewDuplicateKeyError creates a new DuplicateKeyError
func NewDuplicateKeyError(field string, err error) error {
	return &DuplicateKeyError{
		Field: field,
		err:   err,
	}
}

// NewDuplicateKeyErrorWithValue creates a new DuplicateKeyError with value
// Be careful with sensitive data like emails
func NewDuplicateKeyErrorWithValue(field, value string, err error) error {
	return &DuplicateKeyError{
		Field: field,
		Value: value,
		err:   err,
	}
}

// ErrorIsDuplicateConstraint
func WrapErrorIfDuplciateConstraint(err error) (bool, error) {
	var sqliteErr sqlite3.Error
	switch {
	case errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique:
		return true, NewDuplicateKeyError(extractViolatedFieldFromSQLite(err), err)
	default:
		return false, err
	}
}

// A pre-compiled regex to find the column name from a SQLite unique constraint error.
// It looks for the pattern "table.column" at the end of the error string.
var sqliteUniqueConstraintRegex = regexp.MustCompile(`UNIQUE constraint failed: \w+\.(\w+)`)

// ExtractViolatedFieldFromSQLite attempts to parse the column name from a SQLite error.
func extractViolatedFieldFromSQLite(err error) string {
	// FindStringSubmatch will return a slice with the full match and the captured group.
	// e.g., ["UNIQUE constraint failed: users.email", "email"]
	matches := sqliteUniqueConstraintRegex.FindStringSubmatch(err.Error())

	// The captured group is at index 1.
	if len(matches) > 1 {
		return matches[1]
	}

	// Return a generic fallback if parsing fails.
	return "unknown"
}
