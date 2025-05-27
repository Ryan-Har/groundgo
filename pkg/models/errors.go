package models

import "fmt"

//
// ValidationError – for invalid parameters or business rule violations.
// Supports errors.Is.
//

// ValidationError represents an error due to invalid or malformed input.
type ValidationError struct {
	msg string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.msg)
}

// NewValidationError creates a new ValidationError with the given message.
func NewValidationError(msg string) error {
	return &ValidationError{msg: msg}
}

// ErrValidation is a sentinel value for errors.Is comparisons.
var ErrValidation = &ValidationError{}

//
// TransformationError – for issues converting generic input into backend-specific formats.
// Supports errors.Is.
//

// TransformationError wraps errors that occur during the transformation of inputs.
type TransformationError struct {
	msg string
}

// Error implements the error interface.
func (e *TransformationError) Error() string {
	return fmt.Sprintf("transformation error: %s", e.msg)
}

// NewTransformationError creates a new TransformationError.
func NewTransformationError(msg string) error {
	return &TransformationError{
		msg: msg,
	}
}

// ErrTransformation is a sentinel value for errors.Is comparisons.
var ErrTransformation = &TransformationError{}

// DatabaseError – for failures interacting with the persistence layer.
// Supports errors.Is, errors.As, and errors.Unwrap.
//
// DatabaseError wraps errors related to database or SQL interactions.
// Will only be provided as a response from internal stores.
type DatabaseError struct {
	msg string
	err error
}

// Error implements the error interface.
func (e *DatabaseError) Error() string {
	return fmt.Sprintf("database error: %s: %v", e.msg, e.err)
}

// Unwrap allows errors.Unwrap to access the underlying error.
func (e *DatabaseError) Unwrap() error {
	return e.err
}

// NewDatabaseError creates a new DatabaseError.
func NewDatabaseError(msg string, err error) error {
	return &DatabaseError{
		msg: msg,
		err: err,
	}
}

// ErrDatabase is a sentinel value for errors.Is comparisons.
var ErrDatabase = &DatabaseError{}
