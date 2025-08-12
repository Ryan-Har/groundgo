package models

import "fmt"

// ValidationError – for invalid parameters or business rule violations.
// Supports errors.As.
//
// ValidationError represents an error due to invalid or malformed input.
type ValidationError struct {
	msg string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return e.msg
}

// NewValidationError creates a new ValidationError with the given message.
func NewValidationError(msg string) error {
	return &ValidationError{msg: msg}
}

// TransformationError – for issues converting generic input into backend-specific formats.
// Supports errors.As.
//
// TransformationError wraps errors that occur during the transformation of inputs.
type TransformationError struct {
	msg string
}

// Error implements the error interface.
func (e *TransformationError) Error() string {
	return e.msg
}

// NewTransformationError creates a new TransformationError.
func NewTransformationError(msg string) error {
	return &TransformationError{
		msg: msg,
	}
}

// DatabaseError – for failures interacting with the persistence layer.
// Supports errors.As and errors.Unwrap.
//
// DatabaseError wraps errors related to database or SQL interactions.
// Will only be provided as a response from internal stores.
type DatabaseError struct {
	err error
}

// Error implements the error interface.
func (e *DatabaseError) Error() string {
	return fmt.Sprintf("database error: %v", e.err)
}

func (e *DatabaseError) Unwrap() error {
	return e.err
}

// NewDatabaseError creates a new DatabaseError.
func NewDatabaseError(err error) error {
	return &DatabaseError{
		err: err,
	}
}
