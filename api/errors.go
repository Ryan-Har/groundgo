package api

import (
	"log/slog"
	"net/http"
)

// ErrorKey is a type alias for string, used to reference a specific
// standardized error message in the errorMessages map.
type ErrorKey string

// These constants define unique keys for each error variant.
// You can have multiple variants under the same HTTP status code.
// Example: both ErrInvalidJSON and ErrValidation map to HTTP 400.
const (
	ErrInvalidJSON      ErrorKey = "invalid_json"
	ErrValidation       ErrorKey = "validation_failed"
	ErrNotFound         ErrorKey = "not_found"
	ErrInternal         ErrorKey = "internal_error"
	ErrCredentials      ErrorKey = "invalid_credentials"
	ErrAuthRequired     ErrorKey = "auth_required"
	ErrInvalidToken     ErrorKey = "invalid_token"
	ErrAccessDenied     ErrorKey = "access_denied"
	ErrConflict         ErrorKey = "conflict"
	ErrMethodNotAllowed ErrorKey = "not_allowed"
)

// errorMessages is the centralized map of all standard error texts.
// The key is an ErrorKey constant, and the value is the message shown
// in the "error" field of the JSON response.
var errorMessages = map[ErrorKey]string{
	ErrInvalidJSON:      "invalid JSON format",
	ErrValidation:       "validation failed",
	ErrNotFound:         "resource not found",
	ErrInternal:         "internal server error",
	ErrCredentials:      "invalid credentials",
	ErrAuthRequired:     "authentication required",
	ErrInvalidToken:     "invalid token",
	ErrAccessDenied:     "access denied",
	ErrConflict:         "resource conflict",
	ErrMethodNotAllowed: "method not allowed",
}

// ErrorResponse represents the JSON body returned for an error.
// - Error:   short machine-readable summary of the problem
// - Details: optional human-readable explanation (pointer so it can be nil)
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// NewError creates an ErrorResponse for a given HTTP status, error key, and details.
// It looks up the short error message from the errorMessages map using the provided key.
// If the key is not found, it falls back to "unknown error".
func NewError(status int, key ErrorKey, details string) (int, ErrorResponse) {
	msg, ok := errorMessages[key]
	if !ok {
		msg = "unknown error"
	}
	return status, ErrorResponse{
		Error:   msg,
		Details: details,
	}
}

// BadRequestInvalidJSON returns a 400 error for invalid JSON payloads,
// with a fixed details message to aid client debugging.
func BadRequestInvalidJSON() (int, ErrorResponse) {
	return NewError(http.StatusBadRequest, ErrInvalidJSON, "expected valid JSON object")
}

// BadRequestValidation returns a 400 error for failed validation,
// allowing optional custom details for more context.
func BadRequestValidation(details string) (int, ErrorResponse) {
	return NewError(http.StatusBadRequest, ErrValidation, details)
}

// NotFound returns a 404 error with optional custom details,
// typically used when a requested resource cannot be found.
func NotFound(details string) (int, ErrorResponse) {
	return NewError(http.StatusNotFound, ErrNotFound, details)
}

// InternalServerError returns a 500 error with a generic details message,
// signaling an unexpected failure on the server side.
func InternalServerError() (int, ErrorResponse) {
	return NewError(http.StatusInternalServerError, ErrInternal, "an unexpected error occurred")
}

func MethodNotAllowed() (int, ErrorResponse) {
	return NewError(http.StatusMethodNotAllowed, ErrMethodNotAllowed, "")
}

// UnauthorizedInvalidCredentials returns a 401 error indicating incorrect login credentials.
func UnauthorizedInvalidCredentials() (int, ErrorResponse) {
	return NewError(http.StatusUnauthorized, ErrCredentials, "email or password is incorrect")
}

// UnauthorizedMissingRefreshToken returns a 401 error indicating that refresh token is required.
func UnauthorizedMissingRefreshToken() (int, ErrorResponse) {
	return NewError(http.StatusUnauthorized, ErrAuthRequired, "refresh token cookie not found")
}

// UnauthorizedInvalidToken returns a 401 error indicating that the provided token is invalid or expired.
func UnauthorizedInvalidToken() (int, ErrorResponse) {
	return NewError(http.StatusUnauthorized, ErrInvalidToken, "token is expired or malformed")
}

// ForbiddenAccessDenied returns a 403 error indicating insufficient permissions for the requested operation.
func ForbiddenAccessDenied() (int, ErrorResponse) {
	return NewError(http.StatusForbidden, ErrAccessDenied, "insufficient permissions for this operation")
}

// ResourceConflict returns a 409 error indicating a conflict, such as duplicate resource creation.
// Optional details can be provided to clarify the conflict.
func ResourceConflict(details string) (int, ErrorResponse) {
	return NewError(http.StatusConflict, ErrConflict, details)
}

// ReturnError accepts a function returning (int, ErrorResponse)
// calls it, and passes the result to RespondJSONAndLog with the given writer and logger.
func ReturnError(w http.ResponseWriter, logger *slog.Logger, errorFunc func() (int, ErrorResponse)) {
	status, errResp := errorFunc()
	RespondJSONAndLog(w, logger, status, errResp)
}
