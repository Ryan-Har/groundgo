package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// APIResponse defines the standard structure for all JSON responses.
// It provides consistent fields for both successful and error responses.
type APIResponse struct {
	Success bool `json:"success"`         // Indicates if the operation was successful
	Data    any  `json:"data,omitempty"`  // Payload for successful responses
	Error   any  `json:"error,omitempty"` // Error message or details for failed responses
}

// InternalServerError sends a standardized JSON response with an HTTP 500 status code.
// The error payload is a generic "internal server error" message. It's a convenience
// wrapper around RespondJSON to reduce boilerplate for this common error.
func InternalServerError(w http.ResponseWriter) {
	_ = RespondJSON(w, http.StatusInternalServerError, false, "internal server error")
}

// RespondJSONAndLog is a convenience wrapper around RespondJSON that also logs any encoding errors.
// It accepts a logger, writes a standardized JSON response, and logs at debug level if encoding fails.
//
// - If success is true, the payload is serialized under the "data" field.
// - If success is false, the payload is serialized under the "error" field.
//
// This function is useful when you want consistent response formatting and minimal inline error handling.
func RespondJSONAndLog(w http.ResponseWriter, logger *slog.Logger, status int, success bool, payload any) {
	if err := RespondJSON(w, status, success, payload); err != nil {
		if success {
			logger.Debug("failed to respond with success JSON", "err", err)
		} else {
			logger.Debug("failed to respond with error JSON", "err", err)
		}
	}
}

// RespondJSON writes a standardized JSON response using the APIResponse format.
// It sets the appropriate HTTP status code and Content-Type header,
// and encodes the provided payload into the response body.
//
// The 'success' flag determines whether the payload is placed in the 'data' or 'error' field.
// - If success is true, payload is assigned to the 'data' field.
// - If success is false, payload is assigned to the 'error' field.
//
// Returns an error only if JSON encoding fails. In most cases, this happens
// if the response writer is closed or the payload is not serializable.
func RespondJSON(w http.ResponseWriter, status int, success bool, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Create the response envelope
	resp := APIResponse{
		Success: success,
	}

	// Populate the appropriate field
	if success {
		resp.Data = payload
	} else {
		resp.Error = payload
	}

	// Encode and send the response. Return any encoding error to the caller.
	return json.NewEncoder(w).Encode(resp)
}
