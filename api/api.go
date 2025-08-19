package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
)

// RespondJSONAndLog is a convenience wrapper around RespondJSON that also logs any encoding errors.
// It accepts a logger, writes a standardized JSON response, and logs at debug level if encoding fails.
//
// This function is useful when you want consistent response formatting and minimal inline error handling.
func RespondJSONAndLog(w http.ResponseWriter, logger *slog.Logger, status int, payload any) {
	if err := RespondJSON(w, status, payload); err != nil {
		logger.Debug("failed to respond with JSON", "err", err)
	}
}

// RespondJSON writes a standardized JSON response using the APIResponse format.
// It sets the appropriate HTTP status code and Content-Type header,
// and encodes the provided payload into the response body.
//
// Returns an error only if JSON encoding fails. In most cases, this happens
// if the response writer is closed or the payload is not serializable.
func RespondJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Encode and send the response. Return any encoding error to the caller.
	return json.NewEncoder(w).Encode(payload)
}

// LoginRequest defines model for LoginRequest.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse defines model for LoginResponse.
type LoginResponse struct {
	ExpiresIn    int         `json:"expiresIn"`
	RefreshToken *string     `json:"refreshToken"`
	Token        string      `json:"token"`
	User         models.User `json:"user"`
}

type TokenValidationResponse struct {
	ExpiresAt *time.Time `json:"expiresAt"`
	Valid     bool       `json:"valid"`
}

type TokenResponse struct {
	ExpiresIn int64  `json:"expiresIn"`
	Token     string `json:"token"`
}

type UserResponse struct {
	User models.User `json:"user"`
}

type PasswordUpdateRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type GetUsersResponse struct {
	Users []models.User         `json:"users"`
	Meta  models.PaginationMeta `json:"meta"`
}

type UserUpdateRequest struct {
	Claims   *models.Claims `json:"claims,omitempty"`
	Email    *string        `json:"email,omitempty"`
	IsActive *bool          `json:"isActive,omitempty"`
	Role     *models.Role   `json:"role,omitempty"`
}
