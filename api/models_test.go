package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRespondJSON(t *testing.T) {
	tests := []*struct {
		name           string
		status         int
		payload        any
		expectedStatus int
		expectedBody   string
		wantErr        bool
	}{
		{
			name:           "valid JSON response",
			status:         http.StatusOK,
			payload:        map[string]string{"message": "success"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
			wantErr:        false,
		},
		{
			name:           "empty payload",
			status:         http.StatusNoContent,
			payload:        nil,
			expectedStatus: http.StatusNoContent,
			expectedBody:   "null",
			wantErr:        false,
		},
		{
			name:           "error response",
			status:         http.StatusBadRequest,
			payload:        ErrorResponse{Error: "validation failed", Details: "email is required"},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"validation failed","details":"email is required"}`,
			wantErr:        false,
		},
		{
			name:           "struct payload",
			status:         http.StatusCreated,
			payload:        UserResponse{User: models.User{ID: uuid.New(), Email: "test@example.com"}},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"user":{"email":"test@example.com"`,
			wantErr:        false,
		},
		{
			name:           "invalid payload - channel",
			status:         http.StatusOK,
			payload:        make(chan int), // channels are not JSON serializable
			expectedStatus: http.StatusOK,
			expectedBody:   "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			err := RespondJSON(w, tt.status, tt.payload)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)
				assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

				// For complex objects, just check if it contains expected parts
				if tt.expectedBody != "" {
					body := w.Body.String()
					if tt.name == "struct payload" {
						assert.Contains(t, body, `"email":"test@example.com"`)
						// Don't check ID since it's a randomly generated UUID
					} else {
						// Remove whitespace for comparison
						expectedCompact := &bytes.Buffer{}
						err := json.Compact(expectedCompact, []byte(tt.expectedBody))
						require.NoError(t, err)

						actualCompact := &bytes.Buffer{}
						err = json.Compact(actualCompact, []byte(body))
						require.NoError(t, err)

						assert.Equal(t, expectedCompact.String(), actualCompact.String())
					}
				}
			}
		})
	}
}

func TestRespondJSONAndLog(t *testing.T) {
	tests := []*struct {
		name           string
		status         int
		payload        any
		expectedStatus int
		expectLogCall  bool
	}{
		{
			name:           "successful response - no log",
			status:         http.StatusOK,
			payload:        map[string]string{"success": "true"},
			expectedStatus: http.StatusOK,
			expectLogCall:  false,
		},
		{
			name:           "invalid payload - should log",
			status:         http.StatusOK,
			payload:        make(chan int), // will cause JSON encoding error
			expectedStatus: http.StatusOK,
			expectLogCall:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a logger that writes to a buffer so we can check if it was called
			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			RespondJSONAndLog(w, logger, tt.status, tt.payload)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			if tt.expectLogCall {
				assert.Contains(t, logBuffer.String(), "failed to respond with JSON")
			} else {
				assert.Empty(t, logBuffer.String())
			}
		})
	}
}

func TestLoginRequest_Validate(t *testing.T) {
	tests := []*struct {
		name    string
		request LoginRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			request: LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			request: LoginRequest{
				Email:    "",
				Password: "password123",
			},
			wantErr: true,
			errMsg:  "email is required",
		},
		{
			name: "invalid email format",
			request: LoginRequest{
				Email:    "not-an-email",
				Password: "password123",
			},
			wantErr: true,
			errMsg:  "email not in RFC 5322 format",
		},
		{
			name: "empty password",
			request: LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			wantErr: true,
			errMsg:  "password is required",
		},
		{
			name: "both empty",
			request: LoginRequest{
				Email:    "",
				Password: "",
			},
			wantErr: true,
			errMsg:  "email is required", // should fail on email first
		},
		{
			name: "complex valid email",
			request: LoginRequest{
				Email:    "user.name+tag@example-domain.com",
				Password: "password123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.IsType(t, &models.ValidationError{}, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPasswordUpdateRequest_Validate(t *testing.T) {
	tests := []*struct {
		name    string
		request PasswordUpdateRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			request: PasswordUpdateRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "newpassword123",
			},
			wantErr: false,
		},
		{
			name: "empty current password",
			request: PasswordUpdateRequest{
				CurrentPassword: "",
				NewPassword:     "newpassword123",
			},
			wantErr: true,
			errMsg:  "current password is required",
		},
		{
			name: "empty new password",
			request: PasswordUpdateRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "",
			},
			wantErr: true,
			errMsg:  "new password is required",
		},
		{
			name: "both passwords empty",
			request: PasswordUpdateRequest{
				CurrentPassword: "",
				NewPassword:     "",
			},
			wantErr: true,
			errMsg:  "current password is required", // should fail on current password first
		},
		{
			name: "same passwords",
			request: PasswordUpdateRequest{
				CurrentPassword: "samepassword",
				NewPassword:     "samepassword",
			},
			wantErr: false, // validation doesn't check if they're the same
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.IsType(t, &models.ValidationError{}, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
