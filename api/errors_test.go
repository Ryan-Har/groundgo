package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewError(t *testing.T) {
	tests := []*struct {
		name            string
		status          int
		key             ErrorKey
		details         string
		expectedStatus  int
		expectedError   string
		expectedDetails string
	}{
		{
			name:            "known error key",
			status:          http.StatusBadRequest,
			key:             ErrValidation,
			details:         "email is invalid",
			expectedStatus:  http.StatusBadRequest,
			expectedError:   "validation failed",
			expectedDetails: "email is invalid",
		},
		{
			name:            "unknown error key",
			status:          http.StatusTeapot,
			key:             ErrorKey("unknown_key"),
			details:         "some details",
			expectedStatus:  http.StatusTeapot,
			expectedError:   "unknown error",
			expectedDetails: "some details",
		},
		{
			name:            "empty details",
			status:          http.StatusNotFound,
			key:             ErrNotFound,
			details:         "",
			expectedStatus:  http.StatusNotFound,
			expectedError:   "resource not found",
			expectedDetails: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, errResp := NewError(tt.status, tt.key, tt.details)

			assert.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedError, errResp.Error)
			assert.Equal(t, tt.expectedDetails, errResp.Details)
		})
	}
}

func TestErrorResponseHelpers(t *testing.T) {
	tests := []*struct {
		name           string
		errorFunc      func() (int, ErrorResponse)
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "BadRequestInvalidJSON",
			errorFunc:      BadRequestInvalidJSON,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid JSON format",
		},
		{
			name:           "InternalServerError",
			errorFunc:      InternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "internal server error",
		},
		{
			name:           "UnauthorizedInvalidCredentials",
			errorFunc:      UnauthorizedInvalidCredentials,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid credentials",
		},
		{
			name:           "UnauthorizedMissingRefreshToken",
			errorFunc:      UnauthorizedMissingRefreshToken,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "authentication required",
		},
		{
			name:           "UnauthorizedInvalidToken",
			errorFunc:      UnauthorizedInvalidToken,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid token",
		},
		{
			name:           "ForbiddenAccessDenied",
			errorFunc:      ForbiddenAccessDenied,
			expectedStatus: http.StatusForbidden,
			expectedError:  "access denied",
		},
		{
			name:           "MethodNotAllowed",
			errorFunc:      MethodNotAllowed,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "method not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, errResp := tt.errorFunc()

			assert.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedError, errResp.Error)
		})
	}
}

func TestErrorResponseHelpersWithParams(t *testing.T) {
	// Test helper functions that take parameters
	t.Run("BadRequestValidation", func(t *testing.T) {
		status, errResp := BadRequestValidation("custom validation message")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "validation failed", errResp.Error)
		assert.Equal(t, "custom validation message", errResp.Details)
	})

	t.Run("NotFound", func(t *testing.T) {
		status, errResp := NotFound("user not found")
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "resource not found", errResp.Error)
		assert.Equal(t, "user not found", errResp.Details)
	})

	t.Run("ResourceConflict", func(t *testing.T) {
		status, errResp := ResourceConflict("email already exists")
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "resource conflict", errResp.Error)
		assert.Equal(t, "email already exists", errResp.Details)
	})
}

func TestReturnError(t *testing.T) {
	t.Run("calls error function and responds", func(t *testing.T) {
		w := httptest.NewRecorder()
		logger := slog.Default()

		errorFunc := func() (int, ErrorResponse) {
			return BadRequestValidation("test error")
		}

		ReturnError(w, logger, errorFunc)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "validation failed", response.Error)
		assert.Equal(t, "test error", response.Details)
	})
}
