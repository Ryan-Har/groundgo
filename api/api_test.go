package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db"
	"github.com/Ryan-Har/groundgo/internal/testutil"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/middlewarectx"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newHandlerfromMocks() (*Handler,
	*testutil.AuthStoreMock,
	*testutil.SessionStoreMock,
	*testutil.TokenStoreMock,
	*testutil.CookieStoreMock) {

	auth := &testutil.AuthStoreMock{}
	session := &testutil.SessionStoreMock{}
	token := &testutil.TokenStoreMock{}
	cookie := &testutil.CookieStoreMock{}

	h := New(testutil.NoopLogger(), auth, session, token, cookie)
	return h, auth, session, token, cookie
}

func TestHandler_handleAPITokenVerify(t *testing.T) {
	const validToken = "valid-token"
	handler, _, _, tokenMock, _ := newHandlerfromMocks()

	tests := []struct {
		name           string
		setupContext   func(req *http.Request) *http.Request
		mockReturn     func()
		expectedStatus int
	}{
		{
			name: "valid token",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), validToken))
			},
			mockReturn: func() {
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, validToken).Return(&tokenstore.AccessToken{
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					},
				}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing token",
			setupContext: func(req *http.Request) *http.Request {
				return req
			},
			mockReturn:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "empty token",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), ""))
			},
			mockReturn:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), "bad-token"))
			},
			mockReturn: func() {
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, "bad-token").
					Return(nil, assert.AnError)
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks for each test
			tokenMock.ExpectedCalls = nil
			tt.mockReturn()

			req := httptest.NewRequest(http.MethodGet, "/api/token/verify", nil)
			req = tt.setupContext(req)
			w := httptest.NewRecorder()

			handler.HandleAPITokenVerify()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tokenMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPITokenRefresh(t *testing.T) {
	handler, _, _, tokenMock, cookieMock := newHandlerfromMocks()

	tests := []struct {
		name           string
		setupCookies   func(req *http.Request)
		setupMocks     func()
		expectedStatus int
	}{
		{
			name: "successful refresh",
			setupCookies: func(req *http.Request) {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: "valid-refresh-token",
				})
			},
			setupMocks: func() {
				tokenMock.On("RotateRefreshToken", mock.Anything, "valid-refresh-token").Return(&tokenstore.TokenPair{
					AccessToken:      "new-access-token",
					RefreshToken:     "new-refresh-token",
					ExpiresInSeconds: 3600,
				}, nil)
				cookieMock.On("SetRefreshTokenCookie", mock.Anything, "new-refresh-token", (*time.Time)(nil)).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing refresh token cookie",
			setupCookies: func(req *http.Request) {
				// No cookies
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid refresh token",
			setupCookies: func(req *http.Request) {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: "invalid-token",
				})
			},
			setupMocks: func() {
				tokenMock.On("RotateRefreshToken", mock.Anything, "invalid-token").Return(nil, tokenstore.ErrInvalidToken)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "token reuse detected",
			setupCookies: func(req *http.Request) {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: "reused-token",
				})
			},
			setupMocks: func() {
				tokenMock.On("RotateRefreshToken", mock.Anything, "reused-token").Return(nil, tokenstore.ErrTokenReuseDetected)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "cookie setting fails",
			setupCookies: func(req *http.Request) {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: "valid-token",
				})
			},
			setupMocks: func() {
				tokenMock.On("RotateRefreshToken", mock.Anything, "valid-token").Return(&tokenstore.TokenPair{
					AccessToken:      "new-access-token",
					RefreshToken:     "new-refresh-token",
					ExpiresInSeconds: 3600,
				}, nil)
				cookieMock.On("SetRefreshTokenCookie", mock.Anything, "new-refresh-token", (*time.Time)(nil)).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenMock.ExpectedCalls = nil
			cookieMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPost, "/api/token/refresh", nil)
			tt.setupCookies(req)
			w := httptest.NewRecorder()

			handler.HandleAPITokenRefresh()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tokenMock.AssertExpectations(t)
			cookieMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPILoginPost(t *testing.T) {
	validUserID := uuid.New()
	validPasswordHash, _ := passwd.HashPassword("password123")
	handler, authMock, _, tokenMock, cookieMock := newHandlerfromMocks()

	tests := []struct {
		name           string
		payload        string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:    "successful login",
			payload: `{"email":"test@example.com","password":"password123"}`,
			setupMocks: func() {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
				tokenMock.On("IssueTokenPair", mock.Anything, user).Return(&tokenstore.TokenPair{
					AccessToken:      "access-token",
					RefreshToken:     "refresh-token",
					ExpiresInSeconds: int64(3600),
				}, nil)
				cookieMock.On("SetRefreshTokenCookie", mock.Anything, "refresh-token", (*time.Time)(nil)).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid JSON",
			payload:        `{invalid}`,
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "validation error - missing email",
			payload: `{"password":"password123"}`,
			setupMocks: func() {
				// Validation will fail before any mocks are called
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "user not found",
			payload: `{"email":"nonexistent@example.com","password":"password123"}`,
			setupMocks: func() {
				authMock.On("GetUserByEmail", mock.Anything, "nonexistent@example.com").Return(nil, sql.ErrNoRows)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:    "user inactive",
			payload: `{"email":"inactive@example.com","password":"password123"}`,
			setupMocks: func() {
				user := &models.User{
					ID:           validUserID,
					Email:        "inactive@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     false,
				}
				authMock.On("GetUserByEmail", mock.Anything, "inactive@example.com").Return(user, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:    "wrong password",
			payload: `{"email":"test@example.com","password":"wrongpassword"}`,
			setupMocks: func() {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:    "token generation fails",
			payload: `{"email":"test@example.com","password":"password123"}`,
			setupMocks: func() {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
				tokenMock.On("IssueTokenPair", mock.Anything, user).Return(nil, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tokenMock.ExpectedCalls = nil
			cookieMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleAPILoginPost()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
			tokenMock.AssertExpectations(t)
			cookieMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPILogoutPost(t *testing.T) {
	handler, _, _, tokenMock, cookieMock := newHandlerfromMocks()
	validToken := "valid-access-token"

	tests := []struct {
		name           string
		setupContext   func(req *http.Request) *http.Request
		setupMocks     func()
		expectedStatus int
	}{
		{
			name: "successful logout",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), validToken))
			},
			setupMocks: func() {
				accessToken := &tokenstore.AccessToken{}
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, validToken).Return(accessToken, nil)
				tokenMock.On("RevokeAccessToken", mock.Anything, accessToken).Return(nil)
				cookieMock.On("ClearRefreshTokenCookie", mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "missing token",
			setupContext: func(req *http.Request) *http.Request {
				return req
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), "invalid-token"))
			},
			setupMocks: func() {
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, "invalid-token").Return(nil, assert.AnError)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "revoke token fails",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), validToken))
			},
			setupMocks: func() {
				accessToken := &tokenstore.AccessToken{}
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, validToken).Return(accessToken, nil)
				tokenMock.On("RevokeAccessToken", mock.Anything, accessToken).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "clear cookie fails",
			setupContext: func(req *http.Request) *http.Request {
				return req.WithContext(middlewarectx.ContextWithJWT(req.Context(), validToken))
			},
			setupMocks: func() {
				accessToken := &tokenstore.AccessToken{}
				tokenMock.On("ParseAccessTokenAndValidate", mock.Anything, validToken).Return(accessToken, nil)
				tokenMock.On("RevokeAccessToken", mock.Anything, accessToken).Return(nil)
				cookieMock.On("ClearRefreshTokenCookie", mock.Anything).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenMock.ExpectedCalls = nil
			cookieMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
			req = tt.setupContext(req)
			w := httptest.NewRecorder()

			handler.HandleAPILogoutPost()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tokenMock.AssertExpectations(t)
			cookieMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPIGetUserByID(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()
	validUserID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:   "successful get user",
			userID: validUserID.String(),
			setupMocks: func() {
				user := &models.User{
					ID:    validUserID,
					Email: "test@example.com",
				}
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid UUID",
			userID:         "invalid-uuid",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "user not found",
			userID: validUserID.String(),
			setupMocks: func() {
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(nil, models.NewDatabaseError(sql.ErrNoRows))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "database error",
			userID: validUserID.String(),
			setupMocks: func() {
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(nil, models.NewDatabaseError(assert.AnError))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodGet, "/api/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			w := httptest.NewRecorder()

			handler.HandleAPIGetUserByID()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPIGetOwnUser(t *testing.T) {
	handler, _, _, _, _ := newHandlerfromMocks()
	validUserID := uuid.New()

	tests := []struct {
		name           string
		setupContext   func(req *http.Request) *http.Request
		expectedStatus int
	}{
		{
			name: "successful get own user",
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:    validUserID,
					Email: "test@example.com",
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "user not in context",
			setupContext: func(req *http.Request) *http.Request {
				return req
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "guest session (nil UUID)",
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID: uuid.Nil,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/user/me", nil)
			req = tt.setupContext(req)
			w := httptest.NewRecorder()

			handler.HandleAPIGetOwnUser()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHandler_HandleAPIChangeOwnPassword(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()
	validUserID := uuid.New()
	validPasswordHash, _ := passwd.HashPassword("currentpassword")

	tests := []struct {
		name           string
		payload        string
		setupContext   func(req *http.Request) *http.Request
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:    "successful password change",
			payload: `{"currentPassword":"currentpassword","newPassword":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks: func() {
				authMock.On("UpdateUserPassword", mock.Anything, validUserID, "newpassword123").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:    "user not in context",
			payload: `{"current_password":"currentpassword","new_password":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				return req
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:    "guest session",
			payload: `{"current_password":"currentpassword","new_password":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{ID: uuid.Nil}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:    "invalid JSON",
			payload: `{invalid}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:           validUserID,
					PasswordHash: &validPasswordHash,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "validation error",
			payload: `{"currentPassword":"","newPassword":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:           validUserID,
					PasswordHash: &validPasswordHash,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "wrong current password",
			payload: `{"currentPassword":"wrongpassword","newPassword":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:           validUserID,
					PasswordHash: &validPasswordHash,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:    "update password fails",
			payload: `{"currentPassword":"currentpassword","newPassword":"newpassword123"}`,
			setupContext: func(req *http.Request) *http.Request {
				user := &models.User{
					ID:           validUserID,
					PasswordHash: &validPasswordHash,
				}
				return req.WithContext(middlewarectx.ContextWithUser(req.Context(), user))
			},
			setupMocks: func() {
				authMock.On("UpdateUserPassword", mock.Anything, validUserID, "newpassword123").Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPatch, "/api/user/password", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			req = tt.setupContext(req)
			w := httptest.NewRecorder()

			handler.HandleAPIChangeOwnPassword()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPIGetUsers(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()

	tests := []struct {
		name           string
		queryParams    string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:        "successful get users",
			queryParams: "page=1&limit=10",
			setupMocks: func() {
				users := []*models.User{
					{ID: uuid.New(), Email: "user1@example.com"},
					{ID: uuid.New(), Email: "user2@example.com"},
				}
				meta := models.PaginationMeta{
					Page:       1,
					Limit:      10,
					Total:      2,
					TotalPages: 1,
				}
				params := models.GetPaginatedUsersParams{Page: 1, Limit: 10}
				authMock.On("ListUsersPaginatedWithRoleFilter", mock.Anything, params).Return(users, meta, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "with role filter",
			queryParams: "page=1&limit=10&role=admin",
			setupMocks: func() {
				users := []*models.User{
					{ID: uuid.New(), Email: "admin@example.com"},
				}
				meta := models.PaginationMeta{
					Page:       1,
					Limit:      10,
					Total:      1,
					TotalPages: 1,
				}
				adminRole := models.RoleAdmin
				params := models.GetPaginatedUsersParams{Page: 1, Limit: 10, Role: &adminRole}
				authMock.On("ListUsersPaginatedWithRoleFilter", mock.Anything, params).Return(users, meta, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing page parameter",
			queryParams:    "limit=10",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing limit parameter",
			queryParams:    "page=1",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid page parameter",
			queryParams:    "page=invalid&limit=10",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid limit parameter",
			queryParams:    "page=1&limit=invalid",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid role parameter",
			queryParams:    "page=1&limit=10&role=invalidrole",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "validation error",
			queryParams:    "page=0&limit=10",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "no results",
			queryParams: "page=1&limit=10",
			setupMocks: func() {
				params := models.GetPaginatedUsersParams{Page: 1, Limit: 10}
				authMock.On("ListUsersPaginatedWithRoleFilter", mock.Anything, params).Return([]*models.User{}, models.PaginationMeta{}, nil)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "database error",
			queryParams: "page=1&limit=10",
			setupMocks: func() {
				params := models.GetPaginatedUsersParams{Page: 1, Limit: 10}
				authMock.On("ListUsersPaginatedWithRoleFilter", mock.Anything, params).Return(nil, models.PaginationMeta{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			url := "/api/users"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			handler.HandleAPIGetUsers()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPICreateUser(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()

	tests := []struct {
		name           string
		payload        string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:    "successful create user",
			payload: `{"email":"new@example.com","password":"password123","role":"user"}`,
			setupMocks: func() {
				user := &models.User{
					ID:    uuid.New(),
					Email: "new@example.com",
					Role:  models.RoleUser,
				}
				authMock.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).Return(user, nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid JSON",
			payload:        `{invalid}`,
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "validation error",
			payload: `{"email":"","password":"password123","role":"user"}`,
			setupMocks: func() {
				authMock.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).Return(nil, models.NewValidationError("email is required"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "duplicate email",
			payload: `{"email":"existing@example.com","password":"password123","role":"user"}`,
			setupMocks: func() {
				authMock.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).Return(nil, &db.DuplicateKeyError{Field: "email"})
			},
			expectedStatus: http.StatusConflict,
		},
		{
			name:    "database error",
			payload: `{"email":"new@example.com","password":"password123","role":"user"}`,
			setupMocks: func() {
				authMock.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).Return(nil, models.NewDatabaseError(assert.AnError))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleAPICreateUser()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPIUpdateUserByID(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()
	validUserID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		payload        string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:    "successful update user",
			userID:  validUserID.String(),
			payload: `{"email":"updated@example.com","is_active":true,"role":"admin"}`,
			setupMocks: func() {
				updatedUser := &models.User{
					ID:       validUserID,
					Email:    "updated@example.com",
					IsActive: true,
					Role:     models.RoleAdmin,
				}
				authMock.On("UpdateUserByID", mock.Anything, mock.AnythingOfType("models.UpdateUserByIDParams")).Return(updatedUser, nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid UUID",
			userID:         "invalid-uuid",
			payload:        `{"email":"updated@example.com"}`,
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON",
			userID:         validUserID.String(),
			payload:        `{invalid}`,
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "validation error",
			userID:  validUserID.String(),
			payload: `{"email":"invalid-email"}`,
			setupMocks: func() {
				authMock.On("UpdateUserByID", mock.Anything, mock.AnythingOfType("models.UpdateUserByIDParams")).Return(nil, models.NewValidationError("invalid email format"))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "user not found",
			userID:  validUserID.String(),
			payload: `{"email":"updated@example.com"}`,
			setupMocks: func() {
				authMock.On("UpdateUserByID", mock.Anything, mock.AnythingOfType("models.UpdateUserByIDParams")).Return(nil, models.NewDatabaseError(sql.ErrNoRows))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:    "duplicate email",
			userID:  validUserID.String(),
			payload: `{"email":"existing@example.com"}`,
			setupMocks: func() {
				authMock.On("UpdateUserByID", mock.Anything, mock.AnythingOfType("models.UpdateUserByIDParams")).Return(nil, &db.DuplicateKeyError{Field: "email"})
			},
			expectedStatus: http.StatusConflict,
		},
		{
			name:    "database error",
			userID:  validUserID.String(),
			payload: `{"email":"updated@example.com"}`,
			setupMocks: func() {
				authMock.On("UpdateUserByID", mock.Anything, mock.AnythingOfType("models.UpdateUserByIDParams")).Return(nil, models.NewDatabaseError(assert.AnError))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodPatch, "/api/users/"+tt.userID, strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.userID)
			w := httptest.NewRecorder()

			handler.HandleAPIUpdateUserByID()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAPIDeleteUserByID(t *testing.T) {
	handler, authMock, _, _, _ := newHandlerfromMocks()
	validUserID := uuid.New()

	tests := []struct {
		name           string
		userID         string
		setupMocks     func()
		expectedStatus int
	}{
		{
			name:   "successful delete user",
			userID: validUserID.String(),
			setupMocks: func() {
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(nil)
			},
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "invalid UUID",
			userID:         "invalid-uuid",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "user not found",
			userID: validUserID.String(),
			setupMocks: func() {
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(models.NewDatabaseError(sql.ErrNoRows))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "database error",
			userID: validUserID.String(),
			setupMocks: func() {
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(models.NewDatabaseError(assert.AnError))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock.ExpectedCalls = nil
			tt.setupMocks()

			req := httptest.NewRequest(http.MethodDelete, "/api/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			w := httptest.NewRecorder()

			handler.HandleAPIDeleteUserByID()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleJSONDecodeError(t *testing.T) {
	handler, _, _, _, _ := newHandlerfromMocks()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "validation error",
			err:            models.NewValidationError("validation failed"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "transformation error",
			err:            models.NewTransformationError("transformation failed"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "generic JSON decode error",
			err:            fmt.Errorf("invalid JSON"),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			handler.handleJSONDecodeError(w, tt.err)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHandler_handleErrors(t *testing.T) {
	handler, _, _, _, _ := newHandlerfromMocks()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "validation error",
			err:            models.NewValidationError("validation failed"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "duplicate key error",
			err:            &db.DuplicateKeyError{Field: "email"},
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "database error - no rows",
			err:            models.NewDatabaseError(sql.ErrNoRows),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "database error - other",
			err:            models.NewDatabaseError(fmt.Errorf("connection failed")),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "transformation error",
			err:            models.NewTransformationError("transformation failed"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "unknown error",
			err:            fmt.Errorf("unknown error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			handler.handleErrors(w, tt.err)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
