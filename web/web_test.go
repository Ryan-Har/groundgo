package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandler_handleLoginGet(t *testing.T) {
	tests := []*struct {
		name           string
		expectedStatus int
	}{
		{
			name:           "successful login page render",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _ := NewHandlerfromMocks()

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			w := httptest.NewRecorder()

			handler.HandleLoginGet()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHandler_handleLoginPost(t *testing.T) {
	validUserID := uuid.New()
	validPasswordHash, _ := passwd.HashPassword("password123")

	tests := []*struct {
		name           string
		formData       url.Values
		mockSetup      func(*AuthStoreMock, *SessionStoreMock, *CookieStoreMock)
		expectedStatus int
		expectRedirect bool
	}{
		{
			name: "successful login",
			formData: url.Values{
				"email":    []string{"test@example.com"},
				"password": []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				session := &models.Session{
					ID:        "session123",
					UserID:    validUserID,
					ExpiresAt: time.Now().Add(24 * time.Hour),
				}

				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
				sessionMock.On("Create", mock.Anything, validUserID).Return(session, nil)
				cookieMock.On("SetUserSessionCookie", mock.Anything, "session123", &session.ExpiresAt).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectRedirect: true,
		},
		{
			name: "user not found",
			formData: url.Values{
				"email":    []string{"notfound@example.com"},
				"password": []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				authMock.On("GetUserByEmail", mock.Anything, "notfound@example.com").Return(nil, errors.New("user not found"))
			},
			expectedStatus: http.StatusOK, // renders login error template
			expectRedirect: false,
		},
		{
			name: "user inactive",
			formData: url.Values{
				"email":    []string{"inactive@example.com"},
				"password": []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				user := &models.User{
					ID:           validUserID,
					Email:        "inactive@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     false, // inactive user
				}
				authMock.On("GetUserByEmail", mock.Anything, "inactive@example.com").Return(user, nil)
			},
			expectedStatus: http.StatusOK, // renders login error template
			expectRedirect: false,
		},
		{
			name: "wrong password",
			formData: url.Values{
				"email":    []string{"test@example.com"},
				"password": []string{"wrongpassword"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
			},
			expectedStatus: http.StatusOK, // renders login error template
			expectRedirect: false,
		},
		{
			name: "session creation fails",
			formData: url.Values{
				"email":    []string{"test@example.com"},
				"password": []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				user := &models.User{
					ID:           validUserID,
					Email:        "test@example.com",
					PasswordHash: &validPasswordHash,
					IsActive:     true,
				}
				authMock.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
				sessionMock.On("Create", mock.Anything, validUserID).Return(nil, errors.New("session error"))
			},
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, sessionMock, cookieMock := NewHandlerfromMocks()
			tt.mockSetup(authMock, sessionMock, cookieMock)

			body := strings.NewReader(tt.formData.Encode())
			req := httptest.NewRequest(http.MethodPost, "/login", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.HandleLoginPost()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectRedirect {
				assert.Equal(t, "/", w.Header().Get("HX-Redirect"))
			} else {
				assert.Empty(t, w.Header().Get("HX-Redirect"))
			}

			authMock.AssertExpectations(t)
			sessionMock.AssertExpectations(t)
			cookieMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleSignupPost(t *testing.T) {
	validUserID := uuid.New()

	tests := []*struct {
		name           string
		formData       url.Values
		mockSetup      func(*AuthStoreMock, *SessionStoreMock, *CookieStoreMock)
		expectedStatus int
		expectRedirect bool
	}{
		{
			name: "successful signup",
			formData: url.Values{
				"email":    []string{"new@example.com"},
				"password": []string{"password123"},
				"confirm":  []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				user := &models.User{
					ID:    validUserID,
					Email: "new@example.com",
				}
				session := &models.Session{
					ID:        "session123",
					UserID:    validUserID,
					ExpiresAt: time.Now().Add(24 * time.Hour),
				}

				authMock.On("CheckEmailExists", mock.Anything, "new@example.com").Return(false, nil)
				authMock.On("CreateUser", mock.Anything, mock.MatchedBy(func(params models.CreateUserParams) bool {
					return params.Email == "new@example.com" && params.Role == "user"
				})).Return(user, nil)
				sessionMock.On("Create", mock.Anything, validUserID).Return(session, nil)
				cookieMock.On("SetUserSessionCookie", mock.Anything, "session123", &session.ExpiresAt).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectRedirect: true,
		},
		{
			name: "passwords don't match",
			formData: url.Values{
				"email":    []string{"new@example.com"},
				"password": []string{"password123"},
				"confirm":  []string{"different"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				// no mock calls expected
			},
			expectedStatus: http.StatusOK, // renders signup error template
			expectRedirect: false,
		},
		{
			name: "email already exists",
			formData: url.Values{
				"email":    []string{"existing@example.com"},
				"password": []string{"password123"},
				"confirm":  []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				authMock.On("CheckEmailExists", mock.Anything, "existing@example.com").Return(true, nil)
			},
			expectedStatus: http.StatusOK, // renders signup error template
			expectRedirect: false,
		},
		{
			name: "user creation fails",
			formData: url.Values{
				"email":    []string{"new@example.com"},
				"password": []string{"password123"},
				"confirm":  []string{"password123"},
			},
			mockSetup: func(authMock *AuthStoreMock, sessionMock *SessionStoreMock, cookieMock *CookieStoreMock) {
				authMock.On("CheckEmailExists", mock.Anything, "new@example.com").Return(false, nil)
				authMock.On("CreateUser", mock.Anything, mock.AnythingOfType("models.CreateUserParams")).Return(nil, errors.New("creation failed"))
			},
			expectedStatus: http.StatusOK, // renders signup error template
			expectRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, sessionMock, cookieMock := NewHandlerfromMocks()
			tt.mockSetup(authMock, sessionMock, cookieMock)

			body := strings.NewReader(tt.formData.Encode())
			req := httptest.NewRequest(http.MethodPost, "/signup", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.HandleSignupPost()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectRedirect {
				assert.Equal(t, "/", w.Header().Get("HX-Redirect"))
			} else {
				assert.Empty(t, w.Header().Get("HX-Redirect"))
			}

			authMock.AssertExpectations(t)
			sessionMock.AssertExpectations(t)
			cookieMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAdminGet(t *testing.T) {
	tests := []*struct {
		name           string
		mockSetup      func(*AuthStoreMock)
		expectedStatus int
	}{
		{
			name: "successful admin page render",
			mockSetup: func(authMock *AuthStoreMock) {
				users := []*models.User{
					{ID: uuid.New(), Email: "user1@example.com"},
					{ID: uuid.New(), Email: "user2@example.com"},
				}
				authMock.On("ListAllUsers", mock.Anything).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "list users fails",
			mockSetup: func(authMock *AuthStoreMock) {
				authMock.On("ListAllUsers", mock.Anything).Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, _, _ := NewHandlerfromMocks()
			tt.mockSetup(authMock)

			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			w := httptest.NewRecorder()

			handler.HandleAdminGet()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAdminUserEnable(t *testing.T) {
	validUserID := uuid.New()

	tests := []*struct {
		name           string
		pathID         string
		mockSetup      func(*AuthStoreMock)
		expectedStatus int
		expectHeader   bool
	}{
		{
			name:   "successful user enable",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				user := &models.User{
					ID:       validUserID,
					Email:    "test@example.com",
					IsActive: true,
				}
				authMock.On("RestoreUser", mock.Anything, validUserID).Return(nil)
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			expectHeader:   true,
		},
		{
			name:           "invalid UUID",
			pathID:         "invalid-uuid",
			mockSetup:      func(authMock *AuthStoreMock) {}, // no calls expected
			expectedStatus: http.StatusBadRequest,
			expectHeader:   false,
		},
		{
			name:   "restore user fails",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				authMock.On("RestoreUser", mock.Anything, validUserID).Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectHeader:   false,
		},
		{
			name:   "get user after restore fails",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				authMock.On("RestoreUser", mock.Anything, validUserID).Return(nil)
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(nil, errors.New("user not found"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectHeader:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, _, _ := NewHandlerfromMocks()
			tt.mockSetup(authMock)

			req := httptest.NewRequest(http.MethodPost, "/admin/users/"+tt.pathID+"/enable", nil)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			handler.HandleAdminUserEnable()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectHeader {
				assert.Equal(t, `{"update-stats":{"active":1,"inactive":-1}}`, w.Header().Get("HX-Trigger"))
			} else {
				assert.Empty(t, w.Header().Get("HX-Trigger"))
			}

			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAdminUserDisable(t *testing.T) {
	validUserID := uuid.New()

	tests := []*struct {
		name           string
		pathID         string
		mockSetup      func(*AuthStoreMock)
		expectedStatus int
		expectHeader   bool
	}{
		{
			name:   "successful user disable",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				user := &models.User{
					ID:       validUserID,
					Email:    "test@example.com",
					IsActive: false,
				}
				authMock.On("SoftDeleteUser", mock.Anything, validUserID).Return(nil)
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			expectHeader:   true,
		},
		{
			name:           "invalid UUID",
			pathID:         "invalid-uuid",
			mockSetup:      func(authMock *AuthStoreMock) {}, // no calls expected
			expectedStatus: http.StatusBadRequest,
			expectHeader:   false,
		},
		{
			name:   "soft delete fails",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				authMock.On("SoftDeleteUser", mock.Anything, validUserID).Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectHeader:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, _, _ := NewHandlerfromMocks()
			tt.mockSetup(authMock)

			req := httptest.NewRequest(http.MethodPost, "/admin/users/"+tt.pathID+"/disable", nil)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			handler.HandleAdminUserDisable()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectHeader {
				assert.Equal(t, `{"update-stats":{"active":-1,"inactive":1}}`, w.Header().Get("HX-Trigger"))
			} else {
				assert.Empty(t, w.Header().Get("HX-Trigger"))
			}

			authMock.AssertExpectations(t)
		})
	}
}

func TestHandler_handleAdminUserDelete(t *testing.T) {
	validUserID := uuid.New()

	tests := []*struct {
		name           string
		pathID         string
		mockSetup      func(*AuthStoreMock)
		expectedStatus int
		expectedHeader string
	}{
		{
			name:   "successful delete active regular user",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				user := &models.User{
					ID:       validUserID,
					Email:    "test@example.com",
					IsActive: true,
					Role:     models.RoleUser, // regular user
				}
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedHeader: `{"update-stats":{"total":-1,"active":-1}}`,
		},
		{
			name:   "successful delete active admin user",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				user := &models.User{
					ID:       validUserID,
					Email:    "admin@example.com",
					IsActive: true,
					Role:     models.RoleAdmin, // admin user
				}
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedHeader: `{"update-stats":{"total":-1,"active":-1,"admin":-1}}`,
		},
		{
			name:           "invalid UUID",
			pathID:         "invalid-uuid",
			mockSetup:      func(authMock *AuthStoreMock) {}, // no calls expected
			expectedStatus: http.StatusBadRequest,
			expectedHeader: "",
		},
		{
			name:   "get user fails",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(nil, errors.New("user not found"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedHeader: "",
		},
		{
			name:   "hard delete fails",
			pathID: validUserID.String(),
			mockSetup: func(authMock *AuthStoreMock) {
				user := &models.User{
					ID:       validUserID,
					Email:    "test@example.com",
					IsActive: true,
					Role:     models.RoleUser,
				}
				authMock.On("GetUserByID", mock.Anything, validUserID).Return(user, nil)
				authMock.On("HardDeleteUser", mock.Anything, validUserID).Return(errors.New("delete failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, authMock, _, _ := NewHandlerfromMocks()
			tt.mockSetup(authMock)

			req := httptest.NewRequest(http.MethodDelete, "/admin/users/"+tt.pathID, nil)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			handler.HandleAdminUserDelete()(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedHeader != "" {
				assert.Equal(t, tt.expectedHeader, w.Header().Get("HX-Trigger"))
			} else {
				assert.Empty(t, w.Header().Get("HX-Trigger"))
			}

			authMock.AssertExpectations(t)
		})
	}
}

func TestAdminCountDelta(t *testing.T) {
	tests := []*struct {
		name             string
		beforeUpdateUser *models.User
		afterUpdateUser  *models.User
		expected         int
	}{
		{
			name:             "nil before user",
			beforeUpdateUser: nil,
			afterUpdateUser:  &models.User{Role: models.RoleAdmin},
			expected:         0,
		},
		{
			name:             "promoted to admin",
			beforeUpdateUser: &models.User{Role: models.RoleUser},
			afterUpdateUser:  &models.User{Role: models.RoleAdmin},
			expected:         1,
		},
		{
			name:             "demoted from admin",
			beforeUpdateUser: &models.User{Role: models.RoleAdmin},
			afterUpdateUser:  &models.User{Role: models.RoleUser},
			expected:         -1,
		},
		{
			name:             "both admin roles",
			beforeUpdateUser: &models.User{Role: models.RoleAdmin},
			afterUpdateUser:  &models.User{Role: models.RoleAdmin},
			expected:         0,
		},
		{
			name:             "both regular roles",
			beforeUpdateUser: &models.User{Role: models.RoleUser},
			afterUpdateUser:  &models.User{Role: models.RoleUser},
			expected:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adminCountDelta(tt.beforeUpdateUser, tt.afterUpdateUser)
			assert.Equal(t, tt.expected, result)
		})
	}
}
