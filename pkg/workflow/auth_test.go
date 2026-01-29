package workflow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/internal/testutil"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_extractBearerToken(t *testing.T) {
	// Create a Workflow with mocks (even if we don't use them here)
	wf, _, _, _, _ := newWorkflowFromMocks()

	// valid (case-insensitive "Bearer")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	tok, err := wf.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "abc123", tok)

	req.Header.Set("Authorization", "bearer xyz")
	tok, err = wf.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "xyz", tok)

	// invalid format
	req.Header.Set("Authorization", "Token abc")
	_, err = wf.extractBearerToken(req)
	assert.Error(t, err)

	// empty token
	req.Header.Set("Authorization", "Bearer ")
	_, err = wf.extractBearerToken(req)
	assert.Error(t, err)

	// missing header
	req.Header.Del("Authorization")
	_, err = wf.extractBearerToken(req)
	assert.Error(t, err)
}

func Test_userFromJWTString(t *testing.T) {
	cases := []struct {
		name        string
		setupMocks  func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock)
		tokenString string
		expectError bool
		expectUser  bool
	}{
		{
			name: "success path",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				uid := uuid.New()
				token.On("ParseAccessTokenAndValidate", mock.Anything, "good").
					Return(&tokenstore.AccessToken{
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: uid.String(),
						},
					}, nil)
				auth.On("GetUserByID", mock.Anything, uid).
					Return(&models.User{ID: uid, IsActive: true}, nil)
			},
			tokenString: "good",
			expectError: false,
			expectUser:  true,
		},
		{
			name: "parse error",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				token.On("ParseAccessTokenAndValidate", mock.Anything, "bad").
					Return(nil, errors.New("parse fail"))
			},
			tokenString: "bad",
			expectError: true,
			expectUser:  false,
		},
		{
			name: "bad uuid in subject",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				token.On("ParseAccessTokenAndValidate", mock.Anything, "oops").
					Return(&tokenstore.AccessToken{
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: "not-a-uuid",
						},
					}, nil)
			},
			tokenString: "oops",
			expectError: true,
			expectUser:  false,
		},
		{
			name: "user lookup error",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				uid := uuid.New()
				token.On("ParseAccessTokenAndValidate", mock.Anything, "good2").
					Return(&tokenstore.AccessToken{
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: uid.String(),
						},
					}, nil)
				auth.On("GetUserByID", mock.Anything, uid).
					Return(nil, errors.New("db fail"))
			},
			tokenString: "good2",
			expectError: true,
			expectUser:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, authMock, _, tokenMock, _ := newWorkflowFromMocks()
			tc.setupMocks(authMock, tokenMock)

			user, err := wf.userFromJWTString(context.Background(), tc.tokenString)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.expectUser {
				assert.NotNil(t, user)
			} else {
				assert.Nil(t, user)
			}

			authMock.AssertExpectations(t)
			tokenMock.AssertExpectations(t)
		})
	}
}

func Test_userFromSession(t *testing.T) {
	cases := []struct {
		name           string
		session        *models.Session
		setupMocks     func(auth *testutil.AuthStoreMock, uid uuid.UUID)
		expectedError  bool
		expectedRole   models.Role
		expectedUserID uuid.UUID
	}{
		{
			name:    "guest session returns guest user",
			session: &models.Session{UserID: uuid.Nil},
			setupMocks: func(auth *testutil.AuthStoreMock, uid uuid.UUID) {
				// no mocks needed for guest
			},
			expectedError:  false,
			expectedRole:   models.RoleGuest,
			expectedUserID: uuid.Nil,
		},
		{
			name:    "active user session",
			session: &models.Session{UserID: uuid.New()},
			setupMocks: func(auth *testutil.AuthStoreMock, uid uuid.UUID) {
				auth.On("GetUserByID", mock.Anything, uid).
					Return(&models.User{ID: uid, IsActive: true}, nil)
			},
			expectedError: false,
			expectedRole:  "",
		},
		{
			name:    "inactive user causes error",
			session: &models.Session{UserID: uuid.New()},
			setupMocks: func(auth *testutil.AuthStoreMock, uid uuid.UUID) {
				auth.On("GetUserByID", mock.Anything, uid).
					Return(nil, errors.New("inactive"))
			},
			expectedError: true,
			expectedRole:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, authMock, _, _, _ := newWorkflowFromMocks()
			tc.setupMocks(authMock, tc.session.UserID)

			user, err := wf.userFromSession(context.Background(), tc.session)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.session.UserID == uuid.Nil {
					assert.Equal(t, models.RoleGuest, user.Claims["/"])
				} else {
					assert.Equal(t, tc.session.UserID, user.ID)
				}
			}

			authMock.AssertExpectations(t)
		})
	}
}

func TestWorkflow_resolveFromJWT(t *testing.T) {
	uid := uuid.New()

	cases := []struct {
		name           string
		setupMocks     func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock)
		setupRequest   func() *http.Request
		expectOK       bool
		expectUserID   uuid.UUID
		expectTokenStr string
	}{
		{
			name: "valid JWT",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				token.On("ParseAccessTokenAndValidate", mock.Anything, "tok").
					Return(&tokenstore.AccessToken{RegisteredClaims: jwt.RegisteredClaims{Subject: uid.String()}}, nil)
				auth.On("GetUserByID", mock.Anything, uid).
					Return(&models.User{ID: uid, IsActive: true}, nil)
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer tok")
				return req
			},
			expectOK:       true,
			expectUserID:   uid,
			expectTokenStr: "tok",
		},
		{
			name:       "invalid header",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {},
			setupRequest: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			expectOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, authMock, _, tokenMock, _ := newWorkflowFromMocks()
			tc.setupMocks(authMock, tokenMock)

			user, tok, err := wf.resolveFromJWT(tc.setupRequest())

			if tc.expectOK {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, tc.expectUserID, user.ID)
				assert.Equal(t, tc.expectTokenStr, tok)
			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Empty(t, tok)
			}

			authMock.AssertExpectations(t)
			tokenMock.AssertExpectations(t)
		})
	}
}

func Test_resolveFromSession(t *testing.T) {
	cases := []struct {
		name         string
		setupMocks   func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, userID uuid.UUID)
		setupRequest func() *http.Request
		sessionID    string
		expectOK     bool
		expectUserID uuid.UUID
		expectErr    error
	}{
		{
			name:      "valid session",
			sessionID: "s1",
			setupMocks: func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, userID uuid.UUID) {
				session.On("Get", mock.Anything, "s1").
					Return(&models.Session{UserID: userID}, nil)
				auth.On("GetUserByID", mock.Anything, userID).
					Return(&models.User{ID: userID, IsActive: true}, nil)
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "s1"})
				return req
			},
			expectOK:     true,
			expectUserID: uuid.New(), // will match mocked userID
		},
		{
			name:      "expired session",
			sessionID: "expired",
			setupMocks: func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, userID uuid.UUID) {
				session.On("Get", mock.Anything, "expired").
					Return(nil, sessionstore.ErrSessionExpired)
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "expired"})
				return req
			},
			expectOK:  false,
			expectErr: ErrSessionExpired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, authMock, sessionMock, _, _ := newWorkflowFromMocks()
			userID := uuid.New()
			tc.setupMocks(sessionMock, authMock, userID)

			req := tc.setupRequest()
			user, err := wf.resolveFromSession(req)

			if tc.expectOK {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, userID, user.ID)
			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
			}

			authMock.AssertExpectations(t)
			sessionMock.AssertExpectations(t)
		})
	}
}

func Test_extractSessionCookie(t *testing.T) {
	wf, _, _, _, _ := newWorkflowFromMocks()

	// missing cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := wf.extractSessionCookie(req)
	assert.Error(t, err)

	// present cookie
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "abc"})
	c, err := wf.extractSessionCookie(req)
	require.NoError(t, err)
	assert.Equal(t, "abc", c.Value)
}
