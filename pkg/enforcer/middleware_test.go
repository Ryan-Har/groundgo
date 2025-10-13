package enforcer

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
	enf, _, _, _, _ := newEnforcerFromMocks()

	// valid (case-insensitive "Bearer")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	tok, err := enf.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "abc123", tok)

	req.Header.Set("Authorization", "bearer xyz")
	tok, err = enf.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "xyz", tok)

	// invalid format
	req.Header.Set("Authorization", "Token abc")
	_, err = enf.extractBearerToken(req)
	assert.Error(t, err)

	// empty token
	req.Header.Set("Authorization", "Bearer ")
	_, err = enf.extractBearerToken(req)
	assert.Error(t, err)

	// missing header
	req.Header.Del("Authorization")
	_, err = enf.extractBearerToken(req)
	assert.Error(t, err)
}

func Test_validateTokenAndGetUser(t *testing.T) {
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
			enf, auth, _, token, _ := newEnforcerFromMocks()
			tc.setupMocks(auth, token)

			user, err := enf.validateTokenAndGetUser(context.Background(), tc.tokenString)

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

			auth.AssertExpectations(t)
			token.AssertExpectations(t)
		})
	}
}

func Test_getUserFromSession(t *testing.T) {
	cases := []struct {
		name           string
		session        *models.Session
		setupMocks     func(auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, uid uuid.UUID)
		expectedError  bool
		expectedRole   models.Role
		expectedStatus int
	}{
		{
			name:    "guest session returns guest user",
			session: &models.Session{UserID: uuid.Nil},
			setupMocks: func(auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, uid uuid.UUID) {
				// no mocks needed for guest
			},
			expectedError:  false,
			expectedRole:   models.RoleGuest,
			expectedStatus: http.StatusOK,
		},
		{
			name:    "active user session",
			session: &models.Session{UserID: uuid.New()},
			setupMocks: func(auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, uid uuid.UUID) {
				auth.On("GetUserByID", mock.Anything, uid).
					Return(&models.User{ID: uid, IsActive: true}, nil)
			},
			expectedError:  false,
			expectedRole:   "", // normal user has no forced role
			expectedStatus: http.StatusOK,
		},
		{
			name:    "inactive user causes redirect",
			session: &models.Session{UserID: uuid.New()},
			setupMocks: func(auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, uid uuid.UUID) {
				auth.On("GetUserByID", mock.Anything, uid).
					Return(&models.User{ID: uid, IsActive: false}, nil)
				cookie.On("ClearUserSessionCookie", mock.Anything).Return(nil)
			},
			expectedError:  true,
			expectedRole:   "",
			expectedStatus: http.StatusSeeOther,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, auth, _, _, cookie := newEnforcerFromMocks()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			uid := tc.session.UserID
			tc.setupMocks(auth, cookie, uid)

			user, err := enf.getUserFromSession(context.Background(), tc.session, w, r)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.expectedRole != "" {
				assert.Equal(t, tc.expectedRole, user.Claims["/"])
			}

			if tc.expectedStatus != http.StatusOK {
				assert.Equal(t, tc.expectedStatus, w.Result().StatusCode)
			}

			auth.AssertExpectations(t)
			cookie.AssertExpectations(t)
		})
	}
}

func Test_handleSessionError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "expired session returns 303 See Other",
			err:            sessionstore.ErrSessionExpired,
			expectedStatus: http.StatusSeeOther,
		},
		{
			name:           "unknown error returns 500",
			err:            errors.New("boom"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, _, _, _, cookie := newEnforcerFromMocks() // grab cookie mock
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			c := &http.Cookie{Name: "session_token", Value: "zzz"}
			w := httptest.NewRecorder()

			// configure mock so ClearUserSessionCookie won't panic
			cookie.On("ClearUserSessionCookie", mock.Anything).Return(nil).Maybe()

			enf.handleSessionError(tc.err, c, w, req)

			assert.Equal(t, tc.expectedStatus, w.Result().StatusCode)
			cookie.AssertExpectations(t)
		})
	}
}

func Test_getSessionFromCookie(t *testing.T) {
	cases := []struct {
		name          string
		setupRequest  func() *http.Request
		expectedError bool
		expectedValue string
	}{
		{
			name: "missing cookie",
			setupRequest: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			expectedError: true,
			expectedValue: "",
		},
		{
			name: "with cookie returns session",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "sess1"})
				return req
			},
			expectedError: false,
			expectedValue: "sess1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, _, sessionMock, _, _ := newEnforcerFromMocks()
			req := tc.setupRequest()

			// Only set up the mock if the test case actually has a cookie
			for _, c := range req.Cookies() {
				if c.Name == "session_token" {
					sessionMock.On("Get", mock.Anything, c.Value).
						Return(&models.Session{ID: c.Value, UserID: uuid.New()}, nil)
				}
			}

			sess, cookie, err := enf.getSessionFromCookie(req)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, sess)
				assert.Nil(t, cookie)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, sess)
				require.NotNil(t, cookie)
				assert.Equal(t, tc.expectedValue, cookie.Value)
			}

			sessionMock.AssertExpectations(t)
		})
	}

}

func Test_defaultAPIDetector(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "API path with JSON accept",
			path:     "/api/v1/x",
			headers:  map[string]string{"Accept": "application/json"},
			expected: true,
		},
		{
			name:     "regular web request",
			path:     "/ui",
			headers:  map[string]string{"Accept": "text/html"},
			expected: false,
		},
		{
			name:     "API path without JSON accept",
			path:     "/api/v1/x",
			headers:  map[string]string{"Accept": "text/html"},
			expected: true,
		},
		{
			name:     "JSON accept without API path",
			path:     "/x",
			headers:  map[string]string{"Accept": "application/json"},
			expected: true,
		},
		{
			name:     "JSON content type header",
			path:     "/some/endpoint",
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: true,
		},
		{
			name:     "v1 path",
			path:     "/v1/users",
			headers:  nil,
			expected: true,
		},
		{
			name:     "v2 path",
			path:     "/v2/users",
			headers:  nil,
			expected: true,
		},
		{
			name:     "non-API path with HTML accept",
			path:     "/some/web/page",
			headers:  map[string]string{"Accept": "text/html"},
			expected: false,
		},
		{
			name: "API path with both JSON accept and content type",
			path: "/api/v1/users",
			headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.expected, defaultAPIDetector(req))
		})
	}
}

func Test_tryJWTAuth(t *testing.T) {
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
		{
			name: "parse error",
			setupMocks: func(auth *testutil.AuthStoreMock, token *testutil.TokenStoreMock) {
				token.On("ParseAccessTokenAndValidate", mock.Anything, "bad").
					Return(nil, errors.New("nope"))
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer bad")
				return req
			},
			expectOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, authMock, _, tokenMock, _ := newEnforcerFromMocks()
			tc.setupMocks(authMock, tokenMock)

			u, tok, ok := enf.tryJWTAuth(tc.setupRequest())

			assert.Equal(t, tc.expectOK, ok)
			if ok {
				require.NotNil(t, u)
				assert.Equal(t, tc.expectUserID, u.ID)
				assert.Equal(t, tc.expectTokenStr, tok)
			}
		})
	}
}

func Test_trySessionAuth(t *testing.T) {
	guestID := uuid.Nil

	cases := []struct {
		name         string
		sessionID    string
		userID       uuid.UUID // the ID the session should return if valid
		setupMocks   func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, userID uuid.UUID)
		setupRequest func() *http.Request
		expectOK     bool
		expectStatus int
	}{
		{
			name:      "valid guest session",
			sessionID: "s1",
			userID:    guestID,
			setupMocks: func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, userID uuid.UUID) {
				session.On("Get", mock.Anything, "s1").
					Return(&models.Session{UserID: userID}, nil)
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "s1"})
				return req
			},
			expectOK:     true,
			expectStatus: http.StatusOK,
		},
		{
			name:      "expired session",
			sessionID: "expired",
			userID:    uuid.Nil, // won't be used
			setupMocks: func(session *testutil.SessionStoreMock, auth *testutil.AuthStoreMock, cookie *testutil.CookieStoreMock, userID uuid.UUID) {
				session.On("Get", mock.Anything, "expired").
					Return(nil, sessionstore.ErrSessionExpired)
				cookie.On("ClearUserSessionCookie", mock.Anything).
					Return(nil)
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "expired"})
				return req
			},
			expectOK:     false,
			expectStatus: http.StatusSeeOther,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, _, sessionMock, _, cookieMock := newEnforcerFromMocks()
			tc.setupMocks(sessionMock, nil, cookieMock, tc.userID)

			w := httptest.NewRecorder()
			u, ok := enf.trySessionAuth(tc.setupRequest(), w)

			assert.Equal(t, tc.expectOK, ok)
			assert.Equal(t, tc.expectStatus, w.Result().StatusCode)
			if ok {
				require.NotNil(t, u)
				assert.Equal(t, tc.userID, u.ID)
			}
		})
	}
}

func Test_responders_nonAPI(t *testing.T) {
	cases := []struct {
		name           string
		setupRequest   func() *http.Request
		responder      func(*Enforcer, http.ResponseWriter, *http.Request)
		expectedStatus int
	}{
		{
			name: "respondForbidden (browser)",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/page", nil)
				req.Header.Set("Accept", "text/html")
				return req
			},
			responder:      func(e *Enforcer, w http.ResponseWriter, r *http.Request) { e.respondForbidden(w, r) },
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "respondMethodNotAllowed (browser)",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/page", nil)
				req.Header.Set("Accept", "text/html")
				return req
			},
			responder:      func(e *Enforcer, w http.ResponseWriter, r *http.Request) { e.respondMethodNotAllowed(w, r) },
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _, _, _ := newEnforcerFromMocks()
			req := tc.setupRequest()
			w := httptest.NewRecorder()

			tc.responder(e, w, req)

			assert.Equal(t, tc.expectedStatus, w.Result().StatusCode)
		})
	}
}
