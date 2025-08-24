package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// ---------- fakes for dependencies (no external mocking lib required) ----------
//

type fakeSessionStore struct {
	getFn    func(ctx context.Context, id string) (*models.Session, error)
	createFn func(ctx context.Context, uid uuid.UUID) (*models.Session, error)
	expireFn func(cookie *http.Cookie, w http.ResponseWriter)
}

func (f *fakeSessionStore) Get(ctx context.Context, id string) (*models.Session, error) {
	return f.getFn(ctx, id)
}
func (f *fakeSessionStore) Create(ctx context.Context, uid uuid.UUID) (*models.Session, error) {
	return f.createFn(ctx, uid)
}
func (f *fakeSessionStore) ExpireCookie(cookie *http.Cookie, w http.ResponseWriter) {
	if f.expireFn != nil {
		f.expireFn(cookie, w)
	}
}

type fakeAuth struct {
	getUserFn func(ctx context.Context, id uuid.UUID) (*models.User, error)
}

func (f *fakeAuth) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return f.getUserFn(ctx, id)
}

type fakeToken struct {
	parseFn func(ctx context.Context, token string) (*tokenstore.AccessToken, error)
}

func (f *fakeToken) ParseAccessTokenAndValidate(ctx context.Context, token string) (*tokenstore.AccessToken, error) {
	return f.parseFn(ctx, token)
}

//
// ---------- helpers ----------
//

func newBaseEnforcer() *Enforcer {
	return &Enforcer{
		session: &fakeSessionStore{
			getFn: func(ctx context.Context, id string) (*models.Session, error) {
				// default: guest session exists
				return &models.Session{
					ID:        id,
					UserID:    uuid.Nil,
					ExpiresAt: time.Now().Add(30 * time.Minute),
				}, nil
			},
			createFn: func(ctx context.Context, uid uuid.UUID) (*models.Session, error) {
				return &models.Session{
					ID:        "created-session",
					UserID:    uid,
					ExpiresAt: time.Now().Add(30 * time.Minute),
				}, nil
			},
			expireFn: func(cookie *http.Cookie, w http.ResponseWriter) {},
		},
		auth: &fakeAuth{
			getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
				return &models.User{
					ID:       id,
					IsActive: true,
					// keep simple baseline claims
					Claims: map[string]models.Role{"/": models.RoleUser},
				}, nil
			},
		},
		token: &fakeToken{
			parseFn: func(ctx context.Context, token string) (*tokenstore.AccessToken, error) {
				return nil, errors.New("invalid") // default: invalid so JWT path is off unless overridden
			},
		},
		log: NoopLogger(),
	}
}

func nextHandlerCaptureUserAndJWT(t *testing.T, gotUser **models.User, gotJWT *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(UserContextKey).(*models.User)
		require.True(t, ok, "user missing from context")
		*gotUser = user

		if s, ok := r.Context().Value(JWTContextKey).(string); ok {
			*gotJWT = s
		}
		w.WriteHeader(http.StatusOK)
	})
}

//
// ---------- tests for helpers ----------
//

func Test_extractBearerToken(t *testing.T) {
	e := newBaseEnforcer()

	// valid (case-insensitive "Bearer")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	tok, err := e.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "abc123", tok)

	req.Header.Set("Authorization", "bearer xyz")
	tok, err = e.extractBearerToken(req)
	require.NoError(t, err)
	assert.Equal(t, "xyz", tok)

	// invalid format
	req.Header.Set("Authorization", "Token abc")
	_, err = e.extractBearerToken(req)
	assert.Error(t, err)

	// empty token
	req.Header.Set("Authorization", "Bearer ")
	_, err = e.extractBearerToken(req)
	assert.Error(t, err)

	// missing header
	req.Header.Del("Authorization")
	_, err = e.extractBearerToken(req)
	assert.Error(t, err)
}

func Test_validateTokenAndGetUser(t *testing.T) {
	e := newBaseEnforcer()

	// success path
	uid := uuid.New()
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return &tokenstore.AccessToken{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: uid.String(),
				},
			}, nil
		},
	}
	e.auth = &fakeAuth{getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
		return &models.User{ID: id, IsActive: true}, nil
	}}
	user, err := e.validateTokenAndGetUser(context.Background(), "good")
	require.NoError(t, err)
	assert.Equal(t, uid, user.ID)

	// parse error
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return nil, errors.New("parse fail")
		},
	}
	_, err = e.validateTokenAndGetUser(context.Background(), "bad")
	assert.Error(t, err)

	// bad UUID in subject
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return &tokenstore.AccessToken{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "not-a-uuid",
				},
			}, nil
		},
	}
	_, err = e.validateTokenAndGetUser(context.Background(), "oops")
	assert.Error(t, err)

	// user lookup error
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return &tokenstore.AccessToken{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: uid.String(),
				},
			}, nil
		},
	}
	e.auth = &fakeAuth{getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
		return nil, errors.New("db fail")
	}}
	_, err = e.validateTokenAndGetUser(context.Background(), "good2")
	assert.Error(t, err)
}

func Test_getUserFromSession(t *testing.T) {
	e := newBaseEnforcer()

	// guest session -> returns guest user
	guest, err := e.getUserFromSession(context.Background(),
		&models.Session{UserID: uuid.Nil},
		nil,
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, guest.ID)
	assert.Equal(t, models.RoleGuest, guest.Claims["/"])

	// active user session
	uid := uuid.New()
	u, err := e.getUserFromSession(context.Background(),
		&models.Session{UserID: uid},
		nil,
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	require.NoError(t, err)
	assert.Equal(t, uid, u.ID)

	// unknown/inactive user -> cookie expired + redirect + error
	e.auth = &fakeAuth{
		getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{ID: id, IsActive: false}, nil
		},
	}
	w := httptest.NewRecorder()
	_, err = e.getUserFromSession(context.Background(),
		&models.Session{UserID: uuid.New()},
		&http.Cookie{Name: "session_token", Value: "abc"},
		w,
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	assert.Error(t, err)
	assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
}

func Test_handleSessionError(t *testing.T) {
	e := newBaseEnforcer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &http.Cookie{Name: "session_token", Value: "zzz"}

	// expired -> 303 See Other
	w := httptest.NewRecorder()
	e.handleSessionError(sessionstore.ErrSessionExpired, c, w, req)
	assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)

	// unknown -> 500 redirect
	w = httptest.NewRecorder()
	e.handleSessionError(errors.New("boom"), c, w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
}

func Test_getSessionFromCookie(t *testing.T) {
	e := newBaseEnforcer()

	// missing cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, cookie, err := e.getSessionFromCookie(req)
	assert.Nil(t, sess)
	assert.Nil(t, cookie)
	assert.Error(t, err)

	// with cookie -> returns session
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "sess1"})
	sess, cookie, err = e.getSessionFromCookie(req)
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.NotNil(t, cookie)
	assert.Equal(t, "sess1", cookie.Value)
}

func Test_isAPIRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	r.Header.Set("Accept", "application/json")
	assert.True(t, isAPIRequest(r))

	r = httptest.NewRequest(http.MethodGet, "/ui", nil)
	r.Header.Set("Accept", "text/html")
	assert.False(t, isAPIRequest(r))

	// must satisfy both
	r = httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	r.Header.Set("Accept", "text/html")
	assert.False(t, isAPIRequest(r))

	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Accept", "application/json")
	assert.False(t, isAPIRequest(r))
}

//
// ---------- tests for tryJWTAuth / trySessionAuth ----------
//

func Test_tryJWTAuth(t *testing.T) {
	e := newBaseEnforcer()
	uid := uuid.New()

	// valid JWT
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return &tokenstore.AccessToken{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: uid.String(),
				},
			}, nil
		},
	}
	e.auth = &fakeAuth{
		getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{ID: id, IsActive: true}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	u, tok, ok := e.tryJWTAuth(req)
	require.True(t, ok)
	assert.Equal(t, uid, u.ID)
	assert.Equal(t, "tok", tok)

	// invalid header -> false
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, ok = e.tryJWTAuth(req)
	assert.False(t, ok)

	// parse error -> false
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	e.token = &fakeToken{parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
		return nil, errors.New("nope")
	}}
	_, _, ok = e.tryJWTAuth(req)
	assert.False(t, ok)
}

func Test_trySessionAuth(t *testing.T) {
	e := newBaseEnforcer()

	// valid guest session (cookie present)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "s1"})
	w := httptest.NewRecorder()
	u, ok := e.trySessionAuth(req, w)
	require.True(t, ok)
	require.NotNil(t, u)
	assert.Equal(t, uuid.Nil, u.ID) // guest

	// expired session -> handleSessionError + false
	e.session = &fakeSessionStore{
		getFn: func(ctx context.Context, id string) (*models.Session, error) {
			return nil, sessionstore.ErrSessionExpired
		},
		createFn: func(ctx context.Context, uid uuid.UUID) (*models.Session, error) { return nil, errors.New("n/a") },
		expireFn: func(c *http.Cookie, w http.ResponseWriter) {},
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "expired"})
	w = httptest.NewRecorder()
	_, ok = e.trySessionAuth(req, w)
	assert.False(t, ok)
	assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
}

//
// ---------- tests for AuthenticationMiddleware ----------
//

func Test_AuthenticationMiddleware_JWTPath(t *testing.T) {
	e := newBaseEnforcer()
	uid := uuid.New()

	// make JWT valid
	e.token = &fakeToken{
		parseFn: func(ctx context.Context, s string) (*tokenstore.AccessToken, error) {
			return &tokenstore.AccessToken{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: uid.String(),
				},
			}, nil
		},
	}
	e.auth = &fakeAuth{
		getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
			return &models.User{ID: id, IsActive: true}, nil
		},
	}

	var gotUser *models.User
	var gotJWT string
	h := e.AuthenticationMiddleware(nextHandlerCaptureUserAndJWT(t, &gotUser, &gotJWT))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc.jwt")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, gotUser)
	assert.Equal(t, uid, gotUser.ID)
	assert.Equal(t, "abc.jwt", gotJWT)
}

func Test_AuthenticationMiddleware_SessionPath(t *testing.T) {
	e := newBaseEnforcer()

	// session with real user (not guest)
	userID := uuid.New()
	e.session = &fakeSessionStore{
		getFn: func(ctx context.Context, id string) (*models.Session, error) {
			return &models.Session{ID: id, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		createFn: func(ctx context.Context, uid uuid.UUID) (*models.Session, error) {
			return &models.Session{ID: "new", UserID: uid, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		expireFn: func(c *http.Cookie, w http.ResponseWriter) {},
	}
	e.auth = &fakeAuth{getUserFn: func(ctx context.Context, id uuid.UUID) (*models.User, error) {
		return &models.User{ID: id, IsActive: true}, nil
	}}

	var gotUser *models.User
	var gotJWT string
	h := e.AuthenticationMiddleware(nextHandlerCaptureUserAndJWT(t, &gotUser, &gotJWT))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "sess-123"})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, gotUser)
	assert.Equal(t, userID, gotUser.ID)
	assert.Equal(t, "", gotJWT) // no JWT on session path
}

func Test_AuthenticationMiddleware_FallbackGuest_SetsCookie(t *testing.T) {
	e := newBaseEnforcer()

	var gotUser *models.User
	var gotJWT string
	h := e.AuthenticationMiddleware(nextHandlerCaptureUserAndJWT(t, &gotUser, &gotJWT))

	// no JWT, no cookie -> createGuestSession
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, gotUser)
	assert.Equal(t, uuid.Nil, gotUser.ID)

	// should set a session_token cookie
	setCookie := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_token" && c.Value != "" {
			setCookie = true
			break
		}
	}
	assert.True(t, setCookie, "expected session_token cookie to be set")
}

func Test_AuthenticationMiddleware_FallbackGuest_ErrorBranches(t *testing.T) {
	// make Create fail so guest creation errors
	e := newBaseEnforcer()
	e.session = &fakeSessionStore{
		getFn: func(ctx context.Context, id string) (*models.Session, error) { return nil, errors.New("no session") },
		createFn: func(ctx context.Context, uid uuid.UUID) (*models.Session, error) {
			return nil, errors.New("create fail")
		},
		expireFn: func(c *http.Cookie, w http.ResponseWriter) {},
	}

	// Browser request -> http.Error 500
	req := httptest.NewRequest(http.MethodGet, "/web", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	e.AuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

	// API request -> api.ReturnError path (status should be a failure; assert non-200)
	req = httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	e.AuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, req)
	assert.True(t, w.Code >= 400, "expected an error status code for API path")
}

//
// ---------- tests for AuthorizationMiddleware & responses ----------
//

func Test_AuthorizationMiddleware_AllowsAndDenies(t *testing.T) {
	e := newBaseEnforcer()

	// allowed: admin at /admin
	admin := &models.User{
		ID:     uuid.New(),
		Claims: map[string]models.Role{"/admin": models.RoleAdmin},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = req.WithContext(context.WithValue(req.Context(), UserContextKey, admin))
	w := httptest.NewRecorder()
	e.AuthorizationMiddleware("/admin", models.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// denied: user at /admin
	usr := &models.User{
		ID:     uuid.New(),
		Claims: map[string]models.Role{"/admin": models.RoleUser},
	}
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = req.WithContext(context.WithValue(req.Context(), UserContextKey, usr))
	w = httptest.NewRecorder()
	e.AuthorizationMiddleware("/admin", models.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, req)
	// browser branch returns 403 (Forbidden text)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// missing user in context
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	w = httptest.NewRecorder()
	e.AuthorizationMiddleware("/admin", models.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func Test_responders_nonAPI(t *testing.T) {
	e := newBaseEnforcer()

	// respondForbidden (browser)
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	e.respondForbidden(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// respondMethodNotAllowed (browser)
	req = httptest.NewRequest(http.MethodPost, "/page", nil)
	req.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	e.respondMethodNotAllowed(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
