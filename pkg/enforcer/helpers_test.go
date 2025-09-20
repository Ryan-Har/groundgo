package enforcer

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// NoopLogger returns a logger that discards all log messages.
func NoopLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// AuthStore
type AuthStoreMock struct{ mock.Mock }

func (m *AuthStoreMock) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

// SessionStore
type SessionStoreMock struct{ mock.Mock }

func (m *SessionStoreMock) Create(ctx context.Context, userID uuid.UUID) (*models.Session, error) {
	args := m.Called(ctx, userID)
	sess := args.Get(0)
	if sess == nil {
		return nil, args.Error(1)
	}
	return sess.(*models.Session), args.Error(1)
}
func (m *SessionStoreMock) Get(ctx context.Context, sessionID string) (*models.Session, error) {
	args := m.Called(ctx, sessionID)
	sess := args.Get(0)
	if sess == nil {
		return nil, args.Error(1)
	}
	return sess.(*models.Session), args.Error(1)
}

// TokenStore
type TokenStoreMock struct{ mock.Mock }

func (m *TokenStoreMock) ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error) {
	args := m.Called(ctx, tokenStr)
	tok := args.Get(0)
	if tok == nil {
		return nil, args.Error(1)
	}
	return tok.(*tokenstore.AccessToken), args.Error(1)
}

// CookieStore
type CookieStoreMock struct{ mock.Mock }

func (m *CookieStoreMock) SetGuestCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}
func (m *CookieStoreMock) ClearUserSessionCookie(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func NewEnforcerFromMocks() (*Enforcer,
	*AuthStoreMock,
	*SessionStoreMock,
	*TokenStoreMock,
	*CookieStoreMock) {

	auth := &AuthStoreMock{}
	session := &SessionStoreMock{}
	token := &TokenStoreMock{}
	cookie := &CookieStoreMock{}

	cfg := &EnforcerConfig{
		Logger:             NoopLogger(),
		Router:             http.NewServeMux(),
		Auth:               auth,
		Session:            session,
		Token:              token,
		Cookie:             cookie,
		APIRequestDetector: defaultAPIDetector,
	}

	enf, _ := New(cfg)
	return enf, auth, session, token, cookie
}

// dummyHandler is a simple handler that writes a known value
func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot) // 418 I'm a teapot
	w.Write([]byte("teapot"))
}
