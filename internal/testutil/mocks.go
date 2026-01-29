package testutil

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/internal/cookiestore"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// noopLogger returns a logger that discards all log messages.
func NoopLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// AuthStoreMock
type AuthStoreMock struct{ mock.Mock }

func (m *AuthStoreMock) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *AuthStoreMock) CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error) {
	mockArgs := m.Called(ctx, args)
	user := mockArgs.Get(0)
	if user == nil {
		return nil, mockArgs.Error(1)
	}
	return user.(*models.User), mockArgs.Error(1)
}

func (m *AuthStoreMock) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

func (m *AuthStoreMock) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

func (m *AuthStoreMock) GetUserByOAuth(ctx context.Context, args models.UserOAuthParams) (*models.User, error) {
	mockArgs := m.Called(ctx, args)
	user := mockArgs.Get(0)
	if user == nil {
		return nil, mockArgs.Error(1)
	}
	return user.(*models.User), mockArgs.Error(1)
}

func (m *AuthStoreMock) ListAllUsers(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	users := args.Get(0)
	if users == nil {
		return nil, args.Error(1)
	}
	return users.([]*models.User), args.Error(1)
}

func (m *AuthStoreMock) ListUsersPaginatedWithRoleFilter(ctx context.Context, args models.GetPaginatedUsersParams) ([]*models.User, models.PaginationMeta, error) {
	mockArgs := m.Called(ctx, args)
	users := mockArgs.Get(0)
	meta := mockArgs.Get(1)

	var userSlice []*models.User
	var metaObj models.PaginationMeta

	if users != nil {
		userSlice = users.([]*models.User)
	}
	if meta != nil {
		metaObj = meta.(models.PaginationMeta)
	}

	return userSlice, metaObj, mockArgs.Error(2)
}

func (m *AuthStoreMock) SoftDeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *AuthStoreMock) RestoreUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *AuthStoreMock) HardDeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *AuthStoreMock) UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) error {
	args := m.Called(ctx, id, role)
	return args.Error(0)
}

func (m *AuthStoreMock) UpdateUserClaims(ctx context.Context, id uuid.UUID, claims models.Claims) error {
	args := m.Called(ctx, id, claims)
	return args.Error(0)
}

func (m *AuthStoreMock) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	args := m.Called(ctx, id, password)
	return args.Error(0)
}

func (m *AuthStoreMock) UpdateUserByID(ctx context.Context, args models.UpdateUserByIDParams) (*models.User, error) {
	mockArgs := m.Called(ctx, args)
	user := mockArgs.Get(0)
	if user == nil {
		return nil, mockArgs.Error(1)
	}
	return user.(*models.User), mockArgs.Error(1)
}

// SessionStoreMock
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

func (m *SessionStoreMock) Delete(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *SessionStoreMock) Renew(ctx context.Context, sessionID string) (*models.Session, error) {
	args := m.Called(ctx, sessionID)
	sess := args.Get(0)
	if sess == nil {
		return nil, args.Error(1)
	}
	return sess.(*models.Session), args.Error(1)
}

func (m *SessionStoreMock) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *SessionStoreMock) CleanupExpired(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// CookieStoreMock
type CookieStoreMock struct{ mock.Mock }

func (m *CookieStoreMock) UpdateDurations(durations cookiestore.DurationConfig) {
	m.Called(durations)
}

func (m *CookieStoreMock) GetConfig() cookiestore.CookieConfig {
	args := m.Called()
	return args.Get(0).(cookiestore.CookieConfig)
}

func (m *CookieStoreMock) SetCookie(w http.ResponseWriter, opts cookiestore.CookieOptions) error {
	args := m.Called(w, opts)
	return args.Error(0)
}

func (m *CookieStoreMock) SetGuestCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func (m *CookieStoreMock) SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func (m *CookieStoreMock) SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func (m *CookieStoreMock) SetGenericCookie(w http.ResponseWriter, name, value, path string, customExpires *time.Time) error {
	args := m.Called(w, name, value, path, customExpires)
	return args.Error(0)
}

func (m *CookieStoreMock) ClearCookie(w http.ResponseWriter, name, path string) error {
	args := m.Called(w, name, path)
	return args.Error(0)
}

func (m *CookieStoreMock) ClearGuestCookie(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func (m *CookieStoreMock) ClearRefreshTokenCookie(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func (m *CookieStoreMock) ClearUserSessionCookie(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func (m *CookieStoreMock) GetCookie(r *http.Request, name string) (string, error) {
	args := m.Called(r, name)
	return args.String(0), args.Error(1)
}

func (m *CookieStoreMock) GetGuestCookie(r *http.Request) (string, error) {
	args := m.Called(r)
	return args.String(0), args.Error(1)
}

func (m *CookieStoreMock) GetRefreshTokenCookie(r *http.Request) (string, error) {
	args := m.Called(r)
	return args.String(0), args.Error(1)
}

func (m *CookieStoreMock) GetUserSessionCookie(r *http.Request) (string, error) {
	args := m.Called(r)
	return args.String(0), args.Error(1)
}

// TokenStoreMock
type TokenStoreMock struct{ mock.Mock }

func (m *TokenStoreMock) IssueTokenPair(ctx context.Context, user *models.User) (*tokenstore.TokenPair, error) {
	args := m.Called(ctx, user)
	tokenPair := args.Get(0)
	if tokenPair == nil {
		return nil, args.Error(1)
	}
	return tokenPair.(*tokenstore.TokenPair), args.Error(1)
}

func (m *TokenStoreMock) RotateRefreshToken(ctx context.Context, refreshTokenStr string) (*tokenstore.TokenPair, error) {
	args := m.Called(ctx, refreshTokenStr)
	tokenPair := args.Get(0)
	if tokenPair == nil {
		return nil, args.Error(1)
	}
	return tokenPair.(*tokenstore.TokenPair), args.Error(1)
}

func (m *TokenStoreMock) ParseAccessToken(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error) {
	args := m.Called(ctx, tokenStr)
	accessToken := args.Get(0)
	if accessToken == nil {
		return nil, args.Error(1)
	}
	return accessToken.(*tokenstore.AccessToken), args.Error(1)
}

func (m *TokenStoreMock) RevokeAccessToken(ctx context.Context, token *tokenstore.AccessToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *TokenStoreMock) IsAccessTokenRevoked(ctx context.Context, tokenPayload *tokenstore.AccessToken) (bool, error) {
	args := m.Called(ctx, tokenPayload)
	return args.Bool(0), args.Error(1)
}

func (m *TokenStoreMock) ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error) {
	args := m.Called(ctx, tokenStr)
	accessToken := args.Get(0)
	if accessToken == nil {
		return nil, args.Error(1)
	}
	return accessToken.(*tokenstore.AccessToken), args.Error(1)
}

// ProcessorMock is a mock implementation of the Processor interface
type ProcessorMock struct {
	mock.Mock
}

func (m *ProcessorMock) ResolveUser(r *http.Request) (*models.User, error) {
	args := m.Called(r)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

func (m *ProcessorMock) AuthenticateRequest(r *http.Request) (*models.User, context.Context, error) {
	args := m.Called(r)
	user := args.Get(0)
	ctx := args.Get(1)
	if user == nil && ctx == nil {
		return nil, nil, args.Error(2)
	}

	var u *models.User
	if user != nil {
		u = user.(*models.User)
	}

	var c context.Context
	if ctx != nil {
		c = ctx.(context.Context)
	}

	return u, c, args.Error(2)
}

func (m *ProcessorMock) EnsureGuest(r *http.Request, w http.ResponseWriter) (*models.User, context.Context) {
	args := m.Called(r, w)
	user := args.Get(0)
	ctx := args.Get(1)

	var u *models.User
	if user != nil {
		u = user.(*models.User)
	}

	var c context.Context
	if ctx != nil {
		c = ctx.(context.Context)
	}

	return u, c
}
