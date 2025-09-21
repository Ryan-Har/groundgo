package builtins

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

// noopLogger returns a logger that discards all log messages.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// AuthStoreMock
type AuthStoreMock struct{ mock.Mock }

func (m *AuthStoreMock) ListAllUsers(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	users := args.Get(0)
	if users == nil {
		return nil, args.Error(1)
	}
	return users.([]*models.User), args.Error(1)
}

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

func (m *AuthStoreMock) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	args := m.Called(ctx, id, password)
	return args.Error(0)
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

func (m *AuthStoreMock) UpdateUserByID(ctx context.Context, args models.UpdateUserByIDParams) (*models.User, error) {
	mockArgs := m.Called(ctx, args)
	user := mockArgs.Get(0)
	if user == nil {
		return nil, mockArgs.Error(1)
	}
	return user.(*models.User), mockArgs.Error(1)
}

func (m *AuthStoreMock) HardDeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *AuthStoreMock) SoftDeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *AuthStoreMock) RestoreUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
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

func (m *TokenStoreMock) RevokeAccessToken(ctx context.Context, token *tokenstore.AccessToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *TokenStoreMock) ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error) {
	args := m.Called(ctx, tokenStr)
	accessToken := args.Get(0)
	if accessToken == nil {
		return nil, args.Error(1)
	}
	return accessToken.(*tokenstore.AccessToken), args.Error(1)
}

// CookieStoreMock
type CookieStoreMock struct{ mock.Mock }

func (m *CookieStoreMock) ClearRefreshTokenCookie(w http.ResponseWriter) error {
	args := m.Called(w)
	return args.Error(0)
}

func (m *CookieStoreMock) SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func (m *CookieStoreMock) SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func NewHandlerfromMocks() (*Handler,
	*AuthStoreMock,
	*SessionStoreMock,
	*TokenStoreMock,
	*CookieStoreMock) {

	auth := &AuthStoreMock{}
	session := &SessionStoreMock{}
	token := &TokenStoreMock{}
	cookie := &CookieStoreMock{}

	h := newHandler(noopLogger(), auth, session, token, cookie, "", "")
	return h, auth, session, token, cookie
}
