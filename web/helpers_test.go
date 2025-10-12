package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

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

// CookieStoreMock
type CookieStoreMock struct{ mock.Mock }

func (m *CookieStoreMock) SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	args := m.Called(w, value, customExpires)
	return args.Error(0)
}

func NewHandlerfromMocks() (*Handler,
	*AuthStoreMock,
	*SessionStoreMock,
	*CookieStoreMock) {

	auth := &AuthStoreMock{}
	session := &SessionStoreMock{}
	cookie := &CookieStoreMock{}

	h := New(noopLogger(), auth, session, cookie, "")
	return h, auth, session, cookie
}
