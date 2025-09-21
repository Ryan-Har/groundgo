package builtins

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type Handler struct {
	auth         auth
	session      session
	token        token
	cookie       cookie
	log          *slog.Logger
	apiBaseRoute string
	baseRoute    string
}

func newHandler(logger *slog.Logger, auth auth, session session, token token, cookie cookie, baseRoute, apiBaseRoute string) *Handler {
	return &Handler{
		auth:         auth,
		session:      session,
		token:        token,
		cookie:       cookie,
		log:          logger,
		baseRoute:    baseRoute,
		apiBaseRoute: apiBaseRoute,
	}
}

type auth interface {
	ListAllUsers(ctx context.Context) ([]*models.User, error)
	CheckEmailExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error
	ListUsersPaginatedWithRoleFilter(ctx context.Context, args models.GetPaginatedUsersParams) ([]*models.User, models.PaginationMeta, error)
	UpdateUserByID(ctx context.Context, args models.UpdateUserByIDParams) (*models.User, error)
	HardDeleteUser(ctx context.Context, id uuid.UUID) error
	SoftDeleteUser(ctx context.Context, id uuid.UUID) error
	RestoreUser(ctx context.Context, id uuid.UUID) error
}

type session interface {
	Create(ctx context.Context, userID uuid.UUID) (*models.Session, error)
}

type token interface {
	IssueTokenPair(ctx context.Context, user *models.User) (*tokenstore.TokenPair, error)
	RotateRefreshToken(ctx context.Context, refreshTokenStr string) (*tokenstore.TokenPair, error)
	RevokeAccessToken(ctx context.Context, token *tokenstore.AccessToken) error
	ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error)
}

type cookie interface {
	ClearRefreshTokenCookie(w http.ResponseWriter) error
	SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
	SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
}
