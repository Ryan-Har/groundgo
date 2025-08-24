package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/database"
	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type Store struct {
	db      *sql.DB
	log     *slog.Logger
	Auth    Authstore
	Session Sessionstore
	Token   Tokenstore
	dbType  DBType
}

type DBType string

const (
	DBTypeSQLite   DBType = "sqlite"
	DBTypePostgres DBType = "postgres"
)

// New initializes and returns a Store struct with the appropriate
// subcomponents (e.g., Auth, Session, Token) based on the provided configuration.
// It also runs the database migrations required for the stores.
//
// The dbType parameter determines the type of database backend used for storage,
// and sessionInMemory controls whether session storage is in-memory or not.
//
// Params:
//   - db: a live database connection
//   - dbType: the type of database (e.g., SQLite, Postgres) used to determine
//     how to initialize subcomponents like Auth
//   - logger: a slog.Logger pointer instance used for logging
//   - sessionInMemory: if true, an in-memory session store is initialized
//
// Example:
//
//	svc := New(db, DBTypeSQLite, logger, true)
func New(db *sql.DB, dbType DBType, log *slog.Logger, sessionInMemory bool) (*Store, error) {
	s := &Store{
		db:     db,
		log:    log,
		dbType: dbType,
	}

	switch dbType {
	case DBTypeSQLite:
		s.Auth = authstore.NewWithSqliteStore(s.db, s.log)
		if sessionInMemory {
			s.Session = sessionstore.NewInMemory(log)
		} else {
			s.Session = sessionstore.NewSqlite(log, db)
		}
		s.Token = tokenstore.NewSqlite(log, "tempSecureSigningSecret", time.Minute*15, db)
	}

	if err := s.runMigrations(); err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "unable to run migrations", err)
	}

	return s, nil
}

func (s *Store) runMigrations() error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "ran database migrations", "dbType", s.dbType)()
	switch s.dbType {
	case DBTypeSQLite:
		return database.RunSqliteMigrations(s.db)
	default:
		return errors.New("unknown database type")
	}
}

// Sessionstore manages session lifecycle and storage.
// It supports stateless and stateful session management depending on the backend.
type Sessionstore interface {

	// Create generates and stores a new session, returning the new session model.
	Create(ctx context.Context, userID uuid.UUID) (*models.Session, error)

	// Get retrieves a session by its ID.
	// Expired sessions should return an error or nil.
	Get(ctx context.Context, sessionID string) (*models.Session, error)

	// Delete removes a session by ID.
	Delete(ctx context.Context, sessionID string) error

	// Renew extends the expiration time of an existing session.
	Renew(ctx context.Context, sessionID string) (*models.Session, error)

	// DeleteUserSessions removes all sessions for the given user.
	// Useful for logout-all or security workflows.
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// CleanupExpiredSessions deletes expired sessions.
	// For in-memory stores, this is critical to avoid memory leaks.
	CleanupExpired(ctx context.Context) error

	// ExpireCookie invalidates a session cookie in the client response.
	// Should be used during logout or session invalidation.
	ExpireCookie(c *http.Cookie, w http.ResponseWriter)
}

// Tokenstore defines the behavior for issuing, validating, and refreshing tokens.
type Tokenstore interface {
	// IssueTokenPair generates a new access and refresh token pair for the user.
	IssueTokenPair(ctx context.Context, user *models.User) (*tokenstore.TokenPair, error)

	// RotateRefreshToken validates an old refresh token and issues a new token pair.
	// It handles the entire rotation logic: validate, delete old, create new.
	RotateRefreshToken(ctx context.Context, refreshTokenStr string) (*tokenstore.TokenPair, error)

	// ParseAccessToken validates and parses a JWT string, returning the claims if valid.
	// It does not check revocation status.
	ParseAccessToken(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error)

	// RevokeAccessToken permanently invalidates a given access token payload.
	// This adds the token's JTI to your `revoked_tokens` table.
	RevokeAccessToken(ctx context.Context, token *tokenstore.AccessToken) error

	// IsAccessTokenRevoked checks if the given access token has been explicitly revoked.
	IsAccessTokenRevoked(ctx context.Context, tokenPayload *tokenstore.AccessToken) (bool, error)

	// ParseAccessTokenAndValidate is a convenience method that both parses access token
	// And Checks if the token is revoked, providing an error if it is not a valid token.
	ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error)
}

// Authstore provides an abstract interface to manage user authentication and account records.
// It is storage-agnostic and supports common operations like creation, lookup, and account updates.
type Authstore interface {

	// CheckEmailExists returns true if a user with the given email exists in the store.
	CheckEmailExists(ctx context.Context, email string) (bool, error)

	// CreateUser creates a new user record using the provided parameters.
	// Returns the created user or a detailed error on failure.
	CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error)

	// GetUserByEmail retrieves a user by their email address.
	// Returns (nil, nil) if not found.
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	// GetUserByID fetches a user by their UUID.
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetUserByOAuth finds a user using OAuth provider and ID details.
	GetUserByOAuth(ctx context.Context, args models.UserOAuthParams) (*models.User, error)

	// ListAllUsers returns all users in the system.
	// Skips users that cannot be parsed and collects transformation errors.
	ListAllUsers(ctx context.Context) ([]*models.User, error)

	// ListUsersPaginatedWithRoleFilter retrieves a paginated list of users from the database,
	// optionally filtering by role. It also returns pagination metadata.
	// If transformation errors occur, partial results are returned with joined errors.
	ListUsersPaginatedWithRoleFilter(ctx context.Context, args models.GetPaginatedUsersParams) ([]*models.User, models.PaginationMeta, error)

	// SoftDeleteUser marks a user as inactive (without deleting their data).
	SoftDeleteUser(ctx context.Context, id uuid.UUID) error

	// RestoreUser reactivates a previously soft-deleted user.
	RestoreUser(ctx context.Context, id uuid.UUID) error

	// HardDeleteUser permanently removes a user record.
	HardDeleteUser(ctx context.Context, id uuid.UUID) error

	// UpdateUserRole changes a user’s role.
	// Also updates the root claim ("/") to reflect the new role.
	UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) error

	// UpdateUserClaims replaces a user's claims.
	// Ensures consistency between claims and role, especially the root ("/") claim.
	UpdateUserClaims(ctx context.Context, id uuid.UUID, claims models.Claims) error

	// UpdateUserPassword securely hashes and stores a new password for the user.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error

	// UpdateUserByID handles updating of a single user
	UpdateUserByID(ctx context.Context, args models.UpdateUserByIDParams) (*models.User, error)
}
