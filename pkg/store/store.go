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

type Sessionstore interface {
	// CreateSession generates a new session, stores it, and returns the session ID.
	Create(ctx context.Context, userID uuid.UUID) (*models.Session, error)

	// GetSession retrieves a session by its ID.
	// It should also handle session expiration.
	Get(ctx context.Context, sessionID string) (*models.Session, error)

	// DeleteSession removes a session by its ID.
	Delete(ctx context.Context, sessionID string) error

	// RenewSession updates the expiry of an existing session without changing its data.
	// This is commonly used to extend the session lifetime on activity.
	Renew(ctx context.Context, sessionID string) (*models.Session, error)

	// DeleteUserSessions deletes all sessions associated with a specific user ID.
	// Useful when a user changes password, logs out from all devices, or is deleted.
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// CleanupExpiredSessions removes all expired sessions from the store.
	// This is crucial for in-memory stores to prevent memory leaks and should
	// ideally be run periodically (e.g., as a goroutine).
	CleanupExpired(ctx context.Context) error

	//base methods, for various functions required by the store
	ExpireCookie(c *http.Cookie, w http.ResponseWriter)
}

type Tokenstore interface {
	// Generate a new JWT for a user
	IssueToken(user *models.User) (string, error)

	// ParseToken validates and parses a JWT string, returning the tokenPayload if valid. Does not check if it is revoked.
	ParseToken(ctx context.Context, tokenStr string) (*tokenstore.TokenPayload, error)

	// Revoke a token before expiry
	RevokeToken(ctx context.Context, token *tokenstore.TokenPayload) error

	// Check if a token payload has been revoked
	IsRevoked(ctx context.Context, tokenPayload *tokenstore.TokenPayload) (bool, error)

	// Refresh an expiring token
	RefreshTokenStr(ctx context.Context, oldTokenStr string) (string, error)
}

// Authstore defines a unified interface for interacting with the user authentication datastore.
// It abstracts storage-specific implementations (e.g., SQLite, Postgres) behind consistent,
// well-documented operations used by services.
//
// All methods must return meaningful error types as defined in the models package,
// including ValidationError, TransformationError, and DatabaseError.
//
// The returned models must be portable and backend-agnostic (i.e., not tied to any backend schema).
type Authstore interface {

	// CheckEmailExists returns true if a user with the specified email exists in the datastore.
	CheckEmailExists(ctx context.Context, email string) (bool, error)

	// CreateUser inserts a new user into the datastore using the provided parameters.
	// Returns a pointer to the created user, or a DatabaseError if insertion fails.
	CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error)

	// GetUserByEmail retrieves a user by email.
	// If no user is found, returns (nil, nil). Otherwise returns a pointer to the user.
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	// GetUserByID retrieves a user by their UUID.
	// Returns a DatabaseError if the query fails.
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetUserByOAuth looks up a user by their OAuth provider and ID.
	// Empty parameters may be treated as nil depending on the backend.
	GetUserByOAuth(ctx context.Context, args models.UserOAuthParams) (*models.User, error)

	// ListAllUsers returns all users in the datastore.
	// If some users fail to transform from raw DB format to model format,
	// those users are skipped and transformation errors are returned via errors.Join.
	ListAllUsers(ctx context.Context) ([]*models.User, error)

	// SoftDeleteUser marks a user as inactive (IsActive = false) without deleting data.
	SoftDeleteUser(ctx context.Context, id uuid.UUID) error

	// RestoreUser reactivates a soft-deleted user (IsActive = true).
	RestoreUser(ctx context.Context, id uuid.UUID) error

	// HardDeleteUser permanently removes a user's record from the datastore.
	HardDeleteUser(ctx context.Context, id uuid.UUID) error

	// UpdateUserRole sets the user’s role to the specified value.
	// This method must also synchronize the root claim ("/") to match the new role.
	UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) error

	// UpdateUserClaims replaces the user’s claims with the provided claims map.
	// This method must also ensure that the root claim ("/") is updated to match the user's existing role if not specified.
	// It updates the role too if the root claim provided has a different role to what exists currently.
	UpdateUserClaims(ctx context.Context, id uuid.UUID, claims models.Claims) error

	// UpdateUserPassword hashes and stores the new password for the specified user.
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error
}
