package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/database"
	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/cookiestore"
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
	Cookie  Cookiestore
	dbType  DBType
}

type DBType string

const (
	DBTypeSQLite   DBType = "sqlite"
	DBTypePostgres DBType = "postgres"
)

// New initializes and returns a Store struct with the appropriate
// subcomponents (e.g., Auth, Session, Token, Cookie) based on the provided configuration.
// It also runs the database migrations required for the stores.
func New(cfg *StoreConfig) (*Store, error) {
	if cfg == nil {
		return nil, errors.New("provided config cannot be nil")
	}
	if err := cfg.validateAndSetDefaults(); err != nil {
		return nil, err
	}

	s := &Store{
		db:     cfg.DB,
		log:    cfg.Logger,
		dbType: cfg.DBType,
	}

	switch cfg.DBType {
	case DBTypeSQLite:
		s.Auth = authstore.NewWithSqliteStore(s.db, s.log)
		if cfg.SessionStoreInMemory {
			s.Session = sessionstore.NewInMemory(s.log)
		} else {
			s.Session = sessionstore.NewSqlite(s.log, s.db)
		}
		s.Token = tokenstore.NewSqlite(s.log, cfg.JWTSigningSecret, cfg.TokenDuration, s.db)
	case DBTypePostgres:
		return nil, errors.New("postgres not yet supported")
	default:
		return nil, fmt.Errorf("unsupported DBType: %s", cfg.DBType)
	}

	if cfg.InsecureMode {
		s.Cookie = cookiestore.NewManagerWithInsecureDefaults(s.log)
	} else {
		s.Cookie = cookiestore.NewManagerWithDefaults(s.log)
	}

	// override durations with provided durations
	cookieDurations := cookiestore.NewDurationConfig(
		cfg.CookiestoreGuestSessionDuration,
		cfg.RefreshTokenDuration,
		cfg.SessionDuration,
		cfg.CookiestoreGenericCookieDuration,
	)
	s.Cookie.UpdateDurations(cookieDurations)

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

type Cookiestore interface {
	// UpdateDurations updates the duration configuration at runtime
	UpdateDurations(durations cookiestore.DurationConfig)
	// GetConfig returns a copy of the current configuration
	GetConfig() cookiestore.CookieConfig

	SetCookie(w http.ResponseWriter, opts cookiestore.CookieOptions) error
	SetGuestCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
	SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
	SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
	SetGenericCookie(w http.ResponseWriter, name, value, path string, customExpires *time.Time) error
	ClearCookie(w http.ResponseWriter, name, path string) error
	ClearGuestCookie(w http.ResponseWriter) error
	ClearRefreshTokenCookie(w http.ResponseWriter) error
	ClearUserSessionCookie(w http.ResponseWriter) error
	GetCookie(r *http.Request, name string) (string, error)
	GetGuestCookie(r *http.Request) (string, error)
	GetRefreshTokenCookie(r *http.Request) (string, error)
	GetUserSessionCookie(r *http.Request) (string, error)
}

type StoreConfig struct {
	// generic store configuration data
	Logger       *slog.Logger // logger to be injected into stores
	DB           *sql.DB
	DBType       DBType // DBType string enum
	InsecureMode bool   // determines if insecure mode is enabled (default false). Useful for development environments.

	// session store configuration
	TokenLength          int  // number of bytes used when generating tokens (default 32)
	SessionStoreInMemory bool // bool to flag if session store should be in memory (default false)

	// auth store configuration

	// token store configuration
	JWTSigningSecret string        // string used to sign JWT
	TokenDuration    time.Duration // length of time tokens are valid for (default 30 min)

	// cookie store configuration
	CookiestoreGuestSessionDuration  time.Duration // length of time a guest session cookie (default 24 hr)
	CookiestoreGenericCookieDuration time.Duration // length of time generic cookies are valid for (default 1 hr)

	// shared configuration options
	SessionDuration      time.Duration // length of time tokens are active (default 30 min)
	RefreshTokenDuration time.Duration // length of time refresh tokens are valid for (default 7 days)
}

func (c *StoreConfig) validateAndSetDefaults() error {
	// Required fields
	if c.Logger == nil {
		return errors.New("logger must be provided")
	}
	if c.DB == nil {
		return errors.New("DB must be provided")
	}
	if c.DBType == "" {
		return errors.New("DBType must be provided")
	}
	if c.JWTSigningSecret == "" {
		return errors.New("JWTSigningSecret must be provided")
	}

	// Set defaults for zero values
	if c.TokenLength == 0 {
		c.TokenLength = 32
	}
	// SessionStoreInMemory defaults to false, no action needed
	if c.TokenDuration == 0 {
		c.TokenDuration = 30 * time.Minute
	}
	if c.CookiestoreGuestSessionDuration == 0 {
		c.CookiestoreGuestSessionDuration = 24 * time.Hour
	}
	if c.CookiestoreGenericCookieDuration == 0 {
		c.CookiestoreGenericCookieDuration = 1 * time.Hour
	}
	if c.SessionDuration == 0 {
		c.SessionDuration = 30 * time.Minute
	}
	if c.RefreshTokenDuration == 0 {
		c.RefreshTokenDuration = 7 * 24 * time.Hour
	}

	return nil
}
