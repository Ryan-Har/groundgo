package authstore

import (
	"context"
	"database/sql"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

func NewWithSqliteStore(db *sql.DB, logger logr.Logger) *sqliteAuthStore {
	return &sqliteAuthStore{
		db:      db,
		queries: *sqliteDB.New(db),
		log:     logger,
	}
}

// Store defines a unified interface for interacting with the user authentication datastore.
// It abstracts storage-specific implementations (e.g., SQLite, Postgres) behind consistent,
// well-documented operations used by services.
//
// All methods must return meaningful error types as defined in the models package,
// including ValidationError, TransformationError, and DatabaseError.
//
// The returned models must be portable and backend-agnostic (i.e., not tied to any backend schema).
type Store interface {

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
