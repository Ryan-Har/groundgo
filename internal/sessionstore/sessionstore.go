package sessionstore

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

func NewInMemory(logger *slog.Logger) *inMemorySessionStore {
	s := &inMemorySessionStore{
		baseSessionStore: NewBase(logger, 32, time.Minute*30),
		sessions:         make(map[string]*models.Session),
		mutex:            new(sync.Mutex),
		log:              logger,
	}

	s.startCleanupWorker(s, time.Second*10)
	return s
}

func NewSqlite(logger *slog.Logger, db *sql.DB) *sqliteSessionStore {
	s := &sqliteSessionStore{
		baseSessionStore: NewBase(logger, 32, time.Minute*30),
		db:               db,
		queries:          *sqliteDB.New(db),
		log:              logger,
	}

	s.startCleanupWorker(s, time.Second*10)
	return s
}

// Store defines the interface for a session store.
type Store interface {
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

var ErrSessionExpired = &SessionExpiredError{}

// errors
type SessionExpiredError struct {
	ID string
}

func newSessionExpiredError(id string) *SessionExpiredError {
	return &SessionExpiredError{
		ID: id,
	}
}

func (e *SessionExpiredError) Error() string {
	return fmt.Sprintf("session with ID '%s' has expired", e.ID)
}

func (e *SessionExpiredError) Is(target error) bool {
	_, ok := target.(*SessionExpiredError)
	return ok
}
