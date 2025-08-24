package sessionstore

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
)

// cleanup interval represents the time between checks for cleaning up the expired sessions
var cleanupInterval time.Duration = time.Minute * 10

func NewInMemory(logger *slog.Logger) *inMemorySessionStore {
	s := &inMemorySessionStore{
		baseSessionStore: NewBase(logger, 32, time.Minute*30),
		sessions:         make(map[string]*models.Session),
		mutex:            new(sync.Mutex),
		log:              logger,
	}

	s.startCleanupWorker(s, cleanupInterval)
	return s
}

func NewSqlite(logger *slog.Logger, db *sql.DB) *sqliteSessionStore {
	s := &sqliteSessionStore{
		baseSessionStore: NewBase(logger, 32, time.Minute*30),
		db:               db,
		queries:          *sqliteDB.New(db),
		log:              logger,
	}

	s.startCleanupWorker(s, cleanupInterval)
	return s
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
