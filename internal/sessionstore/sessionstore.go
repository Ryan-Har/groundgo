package sessionstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

// Session represents the data stored for a single user session.
type Session struct {
	ID        string     // Unique identifier for the session (e.g., UUID)
	UserID    *uuid.UUID // ID of the user associated with this session, optional
	ExpiresAt time.Time  // When the session becomes invalid
	CreatedAt time.Time  // When the session was created
}

func NewInMemory(logger logr.Logger) *inMemorySessionStore {
	s := &inMemorySessionStore{
		baseSessionStore: NewBase(logger),
		sessions:         make(map[string]*Session),
		mutex:            new(sync.Mutex),
		log:              logger,
		tokenLength:      32,
		tokenDuration:    time.Minute * 30,
		stopCh:           make(chan struct{}),
	}

	s.startCleanupWorker(time.Second * 10)
	return s
}

// Store defines the interface for a session store.
type Store interface {
	// CreateSession generates a new session, stores it, and returns the session ID.
	Create(ctx context.Context, userID *uuid.UUID) (*Session, error)

	// GetSession retrieves a session by its ID.
	// It should also handle session expiration.
	Get(ctx context.Context, sessionID string) (*Session, error)

	// DeleteSession removes a session by its ID.
	Delete(ctx context.Context, sessionID string) error

	// RenewSession updates the expiry of an existing session without changing its data.
	// This is commonly used to extend the session lifetime on activity.
	Renew(ctx context.Context, sessionID string) error

	// DeleteUserSessions deletes all sessions associated with a specific user ID.
	// Useful when a user changes password, logs out from all devices, or is deleted.
	DeleteUser(ctx context.Context, userID *uuid.UUID) error

	// CleanupExpiredSessions removes all expired sessions from the store.
	// This is crucial for in-memory stores to prevent memory leaks and should
	// ideally be run periodically (e.g., as a goroutine).
	CleanupExpired(ctx context.Context) error

	//base methods, for various functions required by the store
	ExpireCookie(c *http.Cookie, w http.ResponseWriter)
}

// helper to generate secure token of a given length
func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var ErrSessionExpired = &SessionExpiredError{}

// errors
type SessionExpiredError struct {
	ID string
}

func (e *SessionExpiredError) Error() string {
	return fmt.Sprintf("session with ID '%s' has expired", e.ID)
}

func (e *SessionExpiredError) Is(target error) bool {
	_, ok := target.(*SessionExpiredError)
	return ok
}
