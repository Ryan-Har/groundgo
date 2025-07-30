package sessionstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type baseSessionStore struct {
	log           *slog.Logger
	tokenLength   int           // number of bytes used when generating tokens
	tokenDuration time.Duration // amount of time tokens are active for
	stopCh        chan struct{} // channel used to stop the cleanup of expired sessions
}

func NewBase(logger *slog.Logger, tokenLength int, tokenDuration time.Duration) *baseSessionStore {
	s := &baseSessionStore{
		log:           logger,
		tokenLength:   tokenLength,
		tokenDuration: tokenDuration,
		stopCh:        make(chan struct{}),
	}
	return s
}

func (s *baseSessionStore) ExpireCookie(c *http.Cookie, w http.ResponseWriter) {
	c.Expires = time.Unix(0, 0)
	http.SetCookie(w, c)
}

// createSession generates a models.Session struct based on the provided input
// A secure token is generated based on the token length stored in baseSessionStore
// Returns a wrapped error if generating the token fails
func (s *baseSessionStore) createSession(userID uuid.UUID, ipAddress *string, userAgent *string) (*models.Session, error) {
	now := time.Now()

	sesID, err := generateSecureToken(s.tokenLength)
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "failed to generate secure token", err)
	}

	return &models.Session{
		ID:        sesID,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.tokenDuration),
		IpAddress: ipAddress,
		UserAgent: userAgent,
	}, nil
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

// expirable is implemented by session stores that support
// automatic cleanup of expired sessions. It allows the
// baseSessionStore to initiate cleanup logic without knowing
// the specific details of how each store handles it.
type expirable interface {
	CleanupExpired(ctx context.Context) error
}

// StartCleanupWorker starts a goroutine that periodically cleans up expired sessions.
// The interval specifies how often the cleanup should run.
func (s *baseSessionStore) startCleanupWorker(exp expirable, interval time.Duration) {
	s.log.Debug("Starting session cleanup worker", "interval", interval)
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop() // Ensure the ticker is stopped when the goroutine exits
		for {
			select {
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(context.Background(), interval/2) // Give it a max half the interval
				err := exp.CleanupExpired(cleanupCtx)
				if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
					s.log.Error("failed to cleanup sessions", "err", err)
				}
				cancel() // Release resources associated with this context

			case <-s.stopCh:
				s.log.Info("Stopping session cleanup worker")
				return // Exit the goroutine
			}
		}
	}()
}
