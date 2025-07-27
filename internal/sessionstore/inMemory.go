package sessionstore

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

type inMemorySessionStore struct {
	*baseSessionStore
	sessions      map[string]*Session // sessionID -> userID
	mutex         *sync.Mutex
	log           *slog.Logger
	tokenLength   int           // number of bytes used when generating tokens
	tokenDuration time.Duration // amound of time tokens are active for
	stopCh        chan struct{} // channel used to stop the cleanup of expired sessions
}

func (s *inMemorySessionStore) Create(ctx context.Context, userID *uuid.UUID) (*Session, error) {
	s.log.Debug("creating session")

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session creation", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sesID, err := generateSecureToken(s.tokenLength)
	if err != nil {
		return nil, err
	}

	session := s.createSession(sesID, userID, s.tokenDuration)
	s.sessions[sesID] = session

	s.log.Debug("created session", "session_id", session.ID, "user_id", session.UserID.String())
	return session, nil
}

func (s *inMemorySessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	s.log.Debug("getting session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session get", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sess, ok := s.sessions[sessionID]
	if !ok || sess.ExpiresAt.Before(time.Now()) {
		return nil, &SessionExpiredError{ID: sessionID}
	}

	return sess, nil
}

func (s *inMemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	s.log.Debug("deleting session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	delete(s.sessions, sessionID)

	s.log.Debug("deleted session", "session_id", sessionID)
	return nil
}

func (s *inMemorySessionStore) Renew(ctx context.Context, sessionID string) error {
	s.log.Debug("renewing session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session renew", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	sess, ok := s.sessions[sessionID]
	if !ok || sess.ExpiresAt.Before(time.Now()) {
		return &SessionExpiredError{ID: sessionID}
	}

	sess.ExpiresAt = time.Now().Add(s.tokenDuration)
	return nil
}

func (s *inMemorySessionStore) DeleteUser(ctx context.Context, userID *uuid.UUID) error {
	s.log.Debug("deleting sessions for user", "user_id", userID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	for k, v := range s.sessions {
		if v.UserID == userID {
			delete(s.sessions, k)
			s.log.Debug("deleted session", "session_id", k)
		}
	}
	return nil
}

func (s *inMemorySessionStore) CleanupExpired(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session cleanup", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	now := time.Now()
	for k, v := range s.sessions {
		if v.ExpiresAt.Before(now) {
			delete(s.sessions, k)
			s.log.Debug("deleted expired session", "session_id", k)
		}
	}
	return nil
}

// StartCleanupWorker starts a goroutine that periodically cleans up expired sessions.
// The interval specifies how often the cleanup should run.
func (s *inMemorySessionStore) startCleanupWorker(interval time.Duration) {
	s.log.Debug("Starting session cleanup worker", "interval", interval)
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop() // Ensure the ticker is stopped when the goroutine exits
		for {
			select {
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(context.Background(), interval/2) // Give it a max half the interval
				err := s.CleanupExpired(cleanupCtx)
				if err != nil {
					if err != context.Canceled && err != context.DeadlineExceeded {
						s.log.Error("failed to cleanup sessions", "err", err)
					}
				}
				cancel() // Release resources associated with this context

			case <-s.stopCh:
				s.log.Info("Stopping session cleanup worker")
				return // Exit the goroutine
			}
		}
	}()
}
