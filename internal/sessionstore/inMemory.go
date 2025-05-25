package sessionstore

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

type inMemorySessionStore struct {
	*baseSessionStore
	sessions      map[string]*Session // sessionID -> userID
	mutex         *sync.Mutex
	log           logr.Logger
	tokenLength   int           // number of bytes used when generating tokens
	tokenDuration time.Duration // amound of time tokens are active for
	stopCh        chan struct{} // channel used to stop the cleanup of expired sessions
}

func (s *inMemorySessionStore) Create(ctx context.Context, userID uuid.UUID) (*Session, error) {
	s.log.V(1).Info("creating session")

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.V(1).Info("context cancelled during session creation", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sesID, err := generateSecureToken(s.tokenLength)
	if err != nil {
		return nil, err
	}

	session := s.createSession(sesID, userID, s.tokenDuration)
	s.sessions[sesID] = session

	s.log.V(4).Info("created session", "session_id", session.ID, "user_id", session.UserID.String())
	return session, nil
}

func (s *inMemorySessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	s.log.V(1).Info("getting session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.V(1).Info("context cancelled during session get", "error", ctx.Err())
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
	s.log.V(1).Info("deleting session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.V(1).Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	delete(s.sessions, sessionID)

	s.log.V(4).Info("deleted session", "session_id", sessionID)
	return nil
}

func (s *inMemorySessionStore) Renew(ctx context.Context, sessionID string) error {
	s.log.V(1).Info("renewing session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.V(1).Info("context cancelled during session renew", "error", ctx.Err())
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

func (s *inMemorySessionStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	s.log.V(1).Info("deleting sessions for user", "user_id", userID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.V(1).Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	for k, v := range s.sessions {
		if v.UserID == userID {
			delete(s.sessions, k)
			s.log.V(4).Info("deleted session", "session_id", k)
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
		s.log.V(1).Info("context cancelled during session cleanup", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	now := time.Now()
	for k, v := range s.sessions {
		if v.ExpiresAt.Before(now) {
			delete(s.sessions, k)
			s.log.V(4).Info("deleted expired session", "session_id", k)
		}
	}
	return nil
}

// StartCleanupWorker starts a goroutine that periodically cleans up expired sessions.
// The interval specifies how often the cleanup should run.
func (s *inMemorySessionStore) startCleanupWorker(interval time.Duration) {
	s.log.V(1).Info("Starting session cleanup worker", "interval", interval)
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
						s.log.Error(err, "periodic session cleanup")
					}
				}
				cancel() // Release resources associated with this context

			case <-s.stopCh:
				s.log.V(1).Info("Stopping session cleanup worker")
				return // Exit the goroutine
			}
		}
	}()
}
