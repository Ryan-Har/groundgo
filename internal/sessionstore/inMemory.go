package sessionstore

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type inMemorySessionStore struct {
	*baseSessionStore
	sessions map[string]*models.Session // sessionID -> userID
	mutex    *sync.Mutex
	log      *slog.Logger
}

func (s *inMemorySessionStore) Create(ctx context.Context, userID uuid.UUID) (*models.Session, error) {
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

	session, err := s.createSession(userID, nil, nil)
	if err != nil {
		return nil, err
	}
	s.sessions[session.ID] = session

	s.log.Debug("created session", "session_id", session.ID, "user_id", session.UserID.String())
	return session, nil
}

func (s *inMemorySessionStore) Get(ctx context.Context, sessionID string) (*models.Session, error) {
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

func (s *inMemorySessionStore) Renew(ctx context.Context, sessionID string) (*models.Session, error) {
	s.log.Debug("renewing session", "session_id", sessionID)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session renew", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sess, ok := s.sessions[sessionID]
	if !ok || sess.ExpiresAt.Before(time.Now()) {
		return nil, &SessionExpiredError{ID: sessionID}
	}

	sess.ExpiresAt = time.Now().Add(s.tokenDuration)
	return sess, nil
}

func (s *inMemorySessionStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
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
