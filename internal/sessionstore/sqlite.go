package sessionstore

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type sqliteSessionStore struct {
	*baseSessionStore
	db      *sql.DB
	queries sqliteDB.Queries
	log     *slog.Logger
}

func (s *sqliteSessionStore) Create(ctx context.Context, userID uuid.UUID) (*models.Session, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "create session")()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session creation", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sesh, err := s.createSession(userID, nil, nil)
	if err != nil {
		return nil, err
	}

	session, err := s.queries.CreateSession(ctx, sqliteDB.CreateSessionParamsFromModel(*sesh))
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "failed to create session",
			models.NewDatabaseError(err))
	}

	response, err := session.ToSessionModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "failed to create session",
			models.NewTransformationError(err.Error()))
	}

	return &response, nil
}

func (s *sqliteSessionStore) Get(ctx context.Context, sessionID string) (*models.Session, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "get session", "session id", sessionID)()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session get", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sesh, err := s.queries.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, newSessionExpiredError(sessionID)
		}
		return nil, logutil.DebugAndWrapErr(s.log, "failed to get session",
			models.NewDatabaseError(err),
			"session id", sessionID)
	}

	response, err := sesh.ToSessionModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "failed to create session",
			models.NewTransformationError(err.Error()))
	}

	return &response, nil
}

func (s *sqliteSessionStore) Delete(ctx context.Context, sessionID string) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "delete session", "session id", sessionID)()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	if err := s.queries.DeleteSession(ctx, sessionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return logutil.DebugAndWrapErr(s.log, "failed to delete session",
			models.NewDatabaseError(err),
			"session id", sessionID)
	}

	return nil
}

func (s *sqliteSessionStore) Renew(ctx context.Context, sessionID string) (*models.Session, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "renew session", "session id", sessionID)()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session renew", "error", ctx.Err())
		return nil, ctx.Err()
	default:
	}

	sesh, err := s.queries.RenewSession(ctx, sqliteDB.RenewSessionParams{
		ID:        sessionID,
		ExpiresAt: time.Now().Add(s.tokenDuration).Unix(),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, newSessionExpiredError(sessionID)
		}
		return nil, logutil.DebugAndWrapErr(s.log, "failed to renew session",
			models.NewDatabaseError(err),
			"session id", sessionID)
	}

	response, err := sesh.ToSessionModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, "failed to renew session",
			models.NewTransformationError(err.Error()))
	}
	return &response, nil
}

func (s *sqliteSessionStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "delete user sessions", "user id", userID)()

	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session delete", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	if err := s.queries.DeleteSessionsByUserID(ctx, userID.String()); err != nil {
		return models.NewDatabaseError(err)
	}

	return nil
}

func (s *sqliteSessionStore) CleanupExpired(ctx context.Context) error {
	// Check for context cancellation/deadline early.
	select {
	case <-ctx.Done():
		s.log.Info("context cancelled during session cleanup", "error", ctx.Err())
		return ctx.Err()
	default:
	}

	return s.queries.DeleteExpiredSessions(ctx)
}
