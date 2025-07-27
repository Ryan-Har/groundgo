package sessionstore

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type baseSessionStore struct {
	log *slog.Logger
}

func NewBase(logger *slog.Logger) *baseSessionStore {
	s := &baseSessionStore{
		log: logger,
	}
	return s
}

func (s *baseSessionStore) ExpireCookie(c *http.Cookie, w http.ResponseWriter) {
	c.Expires = time.Unix(0, 0)
	http.SetCookie(w, c)
}

func (s *baseSessionStore) createSession(id string, userID *uuid.UUID, expiresIn time.Duration) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(expiresIn),
	}
}
