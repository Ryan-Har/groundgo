package tokenstore

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/golang-jwt/jwt/v5"
)

type sqliteTokenStore struct {
	*baseTokenStore
	db      *sql.DB
	queries sqliteDB.Queries
}

func NewSqlLite(logger *slog.Logger, signingSecret string, tokenDuration time.Duration, db *sql.DB) *sqliteTokenStore {
	return &sqliteTokenStore{
		baseTokenStore: NewBase(logger, signingSecret, tokenDuration),
		db:             db,
		queries:        *sqliteDB.New(db),
	}
}

// ParseToken validates and parses a JWT string, returning the claims if valid.
func (t *sqliteTokenStore) ParseToken(ctx context.Context, tokenStr string) (*TokenPayload, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenPayload{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	payload, ok := token.Claims.(*TokenPayload)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token or claims")
	}

	return payload, nil
}

// IsRevoked checks if the token payload has been revoked.
func (t *sqliteTokenStore) IsRevoked(ctx context.Context, tokenPayload *TokenPayload) (bool, error) {
	defer logutil.NewTimingLogger(t.log, time.Now(), "executed sql query", "method", "is token revoked")()
	exists, err := t.queries.IsTokenRevoked(ctx, tokenPayload.ID)
	if err != nil && err == sql.ErrNoRows {
		return exists > 0, nil
	}
	return exists > 0, err
}

// RevokeToken marks a token as revoked
func (t *sqliteTokenStore) RevokeToken(ctx context.Context, token *TokenPayload) error {
	defer logutil.NewTimingLogger(t.log, time.Now(), "executed sql query", "method", "revoke token")()

	params := sqliteDB.RevokeTokenParams{
		ID:                token.ID,
		UserID:            token.Sub.String(),
		OriginalExpiresAt: token.ExpiresAt.Unix(),
	}
	_, err := t.queries.RevokeToken(ctx, params)

	return err
}

// RefreshToken is the public-facing method.
// It calls the generic algorithm from the embedded baseTokenStore,
// passing itself (`s`) as the implementation for the state checking.
// It Parses, validates and checks for revocation before
func (t *sqliteTokenStore) RefreshTokenStr(ctx context.Context, oldTokenStr string) (string, error) {
	return t.baseTokenStore.refreshToken(ctx, t, oldTokenStr)
}
