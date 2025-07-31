package tokenstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type baseTokenStore struct {
	log           *slog.Logger
	jwtSecret     string
	tokenDuration time.Duration
}

func NewBase(logger *slog.Logger, signingSecret string, tokenDuration time.Duration) *baseTokenStore {
	return &baseTokenStore{
		log:           logger,
		jwtSecret:     signingSecret,
		tokenDuration: tokenDuration,
	}
}

type TokenPayload struct {
	Sub    uuid.UUID     `json:"sub"`
	Claims models.Claims `json:"claims"`
	jwt.RegisteredClaims
}

// tokenStateChecker defines the methods a base refresher needs from its parent store.
// It's unexported because it's an internal implementation detail.
type tokenStateChecker interface {
	ParseToken(ctx context.Context, tokenStr string) (*TokenPayload, error)
	IsRevoked(ctx context.Context, tokenPayload *TokenPayload) (bool, error)
	RevokeToken(ctx context.Context, token *TokenPayload) error
}

// IssueToken generates a signed JWT for the given user.
func (t *baseTokenStore) IssueToken(user *models.User) (string, error) {
	now := time.Now()
	payload := TokenPayload{
		Sub:    user.ID,
		Claims: user.Claims,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.tokenDuration)),
			Subject:   user.ID.String(),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return token.SignedString([]byte(t.jwtSecret))
}

// refreshToken provides the generic algorithm for refreshing a token.
// It uses the provided checker to handle stateful operations (parsing, revoking).
func (t *baseTokenStore) refreshToken(ctx context.Context, checker tokenStateChecker, oldTokenStr string) (string, error) {

	payload, err := checker.ParseToken(ctx, oldTokenStr)
	if err != nil {
		return "", fmt.Errorf("could not parse token for refresh: %w", err)
	}

	revoked, err := checker.IsRevoked(ctx, payload)
	if err != nil {
		return "", logutil.LogAndWrapErr(t.log, "failed to check token revocation", err)
	}

	if revoked {
		return "", errors.New("token has been revoked")
	}

	// Revoke the token prior to sending the new one
	if err := checker.RevokeToken(ctx, payload); err != nil {
		return "", logutil.LogAndWrapErr(t.log, "could not revoke old token", err)
	}

	newPayload := TokenPayload{
		Sub:    payload.Sub,
		Claims: payload.Claims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(t.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   payload.Subject,
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newPayload)
	return token.SignedString([]byte(t.jwtSecret))
}

type TokenStore interface {
	// Generate a new JWT for a user
	IssueToken(user *models.User) (string, error)

	// ParseToken validates and parses a JWT string, returning the tokenPayload if valid. Does not check if it is revoked.
	ParseToken(ctx context.Context, tokenStr string) (*TokenPayload, error)

	// Revoke a token before expiry
	RevokeToken(ctx context.Context, token *TokenPayload) error

	// Check if a token payload has been revoked
	IsRevoked(ctx context.Context, tokenPayload *TokenPayload) (bool, error)

	// Refresh an expiring token
	RefreshTokenStr(ctx context.Context, oldTokenStr string) (string, error)
}
