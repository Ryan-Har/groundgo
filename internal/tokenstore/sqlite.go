package tokenstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/transform"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// cleanup interval represents the time between checks for cleaning up the expired, revoked tokens
var cleanupInterval time.Duration = time.Minute * 10

type sqliteTokenStore struct {
	*baseTokenStore
	db      *sql.DB
	queries sqliteDB.Queries
}

func NewSqlite(logger *slog.Logger, signingSecret string, tokenDuration time.Duration, db *sql.DB) *sqliteTokenStore {
	t := &sqliteTokenStore{
		baseTokenStore: NewBase(logger, signingSecret, tokenDuration),
		db:             db,
		queries:        *sqliteDB.New(db),
	}
	t.startCleanupWorker(cleanupInterval)
	return t
}

// IssueTokenPair generates a new access and refresh token pair for the user.
func (t *sqliteTokenStore) IssueTokenPair(ctx context.Context, user *models.User) (*TokenPair, error) {
	now := time.Now()
	accessToken := AccessToken{
		Claims: user.Claims,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.tokenDuration)),
			Subject:   user.ID.String(),
			ID:        uuid.NewString(),
		},
	}
	accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessToken)
	signedAccessToken, err := accessTokenJwt.SignedString([]byte(t.jwtSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	//  generate the refresh token and store it in the db
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	refreshTokenHash := hashToken(refreshToken)
	refreshTokenExpiry := now.Add(t.refreshTokenDuration)

	_, err = t.queries.CreateRefreshToken(ctx, sqliteDB.CreateRefreshTokenParams{
		ID:        uuid.NewString(),
		UserID:    user.ID.String(),
		TokenHash: refreshTokenHash,
		ExpiresAt: refreshTokenExpiry.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:      signedAccessToken,
		RefreshToken:     refreshToken,
		ExpiresInSeconds: int64(t.tokenDuration.Seconds()),
	}, nil
}

// RotateRefreshToken validates an old refresh token and issues a new token pair.
func (t *sqliteTokenStore) RotateRefreshToken(ctx context.Context, refreshTokenStr string) (*TokenPair, error) {
	defer logutil.NewTimingLogger(t.log, time.Now(), "executed sql query", "method", "rotate refresh token")()

	refreshTokenHash := hashToken(refreshTokenStr)

	oldToken, err := t.queries.GetRefreshTokenByHash(ctx, refreshTokenHash)
	if err != nil {
		// If the token is not found, it's invalid.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("db error getting refresh token: %w", err)
	}

	// CRITICAL: Immediately delete the used token to prevent reuse.
	// If we can't delete the token, we must not issue a new one.
	if err := t.queries.DeleteRefreshTokenByID(ctx, oldToken.ID); err != nil {
		return nil, ErrTokenReuseDetected
	}

	if time.Now().Unix() > oldToken.ExpiresAt {
		// As a security measure, if an expired token is used, we can assume
		// something is wrong and invalidate all sessions for that user.
		_ = t.queries.DeleteUserRefreshTokens(ctx, oldToken.UserID)
		return nil, ErrInvalidToken
	}

	userResp, err := t.queries.GetUserByID(ctx, oldToken.UserID)
	if err != nil { //user doesn't exist, invalid
		return nil, ErrInvalidToken
	}

	user, err := transform.FromSQLiteUser(userResp)
	if err != nil {
		return nil, models.NewTransformationError(err.Error())
	}

	return t.IssueTokenPair(ctx, &user)
}

// ParseAccessTokenAndValidate is a helper that both Parses Access Token
// And Checks if the token is revoked, providing an error if it is not a valid token
func (t *sqliteTokenStore) ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*AccessToken, error) {
	accessToken, err := t.ParseAccessToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}

	if revoked, err := t.IsAccessTokenRevoked(ctx, accessToken); revoked {
		return nil, err
	}

	return accessToken, nil
}

// ParseAccessToken validates and parses a JWT string, returning the claims if valid.
func (t *sqliteTokenStore) ParseAccessToken(ctx context.Context, tokenStr string) (*AccessToken, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessToken{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	payload, ok := token.Claims.(*AccessToken)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return payload, nil
}

// IsAccessTokenRevoked checks if the token payload has been revoked.
func (t *sqliteTokenStore) IsAccessTokenRevoked(ctx context.Context, accessToken *AccessToken) (bool, error) {
	defer logutil.NewTimingLogger(t.log, time.Now(), "executed sql query", "method", "is token revoked")()
	exists, err := t.queries.IsTokenRevoked(ctx, accessToken.ID)
	if err != nil && err == sql.ErrNoRows {
		return exists > 0, nil
	}
	return exists > 0, fmt.Errorf("failed to check if access token is revoked: %w", err)
}

// RRevokeAccessToken marks a token as revoked
func (t *sqliteTokenStore) RevokeAccessToken(ctx context.Context, token *AccessToken) error {
	defer logutil.NewTimingLogger(t.log, time.Now(), "executed sql query", "method", "revoke token")()

	params := sqliteDB.RevokeTokenParams{
		ID:                token.ID,
		UserID:            token.Subject,
		OriginalExpiresAt: token.ExpiresAt.Unix(),
	}
	_, err := t.queries.RevokeToken(ctx, params)

	return err
}

// StartCleanupWorker starts a goroutine that periodically cleans up revoked tokens.
// The interval specifies how often the cleanup should run.
func (t *sqliteTokenStore) startCleanupWorker(interval time.Duration) {
	t.log.Debug("Starting revoked tokens cleanup worker", "interval", interval)
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop() // Ensure the ticker is stopped when the goroutine exits
		for {
			select {
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(context.Background(), interval/2) // Give it a max half the interval
				defer cancel()                                                              // Release resources associated with this context

				err := t.queries.DeleteExpiredRevokedTokens(cleanupCtx)
				if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
					t.log.Error("failed to cleanup revoked tokens", "err", err)
				}

				err = t.queries.DeleteExpiredRefreshTokens(cleanupCtx)
				if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
					t.log.Error("failed to cleanup revoked tokens", "err", err)
				}

			case <-t.stopCh:
				t.log.Info("Stopping revoked tokens cleanup worker")
				return // Exit the goroutine
			}
		}
	}()
}
