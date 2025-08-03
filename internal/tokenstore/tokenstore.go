package tokenstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

type baseTokenStore struct {
	log                  *slog.Logger
	jwtSecret            string
	tokenDuration        time.Duration
	refreshTokenDuration time.Duration
	stopCh               chan struct{} // channel used to stop the cleanup of expired sessions
}

func NewBase(logger *slog.Logger, signingSecret string, tokenDuration time.Duration) *baseTokenStore {
	return &baseTokenStore{
		log:                  logger,
		jwtSecret:            signingSecret,
		tokenDuration:        tokenDuration,
		refreshTokenDuration: time.Hour * 24 * 7,
		stopCh:               make(chan struct{}),
	}
}

// TokenPair holds both a new access token and a new refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// This is the access token prior to it being signed
type AccessToken struct {
	Claims models.Claims `json:"claims"`
	jwt.RegisteredClaims
}

// ErrInvalidToken is a sentinel error for invalid or expired tokens.
var ErrInvalidToken = errors.New("invalid or expired token")
var ErrTokenReuseDetected = errors.New("token reuse detected")

// generateRefreshToken creates a secure, random, URL-safe string.
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// hashToken creates a SHA-256 hash of a token string.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
