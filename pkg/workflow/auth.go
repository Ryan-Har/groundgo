package workflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

// resolveFromJWT attempts to extract and validate a JWT Bearer token from the request.
// If successful, it returns the authenticated user, the token string, and nil.
// On failure, it returns nil, "", error.
func (f *Workflow) resolveFromJWT(r *http.Request) (*models.User, string, error) {
	tokenStr, err := f.extractBearerToken(r)
	if err != nil {
		return nil, "", ErrNotAuthenticated
	}

	user, err := f.userFromJWTString(r.Context(), tokenStr)
	if err != nil {
		switch {
		case errors.Is(err, tokenstore.ErrInvalidToken):
			return nil, "", ErrTokenInvalid
		case errors.Is(err, tokenstore.ErrTokenExpired):
			return nil, "", ErrSessionExpired
		case errors.Is(err, tokenstore.ErrTokenRevoked):
			return nil, "", ErrTokenRevoked
		default:
			return nil, "", ErrNotAuthenticated
		}
	}

	return user, tokenStr, nil
}

// resolveFromSession attempts to extract and validate a session cookie from the request.
// If successful, it returns the authenticated user, nil.
// On failure, it returns nil, error.
func (f *Workflow) resolveFromSession(r *http.Request) (*models.User, error) {
	cookie, err := f.extractSessionCookie(r)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	session, err := f.store.Session.Get(r.Context(), cookie.Value)
	if err != nil {
		switch {
		case errors.Is(err, sessionstore.ErrSessionExpired):
			return nil, ErrSessionExpired
		default:
			return nil, ErrInternalServer
		}
	}

	user, err := f.userFromSession(r.Context(), session)
	if err != nil {
		return nil, ErrInternalServer
	}

	return user, nil
}

func (f *Workflow) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("empty token")
	}

	return token, nil
}

func (f *Workflow) extractSessionCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("session_token")
}

func (f *Workflow) userFromJWTString(ctx context.Context, tokenString string) (*models.User, error) {
	payload, err := f.store.Token.ParseAccessTokenAndValidate(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	subID, err := uuid.Parse(payload.Subject)
	if err != nil {
		return nil, fmt.Errorf("unable to parse payload subject: %w", err)
	}

	user, err := f.store.Auth.GetUserByID(ctx, subID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// userFromSession handles session-based authentication
// It returns the user model if it exists or a guest user model if uuid is nil.
func (f *Workflow) userFromSession(ctx context.Context, session *models.Session) (*models.User, error) {
	if session.UserID == uuid.Nil {
		return models.NewGuestUser(), nil
	}

	user, err := f.store.Auth.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("unable to get user from session: %w", err)
	}

	return user, nil
}
