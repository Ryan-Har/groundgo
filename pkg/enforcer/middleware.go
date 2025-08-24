package enforcer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/api"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
	JWTContextKey  contextKey = "jwt"
)

// AuthenticationMiddleware is an HTTP middleware that extracts and validates
// user authentication state from either session cookies or JWT bearer tokens
// and attaches a user object to the request context.
//
// Authentication order:
// 1. First checks for a valid session cookie
// 2. If no session found, checks for JWT bearer token in Authorization header
// 3. If neither found or both invalid, treats user as guest
//
// If a valid session cookie is found, the corresponding user is retrieved and
// passed downstream via context. If the session is expired, it clears the cookie
// and redirects the client to the login page (for browser requests).
//
// If a JWT token is found and valid, the user is extracted from the token claims
// and passed downstream via context. Invalid JWTs result in 401 Unauthorized.
//
// This middleware does not enforce access control — it only authenticates the
// user. Authorization logic should be applied downstream (e.g., via RequireAuth).
//
// Context Injection:
//   - A *models.User is stored under the key `userContextKey` for downstream handlers.
func (e *Enforcer) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authUser *models.User
		var tokenString string
		var isAuthenticated bool

		// check for JWT bearer token first
		if user, token, ok := e.tryJWTAuth(r); ok {
			authUser = user
			tokenString = token
			isAuthenticated = true
		}

		// try session-based authentication next if user is not using JWT
		// returned user could be guest
		if !isAuthenticated {
			user, ok := e.trySessionAuth(r, w)
			if ok {
				authUser = user
				isAuthenticated = true
			}
		}

		// fallback: if neither authentication method worked, assign guest role
		if !isAuthenticated {
			user, err := e.createGuestSession(r, w)
			if err != nil {
				if isAPIRequest(r) {
					api.ReturnError(w, e.log, api.InternalServerError)
				} else {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}
			authUser = user
		}

		// Store the user and jwt string (if available) in the request context
		ctx := context.WithValue(
			context.WithValue(r.Context(), UserContextKey, authUser),
			JWTContextKey, tokenString)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizationMiddleware returns an HTTP middleware that ensures the user has
// the required role for accessing a specific path.
//
// It expects that AuthenticationMiddleware has already been applied and that a
// *models.User is present in the request context under the `userContextKey`.
// If the user context is missing, it logs an error and returns a 500 Internal Server Error.
// If the user lacks sufficient permissions, it returns a 403 Forbidden response.
//
// Parameters:
//   - path: the route path against which the user's role is validated.
//   - required: the minimum role required to access the path.
//
// Logging:
//   - If the user context is missing, logs an info-level message with verbosity 0.
//
// Example usage:
//
//	router.Handle("/admin",
//	  enforcer.AuthenticationMiddleware(
//	    enforcer.AuthorizationMiddleware("/admin", models.RoleAdmin)(adminHandler),
//	  ),
//	)
func (e *Enforcer) AuthorizationMiddleware(path string, required models.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(UserContextKey).(*models.User)
			if !ok {
				e.log.Error("AuthorizationMiddleware expected User in http context and did not receive", "path", path)
				e.respondForbidden(w, r)
				return
			}

			user.EnsureRootClaim()

			if !user.Claims.HasAtLeast(path, required) {
				e.respondForbidden(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getUserFromSession handles session-based authentication
// It returns the user model if it exists or a guest user model if uuid is nil.
func (e *Enforcer) getUserFromSession(ctx context.Context, session *models.Session, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) (*models.User, error) {
	if session.UserID == uuid.Nil {
		guestUser := &models.User{
			ID:     uuid.Nil,
			Claims: map[string]models.Role{"/": models.RoleGuest},
		}
		return guestUser, nil
	}

	user, err := e.auth.GetUserByID(ctx, session.UserID)
	if err != nil || user == nil || !user.IsActive {
		e.log.Info("session request from expired/unknown/inactive user", "id", session.UserID)
		e.session.ExpireCookie(cookie, w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, errors.New("invalid user session")
	}
	return user, nil
}

func (e *Enforcer) extractBearerToken(r *http.Request) (string, error) {
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

func (e *Enforcer) validateTokenAndGetUser(ctx context.Context, tokenString string) (*models.User, error) {
	payload, err := e.token.ParseAccessTokenAndValidate(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	subID, err := uuid.Parse(payload.Subject)
	if err != nil {
		return nil, fmt.Errorf("unable to parse payload subject: %w", err)
	}

	user, err := e.auth.GetUserByID(ctx, subID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// handleSessionError processes session-related errors
// Since we're dealing with cookies, we assume this is a browser request and redirect
func (e *Enforcer) handleSessionError(err error, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) {
	if errors.Is(err, sessionstore.ErrSessionExpired) {
		e.log.Debug("expired session found", "session_id", cookie.Value, "url", r.URL.Path)
		e.session.ExpireCookie(cookie, w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		e.log.Error("unknown error getting session cookie", "error", err.Error())
		http.Redirect(w, r, "/login", http.StatusInternalServerError)
	}
}

// WrapHandler applies authentication and, if a policy exists, authorization middleware
// to the given handler. It returns the fully wrapped http.Handler.
//
// It first determines the required role for the given route and method.
// If a policy is found and the role is not RoleGuest, authorization is added.
// Authentication is always applied.
func (e *Enforcer) WrapHandler(path, method string, h http.Handler) http.Handler {
	requiredRole, _ := e.FindMatchingPolicy(path, method)

	// Guest by default, so no need to authorize
	if requiredRole != models.RoleGuest {
		h = e.AuthorizationMiddleware(path, requiredRole)(h)
	}

	h = e.AuthenticationMiddleware(h)
	return h
}

func (e *Enforcer) getSessionFromCookie(r *http.Request) (*models.Session, *http.Cookie, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, nil, err
	}
	session, err := e.session.Get(r.Context(), cookie.Value)
	return session, cookie, err
}

// tryJWTAuth attempts to extract and validate a JWT Bearer token from the request.
// If successful, it returns the authenticated user, the token string, and true.
// On failure, it logs the error and returns nil, "", false.
func (e *Enforcer) tryJWTAuth(r *http.Request) (*models.User, string, bool) {
	tokenStr, err := e.extractBearerToken(r)
	if err != nil {
		return nil, "", false
	}

	user, err := e.validateTokenAndGetUser(r.Context(), tokenStr)
	if err != nil {
		e.log.Debug("JWT token invalid or user not found", "error", err.Error(), "url", r.URL.Path)
		return nil, "", false
	}

	return user, tokenStr, true
}

// trySessionAuth attempts to retrieve and validate a session from the session cookie.
// If the session is valid (including guest sessions), it returns the user and true.
// If the session is expired or invalid, it handles the response (e.g., clearing cookie or redirecting).
// On failure, it returns nil and false.
func (e *Enforcer) trySessionAuth(r *http.Request, w http.ResponseWriter) (*models.User, bool) {
	session, cookie, err := e.getSessionFromCookie(r)
	if session != nil && err == nil {
		user, err := e.getUserFromSession(r.Context(), session, cookie, w, r)
		if err == nil && user != nil {
			return user, true
		}
		return nil, false // error already handled
	}

	if cookie != nil && err != nil {
		e.handleSessionError(err, cookie, w, r)
	}

	return nil, false
}

// createGuestSession creates a new session for an unauthenticated (guest) user.
// It sets a session cookie in the response, and returns a User with RoleGuest.
// If session creation or user resolution fails, an error is returned.
func (e *Enforcer) createGuestSession(r *http.Request, w http.ResponseWriter) (*models.User, error) {
	e.log.Debug("unauthenticated request, creating guest session",
		"remote_address", r.RemoteAddr,
		"url", r.URL.Path,
		"user_agent", r.UserAgent())

	guestSession, err := e.session.Create(r.Context(), uuid.Nil)
	if err != nil {
		e.log.Error("unable to create guest session", "err", err)
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    guestSession.ID,
		Expires:  guestSession.ExpiresAt,
		HttpOnly: true,
		Secure:   false, // Set to true in production
		Path:     "/",
	})

	user, err := e.getUserFromSession(r.Context(), guestSession, nil, w, r)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// isAPIRequest checks if a request is  an API request by checking that both an accept header exists with json
// and the path contains "api" somewhere
func isAPIRequest(r *http.Request) bool {
	// Check if the request Accept header contains "json"
	acceptHeader := r.Header.Get("Accept")
	acceptsJSON := strings.Contains(acceptHeader, "json")

	// Check if the URL path contains "api"
	pathContainsAPI := strings.Contains(r.URL.Path, "api")

	// Must satisfy both conditions
	return acceptsJSON && pathContainsAPI
}

func (e *Enforcer) respondForbidden(w http.ResponseWriter, r *http.Request) {
	if isAPIRequest(r) {
		api.ReturnError(w, e.log, api.ForbiddenAccessDenied)
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func (e *Enforcer) respondMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if isAPIRequest(r) {
		api.ReturnError(w, e.log, api.MethodNotAllowed)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
