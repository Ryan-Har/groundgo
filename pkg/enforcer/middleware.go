package enforcer

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
)

type contextKey string

const (
	userContextKey contextKey = "user"
	jwtContextKey  contextKey = "jwt"
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
		var isAuthenticated bool
		var authUser models.User
		var tokenString string

		// First, try session-based authentication
		session, cookie, err := e.getSessionFromCookie(r)

		// Handle session authentication
		if session != nil && err == nil {
			user, err := e.getUserFromSession(r.Context(), session, cookie, w, r)
			if err != nil {
				return // getUserFromSession handles redirects/responses
			}
			if user != nil {
				authUser = *user
				isAuthenticated = true
			}
		} else if cookie != nil && err != nil {
			// Cookie exists but session is invalid
			e.handleSessionError(err, cookie, w, r)
			return
		}

		// If session auth failed, try JWT authentication
		if !isAuthenticated {
			tokenStr, err := e.extractBearerToken(r)
			tokenString = tokenStr
			if err == nil { //token extracted
				user, err := e.validateTokenAndGetUser(r.Context(), tokenStr)
				if err == nil {
					authUser = *user
					isAuthenticated = true
				} else {
					e.log.Debug("JWT token invalid or user not found", "error", err.Error(), "url", r.URL.Path)
				}
			}

		}

		// If neither authentication method worked, assign guest role
		if !isAuthenticated {
			e.log.Debug("unable to authenticate user, assigning as guest",
				"remote_address", r.RemoteAddr,
				"url", r.URL.Path,
				"user_agent", r.UserAgent())
			authUser.Claims = map[string]models.Role{
				"/": models.RoleGuest,
			}
		}

		// Store the user and jwt string in the request context
		ctx := context.WithValue(
			context.WithValue(r.Context(), userContextKey, &authUser),
			jwtContextKey, tokenString)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getUserFromSession handles session-based authentication
func (e *Enforcer) getUserFromSession(ctx context.Context, session *models.Session, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) (*models.User, error) {
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
	payload, err := e.token.ParseToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	revoked, err := e.token.IsRevoked(ctx, payload)
	if err != nil {
		return nil, err
	}

	if revoked {
		return nil, errors.New("token revoked")
	}

	user, err := e.auth.GetUserByID(ctx, payload.Sub)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// // getUserFromJWT handles JWT-based authentication
// func (e *Enforcer) getUserFromJWT(r *http.Request) (*models.User, error) {
// 	// Extract JWT from Authorization header
// 	authHeader := r.Header.Get("Authorization")
// 	if authHeader == "" {
// 		return nil, errors.New("no authorization header")
// 	}

// 	// Check for Bearer token format
// 	parts := strings.SplitN(authHeader, " ", 2)
// 	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
// 		return nil, errors.New("invalid authorization header format")
// 	}

// 	tokenString := parts[1]
// 	if tokenString == "" {
// 		return nil, errors.New("empty token")
// 	}

// 	payload, err := e.token.ParseToken(r.Context(), tokenString)
// 	if err != nil {
// 		return nil, err
// 	}

// 	user, err := e.auth.GetUserByID(r.Context(), payload.Sub)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return user, nil
// }

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

// isAPIRequest determines if this is an API request vs browser request
// This helps decide whether to redirect or return HTTP error codes
func (e *Enforcer) isAPIRequest(r *http.Request) bool {
	// Check for API indicators
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	// Check Accept header - APIs typically request JSON
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}

	// Check for Authorization header (JWT users are likely API consumers)
	if r.Header.Get("Authorization") != "" {
		return true
	}

	return false
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
			user, ok := r.Context().Value(userContextKey).(*models.User)
			if !ok {
				e.log.Error("AuthorizationMiddleware expected User in http context and did not receive", "path", path)
				http.Error(w, "Forbidden", http.StatusInternalServerError)
				return
			}

			if !user.Claims.HasAtLeast(path, required) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
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
