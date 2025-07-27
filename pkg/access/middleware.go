package access

import (
	"context"
	"errors"
	"net/http"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
)

type contextKey string

const (
	userContextKey contextKey = "user"
)

// AuthenticationMiddleware is an HTTP middleware that extracts and validates
// user authentication state from the request cookie and attaches a user object
// to the request context.
//
// If a valid session cookie is found, the corresponding user is retrieved and
// passed downstream via context. If the session is expired, it clears the cookie
// and redirects the client to the login page. If no session is found or validation
// fails, the user is treated as a guest and assigned minimal access.
//
// This middleware does not enforce access control — it only authenticates the
// user. Authorization logic should be applied downstream (e.g., via RequireAuth).
//
// Context Injection:
//   - A *models.User is stored under the key `userContextKey` for downstream handlers.
//
// Usage:
//
//	http.Handle("/profile", enforcer.AuthenticationMiddleware(http.HandlerFunc(ProfileHandler)))
//
// Typical redirect behavior:
//   - Expired session ➝ `/login` with StatusSeeOther
//   - Unknown error ➝ `/login` with StatusInternalServerError
func (e *Enforcer) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var isAuthenticated bool
		var authUser models.User

		session, cookie, err := e.getSessionFromCookie(r)

		// cookie and error means no session
		if cookie != nil && err != nil {
			if errors.Is(err, sessionstore.ErrSessionExpired) {
				e.log.Debug("expired session found", "session_id", cookie.Value, "url", r.URL.Path)
				e.session.ExpireCookie(cookie, w)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				e.log.Error("unknown error getting session cookie")
				http.Redirect(w, r, "/login", http.StatusInternalServerError)
			}
			return
		}

		// existing session, get user by id
		if session != nil {
			user, err := e.auth.GetUserByID(r.Context(), *session.UserID)
			if err != nil || user == nil || !user.IsActive { //session exists for a disabled or deleted user
				e.log.Info("session request from expired unknown id", "id", session.UserID)
				e.session.ExpireCookie(cookie, w)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			authUser = *user
			isAuthenticated = true
		}

		// final check to see if the user is authenticated
		if !isAuthenticated {
			e.log.Debug("unable to authenticate user, assigning as guest", "remote_address", r.RemoteAddr, "url", r.URL.Path, "user_agent", r.UserAgent())
			authUser.Claims = map[string]models.Role{
				"/": models.RoleGuest,
			}
		}

		// Store the user in the request context
		ctx := context.WithValue(r.Context(), userContextKey, &authUser)
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

func (e *Enforcer) getSessionFromCookie(r *http.Request) (*sessionstore.Session, *http.Cookie, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, nil, err
	}
	session, err := e.session.Get(r.Context(), cookie.Value)
	return session, cookie, err
}
