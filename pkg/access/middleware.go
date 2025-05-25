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

// AuthenticationMiddleware ensures that a user is present in the request context.
// If no user is authenticated, it injects a default guest user with RoleGuest.
func (e *Enforcer) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var isAuthenticated bool
		var authUser models.User

		session, cookie, err := e.getSessionFromCookie(r)

		// cookie and error means no session
		if cookie != nil && err != nil {
			if errors.Is(err, sessionstore.ErrSessionExpired) {
				e.logger.V(1).Info("expired session found", "session_id", cookie.Value, "url", r.URL.Path)
				e.session.ExpireCookie(cookie, w)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				e.logger.Error(err, "unknown error getting session cookie")
				http.Redirect(w, r, "/login", http.StatusInternalServerError)
			}
			return
		}

		// existing session, get user by id
		if session != nil {
			user, err := e.auth.GetUserByID(r.Context(), session.UserID)
			if err != nil {
				e.logger.Error(err, "getting user by id")
				http.Redirect(w, r, "/login", http.StatusInternalServerError)
			}
			authUser = user
			isAuthenticated = true
		}

		// final check to see if the user is authenticated
		if !isAuthenticated {
			e.logger.V(4).Info("unable to authenticate user, assigning as guest", "remote_address", r.RemoteAddr, "url", r.URL.Path, "user_agent", r.UserAgent())
			authUser.Claims = map[string]models.Role{
				"/": models.RoleGuest,
			}
		}

		// Store the user in the request context
		ctx := context.WithValue(r.Context(), userContextKey, &authUser)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizationMiddleware checks if the current user has the required role
// to access the route. If not, it responds with HTTP 403 Forbidden.
func (e *Enforcer) AuthorizationMiddleware(path string, required models.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(userContextKey).(*models.User)
			if !ok {
				panic("no user in context")
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
