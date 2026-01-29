package enforcer

import (
	"context"
	"net/http"

	"github.com/Ryan-Har/groundgo/api"
	"github.com/Ryan-Har/groundgo/pkg/models"
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
		var ctx context.Context

		_, ctx, err := e.flow.AuthenticateRequest(r)
		// user is not authenticated
		if err != nil {
			_, ctx = e.flow.EnsureGuest(r, w)
		}

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
			user, err := e.flow.ResolveUser(r)
			if err != nil {
				e.log.Error("AuthorizationMiddleware expected User in http context and did not receive", "path", path, "error", err)
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


func (e *Enforcer) respondForbidden(w http.ResponseWriter, r *http.Request) {
	if e.APIDetector(r) {
		api.ReturnError(w, e.log, api.ForbiddenAccessDenied)
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func (e *Enforcer) respondMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if e.APIDetector(r) {
		api.ReturnError(w, e.log, api.MethodNotAllowed)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
