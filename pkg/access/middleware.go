package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

type contextKey string

const (
	userContextKey contextKey = "user"
)

// // AuthenticationMiddleware simulates user authentication and attaches claims to context.
// func AuthenticationMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		var claims Claims
// 		var isAuthenticated bool

// 		//. Check for JWT in Authorization header (API usage)
// 		// authHeader := r.Header.Get("Authorization")
// 		// if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
// 		// 	jwtToken := authHeader[7:]

// 		// 	// 1. Validate JWT signature (using a secret key or public key)
// 		// 	// 2. Check JWT expiration
// 		// 	// 3. Parse claims from the JWT
// 		// 	// For demonstration, let's just parse the dummy user from JWT-like string
// 		// 	if jwtToken == "some_alice_jwt_token" {
// 		// 		claims = Claims{
// 		// 			"blog_posts":      RoleEditor,
// 		// 			"finance_reports": RoleReadOnly,
// 		// 			"user_profile":    RoleUser,
// 		// 		}
// 		// 		isAuthenticated = true
// 		// 	} else if jwtToken == "some_bob_jwt_token" {
// 		// 		claims = Claims{
// 		// 			"user_management": RoleAdmin,
// 		// 			"blog_posts":      RoleUser,
// 		// 		}
// 		// 		isAuthenticated = true
// 		// 	} else if jwtToken == "some_charlie_jwt_token" {
// 		// 		claims = Claims{
// 		// 			"global":          RoleSystemAdmin,
// 		// 			"user_management": RoleOwner,
// 		// 			"blog_posts":      RoleAdmin,
// 		// 		}
// 		// 		isAuthenticated = true
// 		// 	} else {
// 		// 		// Invalid JWT, log and return unauthorized
// 		// 		log.Println("Invalid JWT token provided.")
// 		// 	}
// 		// }

// 		// If not authenticated by JWT, check for session cookie
// 		if !isAuthenticated {
// 			sessionCookie, err := r.Cookie("session_token")
// 			if err == nil { // Cookie found
// 				sessionToken := sessionCookie.Value
// 				// In a real app:
// 				// 1. Look up sessionToken in a database/cache (e.g., Redis)
// 				// 2. Retrieve associated user ID and claims
// 				// 3. Validate session (e.g., check expiry)
// 				if sessionToken == "alice_session_xyz" {
// 					claims = Claims{
// 						"blog_posts":      RoleEditor,
// 						"finance_reports": RoleReadOnly,
// 						"user_profile":    RoleUser,
// 					}
// 					isAuthenticated = true
// 				} else if sessionToken == "bob_session_abc" {
// 					claims = Claims{
// 						"user_management": RoleAdmin,
// 						"blog_posts":      RoleUser,
// 					}
// 					isAuthenticated = true
// 				} else {
// 					log.Println("Invalid session cookie.")
// 				}
// 			}
// 		}

// 		// --- 3. Handle unauthenticated requests or assign default guest claims ---
// 		if !isAuthenticated {
// 			// If no valid authentication method, assign guest claims
// 			claims = Claims{
// 				"public": RoleGuest,
// 			}
// 			// For routes requiring authentication, you might return unauthorized here:
// 			// http.Error(w, "Unauthorized", http.StatusUnauthorized)
// 			// return
// 		}

// 		// Attach claims to the request context
// 		ctx := setClaimsInContext(r.Context(), claims)
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// AuthenticationMiddleware ensures that a user is present in the request context.
// If no user is authenticated, it injects a default guest user with RoleGuest.
func (e *Enforcer) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var isAuthenticated bool
		var authUser models.User

		sessionCookie, err := r.Cookie("session_token")
		if err == nil { // Cookie found
			sessionToken := sessionCookie.Value
			session, err := e.session.Get(r.Context(), sessionToken)
			if err != nil {
				if errors.Is(err, sessionstore.ErrSessionExpired) {
					e.logger.V(1).Info("expired session found", "session_id", sessionToken, "url", r.URL.Path)
					// copy cookie and force expire
					newCookie := *sessionCookie
					newCookie.Expires = time.Unix(0, 0)
					http.SetCookie(w, &newCookie)
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				} else {
					e.logger.Error(err, "unknown error getting session cookie")
					http.Redirect(w, r, "/login", http.StatusInternalServerError)
				}
				return
			}
			user, err := e.auth.GetUserByID(r.Context(), session.UserID)
			if err != nil {
				e.logger.Error(err, "getting user by id")
				http.Redirect(w, r, "/login", http.StatusInternalServerError)
			}
			authUser = user
			isAuthenticated = true
		}

		// final check to see if the user is authenticated, if not
		if !isAuthenticated || authUser.ID == uuid.Nil {
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

			if !e.HasRole(user.Claims, r.URL.Path, required) {
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
	requiredRole := e.LookupRequiredRole(method, path)

	// Guest by default, so no need to authorize
	if requiredRole != models.RoleGuest {
		h = e.AuthorizationMiddleware(path, requiredRole)(h)
	}

	h = e.AuthenticationMiddleware(h)
	return h
}
