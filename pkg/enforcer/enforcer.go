package enforcer

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
)

// Enforcer manages access control policies and wraps route handlers with
// authentication and authorization logic. It is typically used to guard routes
// based on roles defined in the Policies map.
type Enforcer struct {
	log      *slog.Logger
	Policies map[string]map[string]models.Role  // e.g route: {Get: RoleUser, Post: RoleAdmin}
	handlers map[string]map[string]http.Handler // path -> method -> handler internal mapping
	router   Router                             // used for middlewares and creating routes
	auth     authstore.Store
	session  sessionstore.Store
}

// NewEnforcer initializes and returns a new Enforcer instance.
//
// The Enforcer manages route access policies and wraps HTTP handlers
// with authentication and authorization logic. It maintains a mapping of
// allowed roles per HTTP method and path, and handles enforcement
// through middleware integration with the provided router.
//
// Params:
//   - logger: a logr.Logger for structured logging
//   - router: an implementation of the Router interface used to register and manage routes
//   - auth: an authentication store used to validate user credentials
//   - sess: a session store used to persist user sessions
//
// The Enforcer initializes with:
//   - An empty Policies map: policies can be added dynamically to control route access
//   - Internal handler mapping used to wrap and manage protected routes
//
// Example:
//
//	enforcer := NewEnforcer(logger, router, authStore, sessionStore)
func NewEnforcer(logger *slog.Logger, router Router, auth authstore.Store, sess sessionstore.Store) *Enforcer {
	return &Enforcer{
		log:      logger,
		Policies: map[string]map[string]models.Role{},
		router:   router,
		auth:     auth,
		session:  sess,
	}
}

// SetPolicy allows defining the minimum required role for a given resource path and HTTP method.
// Use "*" as the method to apply the policy to all methods for that path.
func (e *Enforcer) SetPolicy(resourcePath string, method string, requiredRole models.Role) {
	if _, ok := e.Policies[resourcePath]; !ok {
		e.Policies[resourcePath] = make(map[string]models.Role)
	}
	e.Policies[resourcePath][strings.ToUpper(method)] = requiredRole // Store method in uppercase
}

// FindMatchingPolicy finds the most specific policy for a given resource path and method.
// It prioritizes exact method matches over wildcard method matches.
func (e *Enforcer) FindMatchingPolicy(resourcePath, method string) (models.Role, bool) {
	method = strings.ToUpper(method)

	// Build all prefixes from most specific to least
	pathsToCheck := buildPrefixes(resourcePath)

	e.log.Debug("enforcer is finding matching policy",
		"resource path", resourcePath,
		"method", method,
		"paths to check", pathsToCheck,
	)

	for _, p := range pathsToCheck {
		if methodPolicies, ok := e.Policies[p]; ok {

			// 1. Exact method match
			if requiredRole, methodOk := methodPolicies[method]; methodOk {
				e.log.Debug("enforcer matched policy for path", "path", p, "available_methods", methodPolicies)
				return requiredRole, true
			}

			// 2. Wildcard match
			if requiredRole, anyMethodOk := methodPolicies["*"]; anyMethodOk {
				e.log.Debug("enforcer matched wildcard policy for path", "path", p, "available_methods", methodPolicies)
				return requiredRole, true
			}
		}
	}

	// No match
	return models.RoleGuest, false
}

// buildPrefixes returns a list of paths to check from most specific to least specific.
// For "/a/b/c" it returns ["/a/b/c", "/a/b", "/a", "/"].
// Preserves the exact path format as specified in HTTP routes.
func buildPrefixes(path string) []string {
	// Handle empty path or root path
	if path == "" || path == "/" {
		return []string{"/"}
	}

	// Split path into segments, removing empty segments from splitting
	segments := strings.Split(strings.Trim(path, "/"), "/")

	// Handle the case where path was just "/" (segments would be [""])
	if len(segments) == 1 && segments[0] == "" {
		return []string{"/"}
	}

	prefixes := make([]string, 0, len(segments)+1)

	// Build prefixes from most specific to least specific
	for i := len(segments); i > 0; i-- {
		if i == 1 {
			// For single segment, just add leading slash
			prefixes = append(prefixes, "/"+segments[0])
		} else {
			// For multiple segments, join with slashes
			prefixes = append(prefixes, "/"+strings.Join(segments[:i], "/"))
		}
	}

	// Always ensure root "/" is last
	prefixes = append(prefixes, "/")

	return prefixes
}
