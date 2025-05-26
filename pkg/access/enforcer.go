package access

import (
	"net/http"
	"strings"

	"slices"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
)

// Enforcer manages access control policies and wraps route handlers with
// authentication and authorization logic. It is typically used to guard routes
// based on roles defined in the Policies map.
type Enforcer struct {
	logger   logr.Logger
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
func NewEnforcer(logger logr.Logger, router Router, auth authstore.Store, sess sessionstore.Store) *Enforcer {
	return &Enforcer{
		logger:   logger,
		Policies: map[string]map[string]models.Role{},
		router:   router,
		auth:     auth,
		session:  sess,
	}
}

// LoadDefaultPolicies sets a baseline set of access control rules for common
// public routes like login, signup, and the home page.
//
// These policies grant access to unauthenticated (guest) users and are
// typically called during application startup before any custom policies
// are added.
func (e *Enforcer) LoadDefaultPolicies() {
	e.SetPolicy("/login", "GET", models.RoleGuest)
	e.SetPolicy("/login", "POST", models.RoleGuest)
	e.SetPolicy("/signup", "GET", models.RoleGuest)
	e.SetPolicy("/signup", "POST", models.RoleGuest)
	e.SetPolicy("/", "GET", models.RoleGuest)
}

// SetPolicy allows defining the minimum required role for a given resource path and HTTP method.
// Use "*" as the method to apply the policy to all methods for that path.
func (e *Enforcer) SetPolicy(resourcePath string, method string, requiredRole models.Role) {
	if _, ok := e.Policies[resourcePath]; !ok {
		e.Policies[resourcePath] = make(map[string]models.Role)
	}
	e.Policies[resourcePath][strings.ToUpper(method)] = requiredRole // Store method in uppercase
}

// findMatchingPolicy finds the most specific policy for a given resource path and method.
// It prioritizes exact method matches over wildcard method matches.
func (e *Enforcer) FindMatchingPolicy(resourcePath, method string) (models.Role, bool) {
	method = strings.ToUpper(method) // Ensure method is uppercase for consistent lookup

	e.logger.V(0).Info("enforcer is finding matching policy", "resource_path", resourcePath, "method", method)

	// Try finding an exact match for the path first (exact or prefix)
	// We'll iterate through paths from most specific to least specific
	pathsToCheck := []string{resourcePath}
	segments := strings.Split(resourcePath, "/")
	currentPath := ""
	for i := len(segments) - 1; i >= 0; i-- { // Iterate backwards from full path to root
		currentPath = strings.Join(segments[:i+1], "/")
		if currentPath == "" && i == 0 { // special case for root path "/"
			currentPath = "/"
		} else if currentPath == "" { // skip empty segments
			continue
		}
		if currentPath != resourcePath { // Add prefixes if they are different from exact path
			pathsToCheck = append(pathsToCheck, currentPath)
		}
	}
	// Ensure root path is always checked last if no other match (e.g. for `/`)
	if !contains(pathsToCheck, "/") {
		pathsToCheck = append(pathsToCheck, "/")
	}

	e.logger.V(4).Info("Paths to check for policy", "order", pathsToCheck)

	for _, p := range pathsToCheck {
		if methodPolicies, ok := e.Policies[p]; ok {
			e.logger.V(4).Info("Policy found for path, checking methods", "path", p, "available_methods", methodPolicies)
			// 1. Try to find an exact method match for this path
			if requiredRole, methodOk := methodPolicies[method]; methodOk {
				return requiredRole, true
			}
			e.logger.V(1).Info("No exact method policy found for path, checking wildcard", "path", p, "method", method)
			// 2. If no exact method match, try to find a wildcard method ("*") policy for this path
			if requiredRole, anyMethodOk := methodPolicies["*"]; anyMethodOk {
				return requiredRole, true
			}
		}
	}

	return models.RoleGuest, false
}

// Helper to check if a string is in a slice
func contains(s []string, e string) bool {
	return slices.Contains(s, e)
}
