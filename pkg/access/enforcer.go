package access

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
)

type Enforcer struct {
	logger        logr.Logger
	RoleHierarchy map[models.Role]int
	Policies      map[string]map[string]models.Role  // e.g route: {Get: RoleUser, Post: RoleAdmin}
	handlers      map[string]map[string]http.Handler // path -> method -> handler internal mapping
	router        Router                             // used for middlewares and creating routes
	auth          authstore.Store
	session       sessionstore.Store
}

func NewEnforcer(logger logr.Logger, router Router, auth authstore.Store, sess sessionstore.Store) *Enforcer {
	return &Enforcer{
		logger: logger,
		RoleHierarchy: map[models.Role]int{
			models.RoleGuest:       0,
			models.RoleReadOnly:    1,
			models.RoleUser:        2,
			models.RoleAuditor:     3,
			models.RoleEditor:      4,
			models.RoleModerator:   5,
			models.RoleSupport:     6,
			models.RoleAdmin:       7,
			models.RoleOwner:       8,
			models.RoleSystemAdmin: 9,
		},
		Policies: map[string]map[string]models.Role{},
		router:   router,
		auth:     auth,
		session:  sess,
	}
}

func (e *Enforcer) LoadDefaultPolicies() {
	e.SetPolicy("/login", "GET", models.RoleGuest)
	e.SetPolicy("/login", "POST", models.RoleGuest)
	e.SetPolicy("/signup", "GET", models.RoleGuest)
	e.SetPolicy("/signup", "GET", models.RoleGuest)
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

	return "", false
}

// HasRole checks if the provided Claims (user's roles) grant sufficient access
// to a given resource for a required minimum role, based on the role hierarchy
func (e *Enforcer) HasRole(c models.Claims, resource string, required models.Role) bool {
	actual, ok := c[resource]
	if !ok {
		return false
	}
	// Validate that both the actual and required roles exist in the RoleHierarchy.
	actualLevel, actualOk := e.RoleHierarchy[actual]
	requiredLevel, requiredOk := e.RoleHierarchy[required]
	if !actualOk || !requiredOk {
		e.logger.Error(errors.New("role not found in enforcer hierarchy"), "actual", actual, "actual_exists", actualOk, "required", required, "required_exists", requiredOk)
		return false
	}
	return actualLevel >= requiredLevel
}

// lookupRequiredRole determines the role required for a given method and path.
// It checks for method-specific policies first, then falls back to any-method ("*") policies.
// If no policy is found, it defaults to RoleGuest.
func (e *Enforcer) LookupRequiredRole(method, path string) models.Role {
	methods, ok := e.Policies[path]
	if !ok {
		return models.RoleGuest
	}

	if role, ok := methods[method]; ok {
		return role
	}

	if role, ok := methods["*"]; ok {
		return role
	}

	return models.RoleGuest
}

// Helper to check if a string is in a slice
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
