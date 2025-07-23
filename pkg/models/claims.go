package models

import (
	"fmt"
	"strings"
)

// Claims maps resource paths to roles, representing access permissions.
type Claims map[string]Role

// GetEffectiveRole returns the most specific role matching the given resource path.
// It finds the longest prefix in the Claims map that matches the resource,
// applying path boundary checks to avoid partial matches (e.g., "/api/" does not match "/api2/").
// Returns the matched Role and true if found, or an empty Role and false if no match exists.
func (c Claims) GetEffectiveRole(resource string) (Role, bool) {
	mostSpecific := ""
	depth := -1

	for path := range c {
		if strings.HasPrefix(resource, path) {
			// Ensure the match respects path boundaries (e.g., "/api/" vs "/api2/")
			if !strings.HasSuffix(path, "/") && len(resource) > len(path) && resource[len(path)] != '/' {
				continue
			}

			currentDepth := strings.Count(path, "/")
			if currentDepth > depth {
				mostSpecific = path
				depth = currentDepth
			}
		}
	}

	if mostSpecific != "" {
		return c[mostSpecific], true
	}

	return "", false
}

// HasAtLeast reports whether the role for the given resource path
// meets or exceeds the required Role level. Returns false if no role is found.
func (c Claims) HasAtLeast(resource string, required Role) bool {
	role, ok := c.GetEffectiveRole(resource)
	if !ok {
		return false
	}
	return role.AtLeast(required)
}

// AddRole assigns a Role to the specified resource path in the Claims map.
func (c Claims) AddRole(resource string, role Role) {
	c[resource] = role
}

// AsSlice returns the claims as a colon delimited slice of roles
// eg. "/": "admin", "/admin": "user" -> ["/:admin", "/admin:user"]
func (c Claims) AsSlice() []string {
	claimsSlice := make([]string, 0, len(c))

	for resource, role := range c {
		claimsSlice = append(claimsSlice, fmt.Sprintf("%s:%s", resource, role.String()))
	}
	return claimsSlice
}
