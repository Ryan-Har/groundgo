package models

import "strings"

type Claims map[string]Role // maps path to role

// GetEffectiveRole returns the most specific role match for the given resource path.
func (c Claims) GetEffectiveRole(resource string) (Role, bool) {
	mostSpecific := ""
	depth := -1

	for path := range c {
		if strings.HasPrefix(resource, path) {
			// Path boundary protection (e.g., "/api/" shouldn't match "/api2/")
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

// HasAtLeast returns true if the claim for the resource is at least the required role.
func (c Claims) HasAtLeast(resource string, required Role) bool {
	role, ok := c.GetEffectiveRole(resource)
	if !ok {
		return false
	}
	return role.AtLeast(required)
}

func (c Claims) AddRole(resource string, role Role) {
	c[resource] = role
}
