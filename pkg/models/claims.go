package models

type Claims map[string]Role // maps path to role

func (c Claims) Has(key string, expected Role) bool {
	r, ok := c[key]
	return ok && r == expected
}

func (c Claims) RoleFor(resource string) (Role, bool) {
	role, ok := c[resource]
	return role, ok
}
