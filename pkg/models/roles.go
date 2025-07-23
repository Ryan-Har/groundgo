package models

import (
	"fmt"
	"slices"
)

// Role represents a user role in the system
type Role string

// These are the standard roles available by default
const (
	RoleGuest       Role = "guest"     // very limited access, items you'd only want publically available
	RoleReadOnly    Role = "readonly"  // Can view, but perhaps not interact or create
	RoleUser        Role = "user"      // standard authenticated user, can usually create and owns their own data
	RoleAuditor     Role = "auditor"   // more access than user but usually not allowed to edit
	RoleEditor      Role = "editor"    // can edit and modify content but perhaps not users
	RoleModerator   Role = "moderator" // Can moderate content, user content etc
	RoleSupport     Role = "support"   //  can perform support actions, perhaps can view sensitive data
	RoleAdmin       Role = "admin"     // Full administrative control within a scope
	RoleOwner       Role = "owner"     // Owner of specific entity, can delegate admins
	RoleSystemAdmin Role = "sysadmin"  // system wide administrator, highest privilege
)

// RoleHierarchy defines the privilege level of each role.
// Higher numbers represent higher privileges.
// If you define additional roles, place them in here.
var RoleHierarchy = map[Role]int{
	RoleGuest:       0,
	RoleReadOnly:    10,
	RoleUser:        20,
	RoleAuditor:     30,
	RoleEditor:      40,
	RoleModerator:   50,
	RoleSupport:     60,
	RoleAdmin:       70,
	RoleOwner:       80,
	RoleSystemAdmin: 90,
}

// ListRoles returns a slice of all existing roles from the RoleHierarchy with the lowest permission role first and the highest last.
func ListRoles() []string {
	type pair struct {
		role Role
		val  int
	}
	pairs := make([]pair, 0, len(RoleHierarchy))
	for r, v := range RoleHierarchy {
		pairs = append(pairs, pair{role: r, val: v})
	}

	slices.SortFunc(pairs, func(a, b pair) int {
		// return negative if a < b, 0 if equal, positive if a > b
		return a.val - b.val
	})

	result := make([]string, 0, len(pairs))
	for _, p := range pairs {
		result = append(result, p.role.String())
	}

	return result
}

// IsValid checks if the Role is one of the predefined valid roles.
func (r Role) IsValid() bool {
	_, exists := RoleHierarchy[r]
	return exists
}

// String implements the fmt.Stringer interface, providing a string representation of the Role.
func (r Role) String() string {
	return string(r)
}

// UnmarshalText and MarshalText methods
func (r *Role) UnmarshalText(text []byte) error {
	s := Role(text)
	if !s.IsValid() {
		return fmt.Errorf("invalid role: %s", text)
	}
	*r = s
	return nil
}

func (r Role) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r Role) AtLeast(min Role) bool {
	if r.IsValid() && min.IsValid() {
		return RoleHierarchy[r] >= RoleHierarchy[min]
	}
	return false
}
