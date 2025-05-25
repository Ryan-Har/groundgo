package models

import "fmt"

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

// IsValid checks if the Role is one of the predefined valid roles.
func (r Role) IsValid() bool {
	switch r {
	case RoleGuest, RoleReadOnly, RoleUser, RoleAuditor, RoleEditor, RoleModerator, RoleSupport, RoleAdmin, RoleOwner, RoleSystemAdmin:
		return true
	}
	return false
}

// String implements the fmt.Stringer interface, providing a string representation of the Role.
func (r Role) String() string {
	return string(r)
}

// UnmarshalText and MarshalText methods (as discussed previously)
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
