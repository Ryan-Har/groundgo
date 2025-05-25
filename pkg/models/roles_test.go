package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		name string
		role Role
		want bool
	}{
		{"Valid Role: Guest", RoleGuest, true},
		{"Valid Role: ReadOnly", RoleReadOnly, true},
		{"Valid Role: User", RoleUser, true},
		{"Valid Role: Auditor", RoleAuditor, true},
		{"Valid Role: Editor", RoleEditor, true},
		{"Valid Role: Moderator", RoleModerator, true},
		{"Valid Role: Support", RoleSupport, true},
		{"Valid Role: Admin", RoleAdmin, true},
		{"Valid Role: Owner", RoleOwner, true},
		{"Valid Role: SystemAdmin", RoleSystemAdmin, true},
		{"Invalid Role: Unknown", Role("unknown_role"), false},
		{"Invalid Role: Empty String", Role(""), false},
		{"Invalid Role: Typo", Role("Admn"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.IsValid(); got != tt.want {
				t.Errorf("Role.IsValid() for role '%s' = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestRole_String(t *testing.T) {
	tests := []struct {
		name string
		role Role
		want string
	}{
		{"Guest Role String", RoleGuest, "guest"},
		{"Admin Role String", RoleAdmin, "admin"},
		{"SystemAdmin Role String", RoleSystemAdmin, "sysadmin"},
		{"Unknown Role String", Role("some_custom_role"), "some_custom_role"},
		{"Empty Role String", Role(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("Role.String() for role '%s' = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestRole_UnmarshalText(t *testing.T) {
	type TestStruct struct {
		MyRole Role `json:"my_role"`
	}

	tests := []struct {
		name        string
		input       []byte
		wantRole    Role
		wantErr     bool
		errContains string // substring to check in error message
	}{
		{"Valid Role: User", []byte(`user`), RoleUser, false, ""},
		{"Valid Role: Admin", []byte(`admin`), RoleAdmin, false, ""},
		{"Invalid Role: Typo", []byte(`adminn`), "", true, "invalid role"},
		{"Invalid Role: Numeric", []byte(`123`), "", true, "invalid role"}, // json.Unmarshal error
		{"Invalid Role: Null JSON", []byte(`null`), "", true, "invalid role"},
		{"Invalid Role: Empty String", []byte(``), "", true, "invalid role"},
		{"Valid Role from JSON object", []byte(`{"my_role": "editor"}`), RoleEditor, false, ""},
		{"Invalid Role from JSON object", []byte(`{"my_role": "bad_role"}`), "", true, "invalid role"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Role
			var ts TestStruct

			var err error
			if strings.HasPrefix(tt.name, "Valid Role from JSON object") || strings.HasPrefix(tt.name, "Invalid Role from JSON object") {
				err = json.Unmarshal(tt.input, &ts)
				r = ts.MyRole
			} else {
				err = r.UnmarshalText(tt.input)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Role.UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Role.UnmarshalText() error = %v, want error containing '%s'", err, tt.errContains)
				}
			} else {
				if r != tt.wantRole {
					t.Errorf("Role.UnmarshalText() got = %s, want %s", r, tt.wantRole)
				}
			}
		})
	}
}

func TestRole_MarshalText(t *testing.T) {
	type TestStruct struct {
		MyRole Role `json:"my_role"`
	}

	tests := []struct {
		name string
		role Role
		want []byte
	}{
		{"Valid Role: User", RoleUser, []byte(`"user"`)},
		{"Valid Role: Admin", RoleAdmin, []byte(`"admin"`)},
		{"Unknown Role", Role("custom_role"), []byte(`"custom_role"`)},
		{"Empty Role", Role(""), []byte(`""`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test MarshalText directly
			gotBytes, err := tt.role.MarshalText()
			if err != nil {
				t.Fatalf("Role.MarshalText() returned an unexpected error: %v", err)
			}
			if string(gotBytes) != string(tt.want[1:len(tt.want)-1]) { // Compare without quotes for direct MarshalText
				t.Errorf("Role.MarshalText() got = %s, want %s", gotBytes, tt.want[1:len(tt.want)-1])
			}

			// Test marshaling via JSON
			ts := TestStruct{MyRole: tt.role}
			jsonBytes, err := json.Marshal(ts)
			if err != nil {
				t.Fatalf("json.Marshal() returned an unexpected error: %v", err)
			}
			expectedJSON := fmt.Sprintf(`{"my_role":%s}`, string(tt.want))
			if string(jsonBytes) != expectedJSON {
				t.Errorf("json.Marshal() got = %s, want %s", jsonBytes, expectedJSON)
			}
		})
	}
}
