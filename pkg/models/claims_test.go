package models

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestClaims_GetEffectiveRole(t *testing.T) {
	claims := Claims{
		"/":          RoleGuest,
		"/api/":      RoleUser,
		"/api/v1":    RoleAdmin,
		"/api/v2/":   RoleEditor,
		"/dashboard": RoleSupport,
	}

	tests := []struct {
		name     string
		resource string
		wantRole Role
		wantOk   bool
	}{
		{
			name:     "root matches exactly /",
			resource: "/",
			wantRole: RoleGuest,
			wantOk:   true,
		},
		{
			name:     "root acts as catch-all when no specific match",
			resource: "/nothing",
			wantRole: RoleGuest,
			wantOk:   true,
		},
		{
			name:     "prefix match - /api/ applies",
			resource: "/api/health",
			wantRole: RoleUser,
			wantOk:   true,
		},
		{
			name:     "more specific prefix wins",
			resource: "/api/v1/resource",
			wantRole: RoleAdmin,
			wantOk:   true,
		},
		{
			name:     "boundary mismatch - /api should not match /api2/",
			resource: "/api2/",
			wantRole: RoleGuest, // falls back to root
			wantOk:   true,
		},
		{
			name:     "exact match without trailing slash",
			resource: "/dashboard",
			wantRole: RoleSupport,
			wantOk:   true,
		},
		{
			name:     "exact match wins over less specific prefix",
			resource: "/api/v2/",
			wantRole: RoleEditor,
			wantOk:   true,
		},
		{
			name:     "longer path breaks depth tie",
			resource: "/api/v1/extra/stuff",
			wantRole: RoleAdmin, // /api/v1 beats /api/
			wantOk:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRole, gotOk := claims.GetEffectiveRole(tt.resource)
			if gotRole != tt.wantRole || gotOk != tt.wantOk {
				t.Errorf("GetEffectiveRole(%q) = (%q,%v), want (%q,%v)",
					tt.resource, gotRole, gotOk, tt.wantRole, tt.wantOk)
			}
		})
	}
}

func TestClaims_HasAtLeast(t *testing.T) {
	claims := Claims{
		"/api/": RoleAdmin,
	}

	tests := []struct {
		name     string
		resource string
		required Role
		want     bool
	}{
		{"meets requirement", "/api/resource", RoleUser, true},
		{"does not meet requirement", "/api/resource", RoleSystemAdmin, false},
		{"no role found", "/unknown", RoleUser, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims.HasAtLeast(tt.resource, tt.required); got != tt.want {
				t.Errorf("HasAtLeast(%q,%q) = %v, want %v", tt.resource, tt.required, got, tt.want)
			}
		})
	}
}

func TestClaims_AddRoleAndAsSlice(t *testing.T) {
	claims := Claims{}
	claims.AddRole("/foo", RoleUser)
	claims.AddRole("/bar", RoleAdmin)

	if claims["/foo"] != RoleUser || claims["/bar"] != RoleAdmin {
		t.Errorf("AddRole failed, got %v", claims)
	}

	slice := claims.AsSlice()
	// Expect both entries present in slice
	want1 := "/foo:user"
	want2 := "/bar:admin"
	if !contains(slice, want1) || !contains(slice, want2) {
		t.Errorf("AsSlice() = %v, want values %q and %q", slice, want1, want2)
	}
}

func TestClaims_JSONRoundTrip(t *testing.T) {
	claims := Claims{
		"/foo": RoleUser,
		"/bar": RoleAdmin,
		"/":    RoleGuest, // should be skipped in Marshal
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Root claim should not be in JSON
	if string(data) == `{"\/":"guest"}` {
		t.Errorf("root claim should be skipped, got %s", string(data))
	}

	var got Claims
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Round-trip should preserve foo and bar
	want := Claims{"/foo": RoleUser, "/bar": RoleAdmin}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch: got %v, want %v", got, want)
	}
}

func TestClaims_UnmarshalJSON_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jsonStr string
	}{
		{"root path forbidden", `{"\/":"user"}`},
		{"invalid role", `{"\/bar":"notarole"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims Claims
			if err := json.Unmarshal([]byte(tt.jsonStr), &claims); err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

// helper
func contains(slice []string, want string) bool {
	for _, s := range slice {
		if s == want {
			return true
		}
	}
	return false
}
