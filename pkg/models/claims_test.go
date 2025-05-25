package models

import "testing"

func TestClaims_Has(t *testing.T) {
	testClaims := Claims{
		"project_alpha": RoleAdmin,
		"project_beta":  RoleUser,
		"global_access": RoleAdmin,
	}

	tests := []struct {
		name     string
		key      string
		expected Role
		want     bool
	}{
		{
			name:     "Existing key with correct role",
			key:      "project_alpha",
			expected: RoleAdmin,
			want:     true,
		},
		{
			name:     "Existing key with incorrect role",
			key:      "project_beta",
			expected: RoleAdmin,
			want:     false,
		},
		{
			name:     "Non-existent key",
			key:      "project_gamma",
			expected: RoleUser,
			want:     false,
		},
		{
			name:     "Empty claims map",
			key:      "any_key",
			expected: RoleAdmin,
			want:     false,
		},
		{
			name:     "Existing key, checking against itself",
			key:      "project_beta",
			expected: RoleUser,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For "Empty claims map" test, create an empty Claims instance
			if tt.name == "Empty claims map" {
				emptyClaims := Claims{}
				if got := emptyClaims.Has(tt.key, tt.expected); got != tt.want {
					t.Errorf("Claims.Has() = %v, want %v", got, tt.want)
				}
			} else {
				if got := testClaims.Has(tt.key, tt.expected); got != tt.want {
					t.Errorf("Claims.Has() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestClaims_RoleFor(t *testing.T) {
	testClaims := Claims{
		"dashboard": RoleAdmin,
		"reports":   RoleUser,
	}

	tests := []struct {
		name      string
		resource  string
		wantRole  Role
		wantFound bool
	}{
		{
			name:      "Existing resource with Admin role",
			resource:  "dashboard",
			wantRole:  RoleAdmin,
			wantFound: true,
		},
		{
			name:      "Existing resource with User role",
			resource:  "reports",
			wantRole:  RoleUser,
			wantFound: true,
		},
		{
			name:      "Non-existent resource",
			resource:  "settings",
			wantRole:  "", // Default zero value for Role
			wantFound: false,
		},
		{
			name:      "Empty claims map",
			resource:  "any_resource",
			wantRole:  "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Claims
			if tt.name == "Empty claims map" {
				c = Claims{} // Use an empty map for this specific test
			} else {
				c = testClaims
			}

			gotRole, gotFound := c.RoleFor(tt.resource)
			if gotRole != tt.wantRole {
				t.Errorf("Claims.RoleFor() gotRole = %v, want %v", gotRole, tt.wantRole)
			}
			if gotFound != tt.wantFound {
				t.Errorf("Claims.RoleFor() gotFound = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}
