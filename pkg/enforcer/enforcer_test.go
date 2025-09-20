package enforcer

import (
	"strings"
	"testing"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- buildPrefixes tests ---
func TestBuildPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple nested path",
			input:    "/a/b/c",
			expected: []string{"/a/b/c", "/a/b", "/a", "/"},
		},
		{
			name:     "root only",
			input:    "/",
			expected: []string{"/"},
		},
		{
			name:     "empty string treated as root",
			input:    "",
			expected: []string{"/"},
		},
		{
			name:     "no leading slash",
			input:    "x/y",
			expected: []string{"/x/y", "/x", "/"},
		},
		{
			name:     "single segment",
			input:    "/foo",
			expected: []string{"/foo", "/"},
		},
		{
			name:     "path with trailing slash",
			input:    "/api/users/",
			expected: []string{"/api/users", "/api", "/"},
		},
		{
			name:     "deeply nested path",
			input:    "/a/b/c/d/e/f",
			expected: []string{"/a/b/c/d/e/f", "/a/b/c/d/e", "/a/b/c/d", "/a/b/c", "/a/b", "/a", "/"},
		},
		{
			name:     "path with dots",
			input:    "/api/v1.0/users",
			expected: []string{"/api/v1.0/users", "/api/v1.0", "/api", "/"},
		},
		{
			name:     "path with parameter",
			input:    "/api/users/{id}/posts",
			expected: []string{"/api/users/{id}/posts", "/api/users/{id}", "/api/users", "/api", "/"},
		},
		{
			name:     "path with hyphens and underscores",
			input:    "/api/user-profiles/get_all",
			expected: []string{"/api/user-profiles/get_all", "/api/user-profiles", "/api", "/"},
		},
		{
			name:     "root with trailing slashes",
			input:    "///",
			expected: []string{"/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := buildPrefixes(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

// Additional FindMatchingPolicy tests for HTTP-specific scenarios
func TestFindMatchingPolicyHTTPScenarios(t *testing.T) {
	enf, _, _, _, _ := NewEnforcerFromMocks()

	// Setup realistic HTTP route policies
	enf.SetPolicy("/api/v1/users", "GET", models.RoleUser)
	enf.SetPolicy("/api/v1/users", "POST", models.RoleAdmin)
	enf.SetPolicy("/api/v1/users/{id}", "PUT", models.RoleAdmin)
	enf.SetPolicy("/api/v1/users/{id}", "DELETE", models.RoleSystemAdmin)
	enf.SetPolicy("/api/v1", "*", models.RoleUser) // wildcard for API access
	enf.SetPolicy("/public", "*", models.RoleGuest)
	enf.SetPolicy("/", "GET", models.RoleGuest) // public homepage

	tests := []struct {
		name      string
		path      string
		method    string
		wantRole  models.Role
		wantFound bool
	}{
		{
			name:      "exact API endpoint match",
			path:      "/api/v1/users",
			method:    "GET",
			wantRole:  models.RoleUser,
			wantFound: true,
		},
		{
			name:      "exact API endpoint different method",
			path:      "/api/v1/users",
			method:    "POST",
			wantRole:  models.RoleAdmin,
			wantFound: true,
		},
		{
			name:      "parameterized route exact match",
			path:      "/api/v1/users/{id}",
			method:    "DELETE",
			wantRole:  models.RoleSystemAdmin,
			wantFound: true,
		},
		{
			name:      "falls back to wildcard parent",
			path:      "/api/v1/products", // no specific policy, should use /api/v1 wildcard
			method:    "GET",
			wantRole:  models.RoleUser,
			wantFound: true,
		},
		{
			name:      "deeply nested falls back to parent wildcard",
			path:      "/api/v1/users/123/posts/456", // should fall back to /api/v1 wildcard
			method:    "GET",
			wantRole:  models.RoleUser,
			wantFound: true,
		},
		{
			name:      "public route with wildcard",
			path:      "/public/images/logo.png",
			method:    "GET",
			wantRole:  models.RoleGuest,
			wantFound: true,
		},
		{
			name:      "method priority over wildcard on same path",
			path:      "/api/v1/users",
			method:    "PUT", // no exact PUT, should fall back to /api/v1 wildcard
			wantRole:  models.RoleUser,
			wantFound: true,
		},
		{
			name:      "case insensitive HTTP methods",
			path:      "/api/v1/users",
			method:    "post", // should match POST policy
			wantRole:  models.RoleAdmin,
			wantFound: true,
		},
		{
			name:      "unusual but valid HTTP method",
			path:      "/api/v1/users",
			method:    "PATCH", // should fall back to wildcard
			wantRole:  models.RoleUser,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, found := enf.FindMatchingPolicy(tt.path, tt.method)
			require.Equal(t, tt.wantFound, found, "expected found=%v", tt.wantFound)
			require.Equal(t, tt.wantRole, role, "expected role=%v", tt.wantRole)
		})
	}
}

func TestPolicyMatching(t *testing.T) {
	cases := []struct {
		name          string
		setupPolicies func(*Enforcer)
		path          string
		method        string
		expectedFound bool
		expectedRole  models.Role
	}{
		{
			name: "exact method wins over wildcard",
			setupPolicies: func(e *Enforcer) {
				e.SetPolicy("/api/users", "*", models.RoleUser)       // wildcard
				e.SetPolicy("/api/users", "DELETE", models.RoleAdmin) // exact
			},
			path:          "/api/users",
			method:        "DELETE",
			expectedFound: true,
			expectedRole:  models.RoleAdmin,
		},
		{
			name: "wildcard used when exact not found",
			setupPolicies: func(e *Enforcer) {
				e.SetPolicy("/api/users", "*", models.RoleUser)
				e.SetPolicy("/api/users", "DELETE", models.RoleAdmin)
			},
			path:          "/api/users",
			method:        "GET",
			expectedFound: true,
			expectedRole:  models.RoleUser,
		},
		{
			name: "child policy isolation from parent",
			setupPolicies: func(e *Enforcer) {
				e.SetPolicy("/admin", "*", models.RoleAdmin)
				e.SetPolicy("/admin/users", "GET", models.RoleUser)
			},
			path:          "/admin",
			method:        "POST",
			expectedFound: true,
			expectedRole:  models.RoleAdmin,
		},
		{
			name: "parent policy isolation from child",
			setupPolicies: func(e *Enforcer) {
				e.SetPolicy("/admin", "*", models.RoleAdmin)
				e.SetPolicy("/admin/users", "GET", models.RoleUser)
			},
			path:          "/admin/users",
			method:        "GET",
			expectedFound: true,
			expectedRole:  models.RoleUser,
		},
		{
			name: "empty method uses wildcard",
			setupPolicies: func(e *Enforcer) {
				e.SetPolicy("/api", "*", models.RoleUser)
			},
			path:          "/api",
			method:        "",
			expectedFound: true,
			expectedRole:  models.RoleUser,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enf, _, _, _, _ := NewEnforcerFromMocks()
			tc.setupPolicies(enf)

			role, found := enf.FindMatchingPolicy(tc.path, tc.method)
			assert.Equal(t, tc.expectedFound, found)
			assert.Equal(t, tc.expectedRole, role)
		})
	}
}

func TestSetPolicyStoresUppercaseMethods(t *testing.T) {
	enf, _, _, _, _ := NewEnforcerFromMocks()
	enf.SetPolicy("/some/path", "get", models.RoleAdmin)
	require.Equal(t, models.RoleAdmin, enf.Policies["/some/path"]["GET"])
}
func BenchmarkBuildPrefixes(b *testing.B) {
	cases := []struct {
		name  string
		depth int // how many segments in the path
	}{
		{"short_path", 5},
		{"medium_path", 50},
		{"long_path", 100},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			path := "/" + strings.Repeat("a/", tc.depth) + "endpoint"
			b.ResetTimer() // ensure setup is not counted in benchmark
			for i := 0; i < b.N; i++ {
				buildPrefixes(path)
			}
		})
	}
}
