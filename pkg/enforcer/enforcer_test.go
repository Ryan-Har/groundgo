package enforcer

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/stretchr/testify/require"
)

// --- Helper: a no-op logger for tests ---
func NoopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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
	e := NewEnforcer(NoopLogger(), nil, nil, nil, nil)

	// Setup realistic HTTP route policies
	e.SetPolicy("/api/v1/users", "GET", models.RoleUser)
	e.SetPolicy("/api/v1/users", "POST", models.RoleAdmin)
	e.SetPolicy("/api/v1/users/{id}", "PUT", models.RoleAdmin)
	e.SetPolicy("/api/v1/users/{id}", "DELETE", models.RoleSystemAdmin)
	e.SetPolicy("/api/v1", "*", models.RoleUser) // wildcard for API access
	e.SetPolicy("/public", "*", models.RoleGuest)
	e.SetPolicy("/", "GET", models.RoleGuest) // public homepage

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
			role, found := e.FindMatchingPolicy(tt.path, tt.method)
			require.Equal(t, tt.wantFound, found, "expected found=%v", tt.wantFound)
			require.Equal(t, tt.wantRole, role, "expected role=%v", tt.wantRole)
		})
	}
}

// Test policy precedence - exact method wins over wildcard on same path
func TestPolicyPrecedence(t *testing.T) {
	e := NewEnforcer(NoopLogger(), nil, nil, nil, nil)

	// Set up conflicting policies to test precedence
	e.SetPolicy("/api/users", "*", models.RoleUser)       // wildcard first
	e.SetPolicy("/api/users", "DELETE", models.RoleAdmin) // specific method second

	role, found := e.FindMatchingPolicy("/api/users", "DELETE")
	require.True(t, found)
	require.Equal(t, models.RoleAdmin, role, "exact method should win over wildcard")

	role, found = e.FindMatchingPolicy("/api/users", "GET")
	require.True(t, found)
	require.Equal(t, models.RoleUser, role, "should fall back to wildcard for other methods")
}

// Test that policies don't interfere with each other
func TestPolicyIsolation(t *testing.T) {
	e := NewEnforcer(NoopLogger(), nil, nil, nil, nil)

	e.SetPolicy("/admin", "*", models.RoleAdmin)
	e.SetPolicy("/admin/users", "GET", models.RoleUser) // less restrictive child

	// Child policy should not affect parent
	role, found := e.FindMatchingPolicy("/admin", "POST")
	require.True(t, found)
	require.Equal(t, models.RoleAdmin, role)

	// Parent should not affect child
	role, found = e.FindMatchingPolicy("/admin/users", "GET")
	require.True(t, found)
	require.Equal(t, models.RoleUser, role)
}

// Test empty method string (edge case)
func TestEmptyMethod(t *testing.T) {
	e := NewEnforcer(NoopLogger(), nil, nil, nil, nil)
	e.SetPolicy("/api", "*", models.RoleUser)

	// Empty method should be converted to uppercase and not match wildcard
	role, found := e.FindMatchingPolicy("/api", "")
	require.True(t, found)
	require.Equal(t, models.RoleUser, role) // should match wildcard
}

// --- SetPolicy test (sanity check) ---
func TestSetPolicyStoresUppercaseMethods(t *testing.T) {
	e := NewEnforcer(NoopLogger(), nil, nil, nil, nil)
	e.SetPolicy("/some/path", "get", models.RoleAdmin)
	require.Equal(t, models.RoleAdmin, e.Policies["/some/path"]["GET"])
}

func BenchmarkBuildPrefixes(b *testing.B) {
	path := "/" + strings.Repeat("a/", 100) + "endpoint"
	for i := 0; i < b.N; i++ {
		buildPrefixes(path)
	}
}
