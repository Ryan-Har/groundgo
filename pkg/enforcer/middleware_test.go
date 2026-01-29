package enforcer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ryan-Har/groundgo/pkg/apidetector"
	"github.com/stretchr/testify/assert"
)

func Test_defaultAPIDetector(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "API path with JSON accept",
			path:     "/api/v1/x",
			headers:  map[string]string{"Accept": "application/json"},
			expected: true,
		},
		{
			name:     "regular web request",
			path:     "/ui",
			headers:  map[string]string{"Accept": "text/html"},
			expected: false,
		},
		{
			name:     "API path without JSON accept",
			path:     "/api/v1/x",
			headers:  map[string]string{"Accept": "text/html"},
			expected: true,
		},
		{
			name:     "JSON accept without API path",
			path:     "/x",
			headers:  map[string]string{"Accept": "application/json"},
			expected: true,
		},
		{
			name:     "JSON content type header",
			path:     "/some/endpoint",
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: true,
		},
		{
			name:     "v1 path",
			path:     "/v1/users",
			headers:  nil,
			expected: true,
		},
		{
			name:     "v2 path",
			path:     "/v2/users",
			headers:  nil,
			expected: true,
		},
		{
			name:     "non-API path with HTML accept",
			path:     "/some/web/page",
			headers:  map[string]string{"Accept": "text/html"},
			expected: false,
		},
		{
			name: "API path with both JSON accept and content type",
			path: "/api/v1/users",
			headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.expected, apidetector.Default(req))
		})
	}
}
