package apidetector

import (
	"net/http/httptest"
	"testing"
)

func TestDefaultAPIDetector(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		accept      string
		contentType string
		expect      bool
	}{
		// Header-based detection
		{"Accept JSON", "/any", "application/json", "", true},
		{"Content-Type JSON", "/any", "", "application/json", true},
		{"Both headers JSON", "/any", "application/json", "application/json", true},
		{"No JSON headers", "/any", "text/html", "text/plain", false},

		// Path-based detection
		{"Path /api/", "/api/users", "", "", true},
		{"Path /v1/", "/v1/users", "", "", true},
		{"Path /v2/", "/v2/users", "", "", true},
		{"Non-API path", "/home", "", "", false},

		// Combination of headers and path
		{"Header JSON overrides non-API path", "/home", "application/json", "", true},
		{"Path API overrides non-JSON headers", "/api/orders", "text/html", "text/plain", true},
		{"Neither headers nor API path", "/home", "text/html", "text/plain", false},

		// Case-insensitive checks
		{"Uppercase Accept header", "/home", "APPLICATION/JSON", "", true},
		{"Uppercase Content-Type header", "/home", "", "APPLICATION/JSON", true},
		{"Uppercase API path", "/API/USERS", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			got := Default(req)
			if got != tt.expect {
				t.Errorf("defaultAPIDetector(%q, Accept=%q, Content-Type=%q) = %v; want %v",
					tt.path, tt.accept, tt.contentType, got, tt.expect)
			}
		})
	}
}

func TestPathOnlyDetector(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect bool
	}{
		{"API path lowercase", "/api/users", true},
		{"API path uppercase", "/API/products", true},
		{"Non-API v1 path", "/v1/users", false},
		{"Non-API path", "/home", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			got := PathOnly(req)
			if got != tt.expect {
				t.Errorf("PathOnlyDetector(%q) = %v; want %v", tt.path, got, tt.expect)
			}
		})
	}
}

func TestHeaderOnlyDetector(t *testing.T) {
	tests := []struct {
		name        string
		accept      string
		contentType string
		expect      bool
	}{
		{"Accept JSON", "application/json", "", true},
		{"Content-Type JSON", "", "application/json", true},
		{"Both headers JSON", "application/json", "application/json", true},
		{"No JSON headers", "text/html", "text/plain", false},
		{"Uppercase headers", "APPLICATION/JSON", "APPLICATION/JSON", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/any", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			got := HeaderOnly(req)
			if got != tt.expect {
				t.Errorf("HeaderOnlyDetector(Accept=%q, Content-Type=%q) = %v; want %v",
					tt.accept, tt.contentType, got, tt.expect)
			}
		})
	}
}

func TestAlwaysAndNeverDetectors(t *testing.T) {
	req := httptest.NewRequest("GET", "/anything", nil)

	t.Run("AlwaysAPIDetector should always return true", func(t *testing.T) {
		if !Always(req) {
			t.Errorf("AlwaysAPIDetector returned false, want true")
		}
	})

	t.Run("NeverAPIDetector should always return false", func(t *testing.T) {
		if Never(req) {
			t.Errorf("NeverAPIDetector returned true, want false")
		}
	})
}
