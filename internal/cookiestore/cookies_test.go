package cookiestore

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Helper function to get a cookie by name from a response recorder
func getCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestNewManager tests the NewManager and default/insecure constructors
func TestNewManager(t *testing.T) {
	// Test NewManager with nil config and logger
	m := NewManager(nil, nil)
	if m == nil {
		t.Fatal("NewManager returned nil manager")
	}
	if m.config == nil {
		t.Error("Manager config is nil")
	}
	if m.logger == nil {
		t.Error("Manager logger is nil")
	}

	// Test NewManagerWithDefaults
	m = NewManagerWithDefaults(nil)
	if m.config.GuestCookieSecure != true {
		t.Error("NewManagerWithDefaults did not set secure flag")
	}

	// Test NewManagerWithInsecureDefaults
	m = NewManagerWithInsecureDefaults(nil)
	if m.config.GuestCookieSecure != false {
		t.Error("NewManagerWithInsecureDefaults did not set insecure flag")
	}
}

// TestSetCookie tests the generic cookie setting function with various options
func TestSetCookie(t *testing.T) {
	m := NewManagerWithDefaults(slog.Default())
	w := httptest.NewRecorder()

	// Test with minimal options
	opts := CookieOptions{
		Name:     "test_cookie",
		Value:    "test_value",
		Path:     "/",
		HttpOnly: true,
	}
	if err := m.SetCookie(w, opts); err != nil {
		t.Fatalf("SetCookie failed: %v", err)
	}
	c := getCookie(w, "test_cookie")
	if c == nil {
		t.Fatal("SetCookie did not set the cookie")
	}
	if c.Value != "test_value" {
		t.Errorf("expected value 'test_value', got '%s'", c.Value)
	}
	if c.HttpOnly != true {
		t.Errorf("expected HttpOnly true, got false")
	}

	// Test with Expires
	w = httptest.NewRecorder()
	expires := time.Now().Add(time.Hour)
	opts.Expires = &expires
	if err := m.SetCookie(w, opts); err != nil {
		t.Fatalf("SetCookie with expires failed: %v", err)
	}
	c = getCookie(w, "test_cookie")
	if c.Expires.IsZero() {
		t.Error("Expires not set")
	}

	// Test with MaxAge
	w = httptest.NewRecorder()
	maxage := 3600
	opts.Expires = nil
	opts.MaxAge = &maxage
	if err := m.SetCookie(w, opts); err != nil {
		t.Fatalf("SetCookie with maxage failed: %v", err)
	}
	c = getCookie(w, "test_cookie")
	if c.MaxAge != 3600 {
		t.Errorf("expected MaxAge 3600, got %d", c.MaxAge)
	}

	// Test with Secure
	w = httptest.NewRecorder()
	opts.Secure = true
	if err := m.SetCookie(w, opts); err != nil {
		t.Fatalf("SetCookie with secure failed: %v", err)
	}
	c = getCookie(w, "test_cookie")
	if c.Secure != true {
		t.Errorf("expected Secure true, got false")
	}
}

// TestSetSpecificCookies tests the functions for setting specific cookie types
func TestSetSpecificCookies(t *testing.T) {
	m := NewManagerWithDefaults(slog.Default())
	w := httptest.NewRecorder()

	// Test SetGuestCookie
	if err := m.SetGuestCookie(w, "guest_val", nil); err != nil {
		t.Fatalf("SetGuestCookie failed: %v", err)
	}
	c := getCookie(w, m.config.GuestCookieName)
	if c == nil {
		t.Fatal("Guest cookie not set")
	}
	if c.Value != "guest_val" || c.Path != m.config.GuestCookiePath || c.Secure != m.config.GuestCookieSecure {
		t.Errorf("Guest cookie mismatch: %+v", c)
	}

	// Test SetRefreshTokenCookie
	w = httptest.NewRecorder()
	if err := m.SetRefreshTokenCookie(w, "refresh_val", nil); err != nil {
		t.Fatalf("SetRefreshTokenCookie failed: %v", err)
	}
	c = getCookie(w, m.config.RefreshTokenCookieName)
	if c == nil {
		t.Fatal("Refresh token cookie not set")
	}
	if c.Value != "refresh_val" || c.Secure != m.config.RefreshTokenSecure {
		t.Errorf("Refresh token cookie mismatch: %+v", c)
	}

	// Test SetUserSessionCookie
	w = httptest.NewRecorder()
	if err := m.SetUserSessionCookie(w, "user_session_val", nil); err != nil {
		t.Fatalf("SetUserSessionCookie failed: %v", err)
	}
	c = getCookie(w, m.config.UserSessionCookieName)
	if c == nil {
		t.Fatal("User session cookie not set")
	}
	if c.Value != "user_session_val" || c.Secure != m.config.UserSessionCookieSecure {
		t.Errorf("User session cookie mismatch: %+v", c)
	}

	// Test SetGenericCookie
	w = httptest.NewRecorder()
	if err := m.SetGenericCookie(w, "generic_test", "generic_val", "/api", nil); err != nil {
		t.Fatalf("SetGenericCookie failed: %v", err)
	}
	c = getCookie(w, "generic_test")
	if c == nil {
		t.Fatal("Generic cookie not set")
	}
	if c.Value != "generic_val" || c.Secure != m.config.GenericCookieSecure {
		t.Errorf("Generic cookie mismatch: %+v", c)
	}
}

// TestClearCookies tests the cookie clearing functions
func TestClearCookies(t *testing.T) {
	m := NewManagerWithDefaults(slog.Default())
	w := httptest.NewRecorder()

	// Test ClearGuestCookie
	if err := m.ClearGuestCookie(w); err != nil {
		t.Fatalf("ClearGuestCookie failed: %v", err)
	}
	c := getCookie(w, m.config.GuestCookieName)
	if c == nil {
		t.Fatal("Guest cookie clear failed")
	}
	if c.Value != "" || c.MaxAge != -1 {
		t.Errorf("Guest cookie not cleared correctly: %+v", c)
	}

	// Test ClearRefreshTokenCookie
	w = httptest.NewRecorder()
	if err := m.ClearRefreshTokenCookie(w); err != nil {
		t.Fatalf("ClearRefreshTokenCookie failed: %v", err)
	}
	c = getCookie(w, m.config.RefreshTokenCookieName)
	if c == nil {
		t.Fatal("Refresh token clear failed")
	}
	if c.Value != "" || c.MaxAge != -1 {
		t.Errorf("Refresh token not cleared correctly: %+v", c)
	}
}

// TestGetCookie tests the cookie retrieval functions
func TestGetCookie(t *testing.T) {
	m := NewManagerWithDefaults(slog.Default())

	// Set up a mock request with a cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "test_get", Value: "retrieved_val"})

	// Test GetCookie with a valid cookie
	val, err := m.GetCookie(req, "test_get")
	if err != nil {
		t.Fatalf("GetCookie failed: %v", err)
	}
	if val != "retrieved_val" {
		t.Errorf("expected value 'retrieved_val', got '%s'", val)
	}

	// Test GetCookie with a missing cookie
	_, err = m.GetCookie(req, "non_existent")
	if err == nil || !strings.Contains(err.Error(), http.ErrNoCookie.Error()) {
		t.Errorf("expected 'no such cookie' error, got %v", err)
	}
}

// TestValidation tests the validateCookieOptions function
func TestValidation(t *testing.T) {
	m := NewManagerWithDefaults(slog.Default())
	tests := []struct {
		name     string
		opts     CookieOptions
		hasError bool
	}{
		{
			"valid cookie",
			CookieOptions{Name: "test_name", Value: "test_value"},
			false,
		},
		{
			"empty name",
			CookieOptions{Name: "", Value: "value"},
			true,
		},
		{
			"invalid characters in name",
			CookieOptions{Name: "name with space", Value: "value"},
			true,
		},
		{
			"value too large",
			CookieOptions{Name: "long_value", Value: strings.Repeat("a", 4097)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.validateCookieOptions(tt.opts)
			if (err != nil) != tt.hasError {
				t.Errorf("expected error: %v, got: %v", tt.hasError, err)
			}
		})
	}
}
