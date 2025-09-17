package cookies

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type DurationConfig struct {
	GuestSessionDuration  time.Duration
	RefreshTokenDuration  time.Duration
	UserSessionDuration   time.Duration
	DefaultCookieDuration time.Duration
}

// CookieConfig holds the configuration for different cookie types
type CookieConfig struct {
	// Guest token specific config
	GuestStateEnabled bool   // determines if guests require state, if not, no cookie is provided
	GuestCookieName   string // string used for the session cookie of guest user
	GuestCookieSecure bool   // determines if the cookie should be secure or not. Recommended always to be true in production environments
	GuestCookiePath   string // path set for the session cookie of the guest user

	RedirectOnAuthErrorPath string // path of the redirection location when authentication fails
	HttpOnly                bool
	SameSite                http.SameSite

	// Refresh token specific config
	RefreshTokenCookieName string
	RefreshTokenPath       string
	RefreshTokenSecure     bool
	RefreshTokenHttpOnly   bool
	RefreshTokenSameSite   http.SameSite

	// Session token specific config
	UserSessionCookieName     string
	UserSessionCookiePath     string
	UserSessionCookieSecure   bool
	UserSessionCookieHttpOnly bool
	UserSessionCookieSameSite http.SameSite

	// Generic cookie specific config
	GenericCookieSecure   bool
	GenericCookieHttpOnly bool
	GenericCookieSameSite http.SameSite

	// API base route for constructing paths
	APIBaseRoute string

	// Duration configuration
	Durations DurationConfig

	// Security settings
	EnableSecurityHeaders bool
	Domain                string // Cookie domain
}

// CookieOptions represents options for setting a cookie
type CookieOptions struct {
	Name     string
	Value    string
	Expires  *time.Time
	MaxAge   *int
	Path     string
	Domain   string
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// ValidationError represents a cookie validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("cookie validation error - %s: %s", e.Field, e.Message)
}

// Manager handles cookie operations with the configured settings
type Manager struct {
	config *CookieConfig
	logger *slog.Logger
}

// NewManager creates a new cookie manager with the provided configuration
func NewManager(config *CookieConfig, logger *slog.Logger) *Manager {
	if config == nil {
		config = newDefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		config: config,
		logger: logger,
	}
}

// NewManagerWithDefaults creates a new cookie manager with default configuration
func NewManagerWithDefaults(logger *slog.Logger) *Manager {
	return NewManager(newDefaultConfig(), logger)
}

// NewManagerWithInsecureDefaults creates a new cookie manager with insecure default configuration
func NewManagerWithInsecureDefaults(logger *slog.Logger) *Manager {
	return NewManager(newInsecureDefaultConfig(), logger)
}

// SetCookie sets a cookie with the provided options and optional logging
func (m *Manager) SetCookie(w http.ResponseWriter, opts CookieOptions) error {
	if err := m.validateCookieOptions(opts); err != nil {
		m.logger.Error("invalid cookie options", "error", err)
		return err
	}

	cookie := &http.Cookie{
		Name:     opts.Name,
		Value:    opts.Value,
		Path:     opts.Path,
		Domain:   opts.Domain,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
	}

	if opts.Expires != nil {
		cookie.Expires = *opts.Expires
	}

	if opts.MaxAge != nil {
		cookie.MaxAge = *opts.MaxAge
	}

	http.SetCookie(w, cookie)

	m.logger.Debug("cookie set successfully",
		"name", opts.Name,
		"path", opts.Path,
		"secure", opts.Secure,
		"httpOnly", opts.HttpOnly,
		"expires", opts.Expires)

	return nil
}

// SetGuestCookie sets a guest session cookie using the configured settings
func (m *Manager) SetGuestCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	expires := customExpires
	if expires == nil {
		exp := time.Now().Add(m.config.Durations.GuestSessionDuration)
		expires = &exp
	}

	opts := CookieOptions{
		Name:     m.config.GuestCookieName,
		Value:    value,
		Expires:  expires,
		Path:     m.config.GuestCookiePath,
		Domain:   m.config.Domain,
		Secure:   m.config.GuestCookieSecure,
		HttpOnly: m.config.HttpOnly,
		SameSite: m.config.SameSite,
	}

	return m.SetCookie(w, opts)
}

// SetRefreshTokenCookie sets a refresh token cookie using the configured settings
func (m *Manager) SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	expires := customExpires
	if expires == nil {
		exp := time.Now().Add(m.config.Durations.RefreshTokenDuration)
		expires = &exp
	}

	path := m.config.RefreshTokenPath
	if path == "" && m.config.APIBaseRoute != "" {
		path = m.config.APIBaseRoute + "/auth/refresh"
	}

	opts := CookieOptions{
		Name:     m.config.RefreshTokenCookieName,
		Value:    value,
		Expires:  expires,
		Path:     path,
		Domain:   m.config.Domain,
		Secure:   m.config.RefreshTokenSecure,
		HttpOnly: m.config.RefreshTokenHttpOnly,
		SameSite: m.config.RefreshTokenSameSite,
	}

	return m.SetCookie(w, opts)
}

// SetSessionTokenCookie sets an access token cookie using the configured settings
func (m *Manager) SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error {
	expires := customExpires
	if expires == nil {
		exp := time.Now().Add(m.config.Durations.UserSessionDuration)
		expires = &exp
	}

	opts := CookieOptions{
		Name:     m.config.UserSessionCookieName,
		Value:    value,
		Expires:  expires,
		Path:     m.config.UserSessionCookiePath,
		Domain:   m.config.Domain,
		Secure:   m.config.UserSessionCookieSecure,
		HttpOnly: m.config.UserSessionCookieHttpOnly,
		SameSite: m.config.UserSessionCookieSameSite,
	}

	return m.SetCookie(w, opts)
}

// SetGenericCookie sets a cookie with a default duration and base security settings
func (m *Manager) SetGenericCookie(w http.ResponseWriter, name, value, path string, customExpires *time.Time) error {
	expires := customExpires
	if expires == nil {
		exp := time.Now().Add(m.config.Durations.DefaultCookieDuration)
		expires = &exp
	}

	opts := CookieOptions{
		Name:     name,
		Value:    value,
		Expires:  expires,
		Path:     path,
		Domain:   m.config.Domain,
		Secure:   m.config.GenericCookieSecure,
		HttpOnly: m.config.GenericCookieHttpOnly,
		SameSite: m.config.GenericCookieSameSite,
	}

	return m.SetCookie(w, opts)
}

// ClearCookie clears a cookie by setting it with an expired date
func (m *Manager) ClearCookie(w http.ResponseWriter, name, path string) error {
	past := time.Now().Add(-time.Hour)
	opts := CookieOptions{
		Name:    name,
		Value:   "",
		Expires: &past,
		Path:    path,
		Domain:  m.config.Domain,
		MaxAge:  intPtr(-1),
	}

	m.logger.Debug("clearing cookie", "name", name, "path", path)
	return m.SetCookie(w, opts)
}

// ClearGuestCookie clears the guest session cookie
func (m *Manager) ClearGuestCookie(w http.ResponseWriter) error {
	return m.ClearCookie(w, m.config.GuestCookieName, m.config.GuestCookiePath)
}

// ClearRefreshTokenCookie clears the refresh token cookie
func (m *Manager) ClearRefreshTokenCookie(w http.ResponseWriter) error {
	path := m.config.RefreshTokenPath
	if path == "" && m.config.APIBaseRoute != "" {
		path = m.config.APIBaseRoute + "/auth/refresh"
	}
	return m.ClearCookie(w, m.config.RefreshTokenCookieName, path)
}

// ClearAccessTokenCookie clears the access token cookie
func (m *Manager) ClearUserSessionCookie(w http.ResponseWriter) error {
	return m.ClearCookie(w, m.config.UserSessionCookieName, m.config.UserSessionCookiePath)
}

// GetCookie retrieves a cookie value by name from the request
func (m *Manager) GetCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		m.logger.Debug("cookie not found", "name", name, "error", err)
		return "", err
	}

	m.logger.Debug("cookie retrieved", "name", name)
	return cookie.Value, nil
}

// GetGuestCookie retrieves the guest session cookie value
func (m *Manager) GetGuestCookie(r *http.Request) (string, error) {
	return m.GetCookie(r, m.config.GuestCookieName)
}

// GetRefreshTokenCookie retrieves the refresh token cookie value
func (m *Manager) GetRefreshTokenCookie(r *http.Request) (string, error) {
	return m.GetCookie(r, m.config.RefreshTokenCookieName)
}

// GetUserSessionCookie retrieves the access token cookie value
func (m *Manager) GetUserSessionCookie(r *http.Request) (string, error) {
	return m.GetCookie(r, m.config.UserSessionCookieName)
}

// validateCookieOptions validates cookie options
func (m *Manager) validateCookieOptions(opts CookieOptions) error {
	if strings.TrimSpace(opts.Name) == "" {
		return ValidationError{Field: "name", Message: "cookie name cannot be empty"}
	}

	// Check for invalid characters in cookie name
	if strings.ContainsAny(opts.Name, " \t\r\n\013\014=;,") {
		return ValidationError{Field: "name", Message: "cookie name contains invalid characters"}
	}

	// Validate cookie value length (browsers typically limit to 4KB)
	if len(opts.Value) > 4096 {
		return ValidationError{Field: "value", Message: "cookie value too large (>4KB)"}
	}

	return nil
}

// UpdateDurations updates the duration configuration at runtime
func (m *Manager) UpdateDurations(durations DurationConfig) {
	m.config.Durations = durations
	m.logger.Info("cookie durations updated",
		"guestSession", durations.GuestSessionDuration,
		"refreshToken", durations.RefreshTokenDuration,
		"accessToken", durations.UserSessionDuration,
		"default", durations.DefaultCookieDuration)
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() CookieConfig {
	return *m.config
}

// newDefaultConfig returns a pointer to CookieConfig with the default options
func newDefaultConfig() *CookieConfig {
	return &CookieConfig{
		GuestStateEnabled: true,
		GuestCookieName:   "session_token",
		GuestCookieSecure: true,
		GuestCookiePath:   "/",

		RedirectOnAuthErrorPath: "/login",
		HttpOnly:                true,
		SameSite:                http.SameSiteLaxMode,

		RefreshTokenCookieName: "refresh_token",
		RefreshTokenPath:       "", // Will be constructed from APIBaseRoute if empty
		RefreshTokenSecure:     true,
		RefreshTokenHttpOnly:   true,
		RefreshTokenSameSite:   http.SameSiteStrictMode, // More restrictive for refresh tokens

		UserSessionCookieName:     "session_token",
		UserSessionCookiePath:     "/",
		UserSessionCookieSecure:   true,
		UserSessionCookieHttpOnly: true,
		UserSessionCookieSameSite: http.SameSiteLaxMode,

		GenericCookieSecure:   true,
		GenericCookieHttpOnly: true,
		GenericCookieSameSite: http.SameSiteLaxMode,

		EnableSecurityHeaders: true,
		Domain:                "", // Empty means current domain only

		Durations: DurationConfig{
			GuestSessionDuration:  24 * time.Hour,     // 24 hours for guest sessions
			RefreshTokenDuration:  7 * 24 * time.Hour, // 7 days for refresh tokens
			UserSessionDuration:   30 * time.Minute,   // 15 minutes for access tokens
			DefaultCookieDuration: 1 * time.Hour,      // 1 hour for generic cookies
		},
	}
}

// newInsecureDefaultConfig returns a pointer to CookieConfig with the insecure default options.
// It is intended to be used only in a development environment.
func newInsecureDefaultConfig() *CookieConfig {
	return &CookieConfig{
		GuestStateEnabled: true,
		GuestCookieName:   "session_token",
		GuestCookieSecure: false,
		GuestCookiePath:   "/",

		RedirectOnAuthErrorPath: "/login",
		HttpOnly:                false,
		SameSite:                http.SameSiteLaxMode,

		RefreshTokenCookieName: "refresh_token",
		RefreshTokenPath:       "",
		RefreshTokenSecure:     false,
		RefreshTokenHttpOnly:   false,
		RefreshTokenSameSite:   http.SameSiteLaxMode,

		UserSessionCookieName:     "session_token",
		UserSessionCookiePath:     "/",
		UserSessionCookieSecure:   false,
		UserSessionCookieHttpOnly: false,
		UserSessionCookieSameSite: http.SameSiteLaxMode,

		GenericCookieSecure:   false,
		GenericCookieHttpOnly: false,
		GenericCookieSameSite: http.SameSiteLaxMode,

		EnableSecurityHeaders: false,
		Domain:                "",

		Durations: DurationConfig{
			GuestSessionDuration:  24 * time.Hour,
			RefreshTokenDuration:  7 * 24 * time.Hour,
			UserSessionDuration:   1 * time.Hour,
			DefaultCookieDuration: 1 * time.Hour,
		},
	}
}

// Helper function to create int pointer
func intPtr(i int) *int {
	return &i
}

// NewDurationConfig creates a new duration configuration
func NewDurationConfig(guestSession, refreshToken, userSession, defaultDuration time.Duration) DurationConfig {
	return DurationConfig{
		GuestSessionDuration:  guestSession,
		RefreshTokenDuration:  refreshToken,
		UserSessionDuration:   userSession,
		DefaultCookieDuration: defaultDuration,
	}
}
