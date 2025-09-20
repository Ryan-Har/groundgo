package store

import (
	"database/sql"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestConfigValidateAndSetDefaults_AppliesDefaults(t *testing.T) {
	logger := slog.Default()

	cfg := &StoreConfig{
		Logger:           logger,
		DBType:           DBTypeSQLite,
		JWTSigningSecret: "secret",
	}

	// Provide a fake DB pointer just to satisfy required field
	cfg.DB = &sql.DB{}

	if err := cfg.validateAndSetDefaults(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.TokenLength != 32 {
		t.Errorf("expected TokenLength default 32, got %d", cfg.TokenLength)
	}
	if cfg.TokenDuration != 30*time.Minute {
		t.Errorf("expected TokenDuration default 30m, got %v", cfg.TokenDuration)
	}
	if cfg.CookiestoreGuestSessionDuration != 24*time.Hour {
		t.Errorf("expected CookiestoreGuestSessionDuration 24h, got %v", cfg.CookiestoreGuestSessionDuration)
	}
	if cfg.CookiestoreGenericCookieDuration != time.Hour {
		t.Errorf("expected CookiestoreGenericCookieDuration 1h, got %v", cfg.CookiestoreGenericCookieDuration)
	}
	if cfg.SessionDuration != 30*time.Minute {
		t.Errorf("expected SessionDuration 30m, got %v", cfg.SessionDuration)
	}
	if cfg.RefreshTokenDuration != 7*24*time.Hour {
		t.Errorf("expected RefreshTokenDuration 7d, got %v", cfg.RefreshTokenDuration)
	}
}

func TestConfigValidateAndSetDefaults_RequiredFieldsMissing(t *testing.T) {
	cfg := &StoreConfig{}

	err := cfg.validateAndSetDefaults()
	if err == nil {
		t.Fatal("expected error for missing required fields, got nil")
	}

	expectedErrors := []string{
		"logger must be provided",
	}

	found := false
	for _, e := range expectedErrors {
		if errors.Is(err, errors.New(e)) || err.Error() == e {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected one of %v, got %v", expectedErrors, err)
	}
}

func TestConfigValidateAndSetDefaults_PreservesProvidedValues(t *testing.T) {
	logger := slog.Default()

	cfg := &StoreConfig{
		Logger:                           logger,
		DBType:                           DBTypeSQLite,
		JWTSigningSecret:                 "secret",
		TokenLength:                      64,
		TokenDuration:                    15 * time.Minute,
		CookiestoreGuestSessionDuration:  12 * time.Hour,
		CookiestoreGenericCookieDuration: 30 * time.Minute,
		SessionDuration:                  45 * time.Minute,
		RefreshTokenDuration:             10 * 24 * time.Hour,
	}

	cfg.DB = &sql.DB{}

	if err := cfg.validateAndSetDefaults(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.TokenLength != 64 {
		t.Errorf("expected TokenLength 64, got %d", cfg.TokenLength)
	}
	if cfg.TokenDuration != 15*time.Minute {
		t.Errorf("expected TokenDuration 15m, got %v", cfg.TokenDuration)
	}
	if cfg.CookiestoreGuestSessionDuration != 12*time.Hour {
		t.Errorf("expected CookiestoreGuestSessionDuration 12h, got %v", cfg.CookiestoreGuestSessionDuration)
	}
	if cfg.CookiestoreGenericCookieDuration != 30*time.Minute {
		t.Errorf("expected CookiestoreGenericCookieDuration 30m, got %v", cfg.CookiestoreGenericCookieDuration)
	}
	if cfg.SessionDuration != 45*time.Minute {
		t.Errorf("expected SessionDuration 45m, got %v", cfg.SessionDuration)
	}
	if cfg.RefreshTokenDuration != 10*24*time.Hour {
		t.Errorf("expected RefreshTokenDuration 10d, got %v", cfg.RefreshTokenDuration)
	}
}
