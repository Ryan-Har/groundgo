package models

import (
	"testing"

	"github.com/google/uuid"
)

func TestCreateUserParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  CreateUserParams
		wantErr bool
	}{
		{"missing email", CreateUserParams{Password: strPtr("pass")}, true},
		{"invalid email", CreateUserParams{Email: "not-an-email", Password: strPtr("pass")}, true},
		{"missing password", CreateUserParams{Email: "test@example.com"}, true},
		{"valid", CreateUserParams{Email: "test@example.com", Password: strPtr("pass")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewGuestUser(t *testing.T) {
	user := NewGuestUser()
	if user.ID != uuid.Nil {
		t.Errorf("expected uuid.Nil, got %v", user.ID)
	}
	if role, ok := user.Claims["/"]; !ok || role != RoleGuest {
		t.Errorf("expected Claims['/'] = RoleGuest, got %v", role)
	}
}

func TestUpdateUserByIDParams_Verify(t *testing.T) {
	validID := uuid.New()

	t.Run("missing ID", func(t *testing.T) {
		u := &UpdateUserByIDParams{}
		if err := u.Verify(); err == nil {
			t.Error("expected error for missing ID")
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		email := "invalid"
		u := &UpdateUserByIDParams{ID: validID, Email: &email}
		if err := u.Verify(); err == nil {
			t.Error("expected error for invalid email")
		}
	})

	t.Run("claims should remove root role", func(t *testing.T) {
		claims := Claims{"/": RoleAdmin, "foo": RoleUser}
		u := &UpdateUserByIDParams{ID: validID, Claims: &claims}
		_ = u.Verify()
		if _, exists := claims["/"]; exists {
			t.Error("expected root claim '/' to be removed")
		}
	})

	t.Run("password should be hashed", func(t *testing.T) {
		pwd := "secret"
		u := &UpdateUserByIDParams{ID: validID, Password: &pwd}
		if err := u.Verify(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if *u.Password == pwd {
			t.Error("expected password to be hashed, got same value")
		}
	})

	t.Run("oauth not implemented", func(t *testing.T) {
		oid := "oauth-id"
		u := &UpdateUserByIDParams{ID: validID, OauthID: &oid}
		if err := u.Verify(); err == nil {
			t.Error("expected error for oauth fields")
		}
	})
}

func TestGetPaginatedUsersParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  GetPaginatedUsersParams
		wantErr bool
	}{
		{"page < 1", GetPaginatedUsersParams{Page: 0, Limit: 10}, true},
		{"limit < 1", GetPaginatedUsersParams{Page: 1, Limit: 0}, true},
		{"limit > 100", GetPaginatedUsersParams{Page: 1, Limit: 101}, true},
		{"valid", GetPaginatedUsersParams{Page: 1, Limit: 10}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUser_EnsureRootClaim(t *testing.T) {
	user := &User{Role: RoleAdmin, Claims: Claims{"foo": RoleUser}}
	user.EnsureRootClaim()
	if role, ok := user.Claims["/"]; !ok || role != RoleAdmin {
		t.Errorf("expected root claim to be set to RoleAdmin, got %v", role)
	}
}

func TestSessionStruct(t *testing.T) {
	s := Session{
		ID:     "session-id",
		UserID: uuid.New(),
	}
	if s.ID == "" || s.UserID == uuid.Nil {
		t.Error("expected valid session fields")
	}
}

// helper
func strPtr(s string) *string { return &s }
