package passwd

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{"Valid password", "mysecretpassword", false},
		{"Password exceeding MaxPasswordLen", strings.Repeat("a", MaxPasswordLen+1), true},
		{"Empty password", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashed, err := HashPassword(tt.password)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hashed == "" {
				t.Error("hashed password is empty")
			}

			// Validate the hash
			if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(tt.password)) != nil {
				t.Errorf("hashed password does not match original")
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedEmptyPassword, _ := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)

	tests := []struct {
		name     string
		password string
		hash     string
		expected bool
	}{
		{"Correct password", password, string(hashedPassword), true},
		{"Incorrect password", "wrongpassword", string(hashedPassword), false},
		{"Empty password with empty hash", "", string(hashedEmptyPassword), true},
		{"Empty password with non-empty hash", "", string(hashedPassword), false},
		{"Invalid hash format", password, "thisisnotavalidhash", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckPasswordHash(tt.password, tt.hash)
			if got != tt.expected {
				t.Errorf("CheckPasswordHash(%q, %q) = %v, want %v", tt.password, tt.hash, got, tt.expected)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	password := "securestring"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedEmptyPassword, _ := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)

	tests := []struct {
		name           string
		inputPassword  string
		storedHash     string
		expectedResult bool
	}{
		{"Correct password", password, string(hashedPassword), true},
		{"Incorrect password", "incorrect", string(hashedPassword), false},
		{"Empty password and hash", "", string(hashedEmptyPassword), true},
		{"Empty input password, non-empty hash", "", string(hashedPassword), false},
		{"Valid password with invalid stored hash", password, "malformedhash", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Authenticate(tt.inputPassword, tt.storedHash)
			if got != tt.expectedResult {
				t.Errorf("Authenticate(%q, %q) = %v, want %v", tt.inputPassword, tt.storedHash, got, tt.expectedResult)
			}
		})
	}
}

func TestIsHashed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid $2a$ hash",
			input:    "$2a$12$" + strings.Repeat("a", 53), // 60 chars
			expected: true,
		},
		{
			name:     "Valid $2b$ hash",
			input:    "$2b$12$" + strings.Repeat("a", 53),
			expected: true,
		},
		{
			name:     "Valid $2y$ hash",
			input:    "$2y$12$" + strings.Repeat("a", 53),
			expected: true,
		},
		{
			name:     "Invalid prefix",
			input:    "$2x$12$" + strings.Repeat("a", 53),
			expected: false,
		},
		{
			name:     "Too short",
			input:    "$2a$12$short",
			expected: false,
		},
		{
			name:     "Too long",
			input:    "$2a$12$" + strings.Repeat("a", 100),
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Random string 60 chars",
			input:    strings.Repeat("x", 60),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHashed(tt.input)
			if got != tt.expected {
				t.Errorf("IsHashed(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
