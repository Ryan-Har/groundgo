package passwd

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	// Test case 1: Valid password
	password := "mysecretpassword"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error for valid password: %v", err)
	}
	if hashedPassword == "" {
		t.Error("HashPassword returned an empty string for valid password")
	}

	// Verify the hash (we can't decrypt, but we can check if it's a valid bcrypt hash)
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Errorf("Hashed password does not match original password: %v", err)
	}

	// Test case 2: Password exceeding MaxPasswordLen
	longPassword := strings.Repeat("a", MaxPasswordLen+1) // 73 characters
	_, err = HashPassword(longPassword)
	if err == nil {
		t.Error("HashPassword did not return an error for overly long password")
	}
	expectedErr := errors.New("password exceeds 72 bytes and will be truncated by bcrypt")
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', got '%v' for overly long password", expectedErr, err)
	}

	// Test case 3: Empty password (bcrypt handles this)
	emptyPassword := ""
	hashedEmptyPassword, err := HashPassword(emptyPassword)
	if err != nil {
		t.Fatalf("HashPassword returned an error for empty password: %v", err)
	}
	if hashedEmptyPassword == "" {
		t.Error("HashPassword returned an empty string for empty password")
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedEmptyPassword), []byte(emptyPassword))
	if err != nil {
		t.Errorf("Hashed empty password does not match original empty password: %v", err)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	// Generate a valid hash for testing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash for testing: %v", err)
	}

	// Test case 1: Correct password and hash
	if !CheckPasswordHash(password, string(hashedPassword)) {
		t.Error("CheckPasswordHash returned false for correct password and hash")
	}

	// Test case 2: Incorrect password
	incorrectPassword := "wrongpassword"
	if CheckPasswordHash(incorrectPassword, string(hashedPassword)) {
		t.Error("CheckPasswordHash returned true for incorrect password")
	}

	// Test case 3: Empty password and hash
	emptyPassword := ""
	hashedEmptyPassword, err := bcrypt.GenerateFromPassword([]byte(emptyPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash for empty password for testing: %v", err)
	}
	if !CheckPasswordHash(emptyPassword, string(hashedEmptyPassword)) {
		t.Error("CheckPasswordHash returned false for empty password and hash")
	}

	// Test case 4: Empty password with non-empty hash (should fail)
	if CheckPasswordHash(emptyPassword, string(hashedPassword)) {
		t.Error("CheckPasswordHash returned true for empty password and non-empty hash")
	}

	// Test case 5: Invalid hash format (should fail)
	invalidHash := "thisisnotavalidhash"
	if CheckPasswordHash(password, invalidHash) {
		t.Error("CheckPasswordHash returned true for invalid hash format")
	}
}

func TestAuthenticate(t *testing.T) {
	password := "securestring"
	// Generate a valid hash for testing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash for testing: %v", err)
	}

	// Test case 1: Correct password and hash
	if !Authenticate(password, string(hashedPassword)) {
		t.Error("Authenticate returned false for correct input and stored hash")
	}

	// Test case 2: Incorrect password
	incorrectPassword := "incorrect"
	if Authenticate(incorrectPassword, string(hashedPassword)) {
		t.Error("Authenticate returned true for incorrect input password")
	}

	// Test case 3: Empty password and hash (should pass if both are empty and valid bcrypt)
	emptyPassword := ""
	hashedEmptyPassword, err := bcrypt.GenerateFromPassword([]byte(emptyPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash for empty password for testing: %v", err)
	}
	if !Authenticate(emptyPassword, string(hashedEmptyPassword)) {
		t.Error("Authenticate returned false for empty password and hash")
	}

	// Test case 4: Empty input password with non-empty stored hash (should fail)
	if Authenticate(emptyPassword, string(hashedPassword)) {
		t.Error("Authenticate returned true for empty input password and non-empty stored hash")
	}

	// Test case 5: Valid input password with invalid stored hash (should fail)
	invalidHash := "malformedhash"
	if Authenticate(password, invalidHash) {
		t.Error("Authenticate returned true for valid input password and invalid stored hash")
	}
}
