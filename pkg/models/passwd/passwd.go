package passwd

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// Constants for cost and max password length (bcrypt truncates after 72 bytes)
const (
	DefaultCost    = 12 // Usually 10
	MaxPasswordLen = 72 // bcrypt input limit
)

// HashPassword hashes a password using bcrypt with the DefaultCost
func HashPassword(password string) (string, error) {
	// Warn or reject overly long passwords
	if len(password) > MaxPasswordLen {
		return "", errors.New("password exceeds 72 bytes and will be truncated by bcrypt")
	}

	// Generate the hash
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

// CheckPasswordHash compares a plaintext password with a bcrypt hashed password.
// Returns true if they match, false otherwise.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Authenticate verifies whether the input password matches the stored bcrypt hash.
// Returns true if authentication is successful.
func Authenticate(inputPassword, storedHash string) bool {
	return CheckPasswordHash(inputPassword, storedHash)
}
