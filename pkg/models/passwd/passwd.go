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

// IsHashed checks if a given password string appears to be a bcrypt hash.
// This is a simple sanity check to prevent storing plaintext passwords in the database.
//
// It verifies two things:
// 1. Length: bcrypt hashes are always 60 characters long.
// 2. Prefix: bcrypt hashes start with "$2a$", "$2b$", or "$2y$".
//
// Returns true if the string looks like a valid bcrypt hash, false otherwise.
//
// Note:
// This check is not cryptographically guaranteed — it only validates the string format.
// A string could theoretically match the length and prefix without being a true bcrypt hash.
// However, for the purpose of preventing accidental storage of plaintext passwords,
// this is sufficient as a final safety check before writing to the database.
func IsHashed(password string) bool {
	if len(password) != 60 {
		return false
	}
	switch password[:4] {
	case "$2a$", "$2b$", "$2y$":
		return true
	default:
		return false
	}
}
