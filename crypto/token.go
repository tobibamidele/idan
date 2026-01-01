package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateToken returns a cryptographically secure random token
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateSessionToken creates a token for session identification
func GenerateSessionToken() (string, error) {
	return GenerateToken(32)
}

// GenerateVerificationToken generates a token for email verification
func GenerateVerificationToken() (string, error) {
	return GenerateToken(32)
}

// GeneratePasswordTokenLength geenerates a token for password reset
func GeneratePasswordTokenLength() (string, error) {
	return GenerateToken(32)
}

// GenerateCSRFToken generates a CSRF token
func GenerateCSRFToken(length int) (string, error) {
	if length < 16 {
		length = 16 // Minimum length for security
	}
	return GenerateToken(length)
}
