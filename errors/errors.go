package errors

import (
	"errors"
	"fmt"
)

// Common errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked due to too many failed login attempts")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token has expired")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrWeakPassword       = errors.New("password does not meet policy requirements")
	ErrPasswordMismatch   = errors.New("passwords do not match")
	ErrPasswordReused     = errors.New("password was recently used")
	ErrRateLimitExceeded  = errors.New("rate limit exceeded")
	ErrInvalidInput       = errors.New("invalid input")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrInternalServer     = errors.New("internal server error")
)

// ValidationError represents a validation error with field details
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
	}
}

// PasswordPolicyError represents a password policy error
type PasswordPolicyError struct {
	Violations []string
}

func (e PasswordPolicyError) Error() string {
	if len(e.Violations) == 1 {
		return e.Violations[0]
	}
	return fmt.Sprintf("password policy violations: %v", e.Violations)
}

// NewPasswordPolicyError creates a new password policy error
func NewPasswordPolicyError(violations ...string) PasswordPolicyError {
	return PasswordPolicyError{
		Violations: violations,
	}
}
