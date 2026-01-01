package validator

import (
	"net/mail"
	"strings"

	"github.com/tobibamidele/idan/errors"
)

// ValidateEmail validates a given email address according to RFC 5322
func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.NewValidationError("email", "email is required")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.ErrInvalidEmail
	}
	return nil
}

// ValidateRequired checks if a string field is not empty
func ValidateRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.NewValidationError(field, field+" is required")
	}
	return nil
}

// ValidateLength check is a string is within specified length bounds
func ValidateLength(field, value string, max, min int) error {
	length := len(value)
	if min > 0 && length < min {
		return errors.NewValidationError(field, field+" must be at least "+string(rune(min))+" characters")
	}
	if max > 0 && length > max {

		return errors.NewValidationError(field, field+" must not exceed "+string(rune(max))+" characters")
	}

	return nil
}

// Validator validates common user input structs
type Validator struct{}

// New creates a new validator
func New() *Validator {
	return &Validator{}
}
