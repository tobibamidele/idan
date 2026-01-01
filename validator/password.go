package validator

import (
	"strings"
	"unicode"

	"github.com/tobibamidele/idan/config"
	"github.com/tobibamidele/idan/errors"
)

var CommonPasswords = map[string]bool{
	"password": true,
	"123456":   true,
	"12345678": true,
	"qwerty":   true,
	"abc123":   true,
	"monkey":   true,
	"1234567":  true,
	"letmein":  true,
	"trustno1": true,
	"dragon":   true,
	"baseball": true,
	"111111":   true,
	"iloveyou": true,
	"master":   true,
	"sunshine": true,
	"ashley":   true,
	"bailey":   true,
	"passw0rd": true,
	"shadow":   true,
	"123123":   true,
	"654321":   true,
	"superman": true,
	"qazwsx":   true,
	"michael":  true,
	"football": true,
}

// PasswordValidator validates passwords against a policy
type PasswordValidator struct {
	policy config.PasswordPolicy
}

// NewPasswordValidator creates a new password validator with the given policy
func NewPasswordValidator(policy config.PasswordPolicy) *PasswordValidator {
	return &PasswordValidator{
		policy: policy,
	}
}

// Validate validates a password against the configured policy
func (v *PasswordValidator) Validate(password string) error {
	var violations []string

	// Check length
	if len(password) < v.policy.MinLength {
		violations = append(violations, "password must be at least "+string(rune(v.policy.MinLength))+" characters long")
	}
	if v.policy.MaxLength > 0 && len(password) > v.policy.MaxLength {
		violations = append(violations, "password must not exceed "+string(rune(v.policy.MaxLength))+" characters")
	}

	// Check for uppercase
	if v.policy.RequireUppercase && !hasUppercase(password) {
		violations = append(violations, "password must contain at least one uppercase letter")
	}

	// Check for lowercase
	if v.policy.RequireLowercase && !hasLowercase(password) {
		violations = append(violations, "password must contain at least one lowercase letter")
	}

	// Check for number
	if v.policy.RequireNumber && !hasNumber(password) {
		violations = append(violations, "password must contain at least one number")
	}

	// Check for special character
	if v.policy.RequireSpecial && !hasSpecialChar(password, v.policy.SpecialChars) {
		violations = append(violations, "password must contain at least one special character")
	}

	// Check for common passwords
	if v.policy.PreventCommon && isCommonPassword(password) {
		violations = append(violations, "password is too common, please choose a more unique password")
	}

	if len(violations) > 0 {
		return errors.NewPasswordPolicyError(violations...)
	}

	return nil
}

// hasUppercase checks if string contains at least one uppercase letter
func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// hasLowercase checks if string contains at least one lowercase letter
func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

// hasNumber checks if string contains at least one digit
func hasNumber(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// hasSpecialChar checks if string contains at least one special character from allowed set
func hasSpecialChar(s, allowedChars string) bool {
	if allowedChars == "" {
		// If no specific chars specified, check for any non-alphanumeric
		for _, r := range s {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return true
			}
		}
		return false
	}

	// Check for specific allowed special characters
	for _, r := range s {
		if strings.ContainsRune(allowedChars, r) {
			return true
		}
	}
	return false
}

// isCommonPassword checks if password is in the common passwords list
func isCommonPassword(password string) bool {
	return CommonPasswords[strings.ToLower(password)]
}
