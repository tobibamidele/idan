package config

// PasswordPolicy defines the rules for password validation
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int // Maximum password length (0 = no limit)
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
	SpecialChars     string // Allowed special characters
	PreventCommon    bool   // Prevent commonly used passwords
	PreventReuse     int    // Prevent reusing last N passwords (0 = disabled)
}

// DefaultPasswordPolicy returns a secure default password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
		SpecialChars:     "!@#$%^&*()_+[]{}|;:,.<>?",
		PreventCommon:    true,
		PreventReuse:     3,
	}
}

// WeakPasswordPolicy returns a very lenient password policy (not recommended for production, use mostly for testing)
func WeakPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        6,
		MaxLength:        128,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumber:    false,
		RequireSpecial:   false,
		SpecialChars:     "",
		PreventCommon:    false,
		PreventReuse:     0,
	}
}

// StrongPasswordPolicy returns a very strict password policy
func StrongPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
		SpecialChars:     "!@#$%^&*()_+[]{}|;:,.<>?",
		PreventCommon:    true,
		PreventReuse:     5,
	}
}
