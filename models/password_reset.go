package models

import "time"

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string     `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`
	Token     string     `json:"token" db:"token"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	Used      bool       `json:"used" db:"used"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
}

// IsExpired checks if the reset token has expired
func (t *PasswordResetToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if the token is valid (not used and not expired)
func (t *PasswordResetToken) IsValid() bool {
	return !t.Used && !t.IsExpired()
}

// PasswordResetRequest represents a request to reset password
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordResetConfirmRequest represents the actual password reset
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
