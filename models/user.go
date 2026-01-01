package models

import "time"

// User represents a user in the system
type User struct {
	ID                  string     `json:"id" db:"id"`
	Email               string     `json:"email" db:"email"`
	PasswordHash        string     `json:"-" db:"password_hash"`
	EmailVerified       bool       `json:"email_verified" db:"email_verified"`
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty" db:"email_verified_at"`
	VerificationToken   *string    `json:"-" db:"verification_token"` // Token for email verification
	FailedLoginAttempts int        `json:"-" db:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP         *string    `json:"-" db:"last_login_ip"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`

	// Optional fields for extra functionality
	Name             *string `json:"name,omitempty" db:"name"`
	ProfilePicture   *string `json:"profile_picture,omitempty" db:"profile_picture"`
	TwoFactorEnabled bool    `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret  *string `json:"-" db:"two_factor_secret"`
}

// IsLocked checks if the user account is current locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// CanLogin checks if the user can attempt to login
func (u *User) CanLogin() bool {
	return !u.IsLocked()
}

// PasswordHistory represents the previous passwords for reuse prevention
type PasswordHistory struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// CreateUserRequest represents the data needed to create a user
type CreateUserRequest struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

// LoginRequest represents the login creds
type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

// UpdateUserRequest represents the data for updating a user
type UpdateUserRequest struct {
	Name           *string `json:"name,omitempty"`
	ProfilePicture *string `json:"profile_picture,omitempty"`
}

// ChangePasswordRequest repreents password change data
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// UserResponse describes what gets returned to the client
type UserResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	EmailVerified   bool       `json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	CreatedAt       time.Time  `json:"'created_at"`
	Name            *string    `json:"name,omitempty"`
	ProfilePicture  *string    `json:"profile_picture,omitempty"`
}

// ToResponse converts a User to a UserResponse
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:              u.ID,
		Email:           u.Email,
		EmailVerified:   u.EmailVerified,
		EmailVerifiedAt: u.EmailVerifiedAt,
		LastLoginAt:     u.LastLoginAt,
		CreatedAt:       u.CreatedAt,
		Name:            u.Name,
		ProfilePicture:  u.ProfilePicture,
	}
}
