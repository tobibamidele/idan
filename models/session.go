package models

import "time"

// Session represents an active user session
type Session struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	Token      string    `json:"token" db:"token"` // Session token (stored as a cookie)
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	RememberMe bool      `json:"remember_me" db:"remember_me"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at" db:"last_seen_at"`
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if a session is valid
func (s *Session) IsValid() bool {
	return !s.IsExpired()
}
