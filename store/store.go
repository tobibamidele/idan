package store

import (
	"context"
	"time"

	"github.com/tobibamidele/idan/models"
)

// Store defines the interfeace for data persistence
// All database implementations must implement this interface
type Store interface {
	// Close closes the database connection
	Close() error

	// RunMigrations runs database migrations
	RunMigrations(ctx context.Context) error

	// User operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	IncrementFailedLogins(ctx context.Context, userID string) error
	ResetFailedLogins(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string, until *time.Time) error

	// Session operations
	CreateSession(ctx context.Context, session *models.Session) error
	GetSessionByToken(ctx context.Context, token string) (*models.Session, error)
	GetUserSessions(ctx context.Context, userID string) ([]*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSession(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Password reset operations
	CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, token string) error
	DeletePasswordResetToken(ctx context.Context, token string) error
	DeleteUserPasswordResetTokens(ctx context.Context, userID string) error

	// Password history operations (for password reuse prevention)
	AddPasswordHistory(ctx context.Context, userID, passwordHash string) error
	GetPasswordHistory(ctx context.Context, userID string, limit int) ([]*models.PasswordHistory, error)
	DeleteOldPasswordHistory(ctx context.Context, userID string, keepCount int) error
}
