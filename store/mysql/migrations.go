package mysql

import (
	"context"
	"fmt"
)

// RunMigrations creates all necessary tables for the authentication system
func (s *MySQLStore) RunMigrations(ctx context.Context) error {
	migrations := []string{
		createUsersTable,
		createSessionsTable,
		createPasswordResetTokensTable,
		createPasswordHistoryTable,
		createIndexes,
	}

	for i, migration := range migrations {
		if _, err := s.db.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	return nil
}

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(255) PRIMARY KEY,
	email VARCHAR(255) UNIQUE NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	email_verified BOOLEAN DEFAULT FALSE,
	email_verified_at DATETIME,
	verification_token VARCHAR(255),
	failed_login_attempts INT DEFAULT 0,
	locked_until DATETIME,
	last_login_at DATETIME,
	last_login_ip VARCHAR(45),
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	name VARCHAR(255),
	profile_picture TEXT,
	two_factor_enabled BOOLEAN DEFAULT FALSE,
	two_factor_secret VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
	id VARCHAR(255) PRIMARY KEY,
	user_id VARCHAR(255) NOT NULL,
	token VARCHAR(255) UNIQUE NOT NULL,
	ip_address VARCHAR(45) NOT NULL,
	user_agent TEXT NOT NULL,
	remember_me BOOLEAN DEFAULT FALSE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL,
	last_seen_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_sessions_user_id (user_id),
	INDEX idx_sessions_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

const createPasswordResetTokensTable = `
CREATE TABLE IF NOT EXISTS password_reset_tokens (
	id VARCHAR(255) PRIMARY KEY,
	user_id VARCHAR(255) NOT NULL,
	token VARCHAR(255) UNIQUE NOT NULL,
	expires_at DATETIME NOT NULL,
	used BOOLEAN DEFAULT FALSE,
	created_at DATETIME NOT NULL,
	used_at DATETIME,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_password_reset_tokens_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

const createPasswordHistoryTable = `
CREATE TABLE IF NOT EXISTS password_history (
	id VARCHAR(255) PRIMARY KEY,
	user_id VARCHAR(255) NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	created_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	INDEX idx_password_history_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

const createIndexes = `
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
`
