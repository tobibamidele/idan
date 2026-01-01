package sqlite

import (
	"context"
	"fmt"
)

// RunMigrations creates all necessary tables for the authentication system
func (s *SQLiteStore) RunMigrations(ctx context.Context) error {
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
	id TEXT PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	email_verified INTEGER DEFAULT 0,
	email_verified_at DATETIME,
	verification_token TEXT,
	failed_login_attempts INTEGER DEFAULT 0,
	locked_until DATETIME,
	last_login_at DATETIME,
	last_login_ip TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	name TEXT,
	profile_picture TEXT,
	two_factor_enabled INTEGER DEFAULT 0,
	two_factor_secret TEXT
);
`

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	token TEXT UNIQUE NOT NULL,
	ip_address TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	remember_me INTEGER DEFAULT 0,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL,
	last_seen_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`

const createPasswordResetTokensTable = `
CREATE TABLE IF NOT EXISTS password_reset_tokens (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	token TEXT UNIQUE NOT NULL,
	expires_at DATETIME NOT NULL,
	used INTEGER DEFAULT 0,
	created_at DATETIME NOT NULL,
	used_at DATETIME,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`

const createPasswordHistoryTable = `
CREATE TABLE IF NOT EXISTS password_history (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`

const createIndexes = `
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
`