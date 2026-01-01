package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/tobibamidele/idan/errors"
	"github.com/tobibamidele/idan/models"
)

// MySQLStore implements the Store interface for MySQL
type MySQLStore struct {
	db *sql.DB
}

// New creates a new MySQL store
func New(connectionURL string, maxOpenConns, maxIdleConns int, connMaxLife time.Duration) (*MySQLStore, error) {
	db, err := sql.Open("mysql", connectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLife)

	// Test the connection
	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &MySQLStore{db: db}, nil
}

// Close closes the database connection
func (s *MySQLStore) Close() error {
	return s.db.Close()
}

// CreateUser creates a new user
func (s *MySQLStore) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (
			id, email, password_hash, email_verified, verification_token,
			failed_login_attempts, created_at, updated_at, name, two_factor_enabled
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.EmailVerified,
		user.VerificationToken, user.FailedLoginAttempts,
		user.CreatedAt, user.UpdatedAt, user.Name, user.TwoFactorEnabled,
	)

	if err != nil {
		// Check for unique constraint violation
		if isUniqueViolation(err) {
			return errors.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByID retrieves a user by ID
func (s *MySQLStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, email_verified_at,
			verification_token, failed_login_attempts, locked_until,
			last_login_at, last_login_ip, created_at, updated_at,
			name, profile_picture, two_factor_enabled, two_factor_secret
		FROM users WHERE id = ?
	`

	var user models.User
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified,
		&user.EmailVerifiedAt, &user.VerificationToken, &user.FailedLoginAttempts,
		&user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP,
		&user.CreatedAt, &user.UpdatedAt, &user.Name, &user.ProfilePicture,
		&user.TwoFactorEnabled, &user.TwoFactorSecret,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email (case-insensitive)
func (s *MySQLStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, email_verified_at,
			verification_token, failed_login_attempts, locked_until,
			last_login_at, last_login_ip, created_at, updated_at,
			name, profile_picture, two_factor_enabled, two_factor_secret
		FROM users WHERE LOWER(email) = LOWER(?)
	`

	var user models.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified,
		&user.EmailVerifiedAt, &user.VerificationToken, &user.FailedLoginAttempts,
		&user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP,
		&user.CreatedAt, &user.UpdatedAt, &user.Name, &user.ProfilePicture,
		&user.TwoFactorEnabled, &user.TwoFactorSecret,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (s *MySQLStore) UpdateUser(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET
			email = ?, password_hash = ?, email_verified = ?,
			email_verified_at = ?, verification_token = ?,
			failed_login_attempts = ?, locked_until = ?,
			last_login_at = ?, last_login_ip = ?, updated_at = ?,
			name = ?, profile_picture = ?, two_factor_enabled = ?,
			two_factor_secret = ?
		WHERE id = ?
	`

	user.UpdatedAt = time.Now()

	result, err := s.db.ExecContext(ctx, query,
		user.Email, user.PasswordHash, user.EmailVerified,
		user.EmailVerifiedAt, user.VerificationToken,
		user.FailedLoginAttempts, user.LockedUntil, user.LastLoginAt,
		user.LastLoginIP, user.UpdatedAt, user.Name, user.ProfilePicture,
		user.TwoFactorEnabled, user.TwoFactorSecret, user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return errors.ErrUserNotFound
	}

	return nil
}

// DeleteUser deletes a user
func (s *MySQLStore) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return errors.ErrUserNotFound
	}

	return nil
}

// IncrementFailedLogins increments failed login attempts
func (s *MySQLStore) IncrementFailedLogins(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
			updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), userID)
	return err
}

// ResetFailedLogins resets failed login attempts to 0
func (s *MySQLStore) ResetFailedLogins(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), userID)
	return err
}

// LockUser locks a user account until specified time
func (s *MySQLStore) LockUser(ctx context.Context, userID string, until *time.Time) error {
	query := `
		UPDATE users
		SET locked_until = ?,
			updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.ExecContext(ctx, query, until, time.Now(), userID)
	return err
}

// Session operations

// CreateSession creates a new session
func (s *MySQLStore) CreateSession(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.Token, session.IPAddress,
		session.UserAgent, session.RememberMe, session.ExpiresAt,
		session.CreatedAt, session.LastSeenAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSessionByToken retrieves a session by token
func (s *MySQLStore) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		FROM sessions WHERE token = ?
	`

	var session models.Session
	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID, &session.UserID, &session.Token, &session.IPAddress,
		&session.UserAgent, &session.RememberMe, &session.ExpiresAt,
		&session.CreatedAt, &session.LastSeenAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// GetUserSessions retrieves all active sessions for a user
func (s *MySQLStore) GetUserSessions(ctx context.Context, userID string) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		FROM sessions
		WHERE user_id = ? AND expires_at > ?
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		var session models.Session
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Token, &session.IPAddress,
			&session.UserAgent, &session.RememberMe, &session.ExpiresAt,
			&session.CreatedAt, &session.LastSeenAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &session)
	}

	return sessions, nil
}

// UpdateSession updates a session
func (s *MySQLStore) UpdateSession(ctx context.Context, session *models.Session) error {
	query := `
		UPDATE sessions SET
			last_seen_at = ?,
			expires_at = ?
		WHERE token = ?
	`

	_, err := s.db.ExecContext(ctx, query, session.LastSeenAt, session.ExpiresAt, session.Token)
	return err
}

// DeleteSession deletes a session
func (s *MySQLStore) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

// DeleteUserSessions deletes all sessions for a user
func (s *MySQLStore) DeleteUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// DeleteExpiredSessions deletes expired sessions
func (s *MySQLStore) DeleteExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < ?`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	return err
}

// Password reset operations

// CreatePasswordResetToken creates a new password reset token
func (s *MySQLStore) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (
			id, user_id, token, expires_at, used, created_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Token, token.ExpiresAt,
		token.Used, token.CreatedAt,
	)

	return err
}

// GetPasswordResetToken retrieves a password reset token
func (s *MySQLStore) GetPasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used, created_at, used_at
		FROM password_reset_tokens WHERE token = ?
	`

	var resetToken models.PasswordResetToken
	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&resetToken.ID, &resetToken.UserID, &resetToken.Token,
		&resetToken.ExpiresAt, &resetToken.Used, &resetToken.CreatedAt,
		&resetToken.UsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	return &resetToken, nil
}

// MarkPasswordResetTokenUsed marks a token as used
func (s *MySQLStore) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	query := `UPDATE password_reset_tokens SET used = 1, used_at = ? WHERE token = ?`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, now, token)
	return err
}

// DeletePasswordResetToken deletes a token
func (s *MySQLStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	query := `DELETE FROM password_reset_tokens WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

// DeleteUserPasswordResetTokens deletes all reset tokens for a user
func (s *MySQLStore) DeleteUserPasswordResetTokens(ctx context.Context, userID string) error {
	query := `DELETE FROM password_reset_tokens WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// Password history operations

// AddPasswordHistory adds a password to history
func (s *MySQLStore) AddPasswordHistory(ctx context.Context, userID, passwordHash string) error {
	query := `
		INSERT INTO password_history (id, user_id, password_hash, created_at)
		VALUES (?, ?, ?, ?)
	`

	id := fmt.Sprintf("%s_%d", userID, time.Now().Unix())
	_, err := s.db.ExecContext(ctx, query, id, userID, passwordHash, time.Now())
	return err
}

// GetPasswordHistory retrieves password history for a user
func (s *MySQLStore) GetPasswordHistory(ctx context.Context, userID string, limit int) ([]*models.PasswordHistory, error) {
	query := `
		SELECT id, user_id, password_hash, created_at
		FROM password_history
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*models.PasswordHistory
	for rows.Next() {
		var ph models.PasswordHistory
		err := rows.Scan(&ph.ID, &ph.UserID, &ph.PasswordHash, &ph.CreatedAt)
		if err != nil {
			return nil, err
		}
		history = append(history, &ph)
	}

	return history, nil
}

// DeleteOldPasswordHistory keeps only the most recent N passwords
func (s *MySQLStore) DeleteOldPasswordHistory(ctx context.Context, userID string, keepCount int) error {
	query := `
		DELETE FROM password_history
		WHERE user_id = ?
		AND id NOT IN (
			SELECT id FROM (
				SELECT id FROM password_history
				WHERE user_id = ?
				ORDER BY created_at DESC
				LIMIT ?
			) AS keep_passwords
		)
	`

	_, err := s.db.ExecContext(ctx, query, userID, userID, keepCount)
	return err
}

// Helper function to check for unique constraint violations in MySQL
func isUniqueViolation(err error) bool {
	// MySQL error code 1062 is for duplicate entry
	return err != nil && (strings.Contains(err.Error(), "Error 1062") ||
		strings.Contains(err.Error(), "Duplicate entry"))
}
