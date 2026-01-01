package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/tobibamidele/idan/errors"
	"github.com/tobibamidele/idan/models"
)

// PostgresStore implements the store interface for PostgreSQL
type PostgresStore struct {
	db *sql.DB
}

// New creates a new PostgreSQL store
func New(
	connectionURL string,
	maxOpenConns,
	maxIdleConns int,
	connMaxLife time.Duration,
) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLife)

	// Test
	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

// isUniqueViolation is a helper function that does what it's named
func isUniqueViolation(err error) bool {
	// PostgreSQL returns an error code 25505 for unique constraints violation
	return err != nil && (err.Error() == "pq: duplicate key value violates unique constraint \"users_email_key\"" ||
		err.Error() == "ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)")
}

// Close closes the database connection
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// CreateUser creates a new user
func (s *PostgresStore) CreateUser(ctx context.Context, user *models.User) error {
	query := `
	INSERT INTO users (
	id, email, password_hash, email_verified, verification_token, failed_login_attempts, created_at, updated_at, name, two_factor_enabled
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := s.db.ExecContext(ctx, query, user.ID, user.Email, user.PasswordHash, user.EmailVerified, user.VerificationToken, user.FailedLoginAttempts, user.CreatedAt, user.UpdatedAt, user.Name, user.TwoFactorEnabled)

	if err != nil {
		// Check for unique constraint violcation
		if isUniqueViolation(err) {
			return errors.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, email_verified_at,
		verification_token, failed_login_attempts, locked_until,
		last_login_at, last_login_ip, created_at, updated_at, name, profile_picture,
		two_factor_enabled, two_factor_secret
		FROM users WHERE id = $1
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

// GetUserByEmail retrieves a user by email
func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, email_verified_at,
			verification_token, failed_login_attempts, locked_until,
			last_login_at, last_login_ip, created_at, updated_at,
			name, profile_picture, two_factor_enabled, two_factor_secret
		FROM users WHERE LOWER(email) = LOWER($1)
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
func (s *PostgresStore) UpdateUser(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET
			email = $2, password_hash = $3, email_verified = $4,
			email_verified_at = $5, verification_token = $6,
			failed_login_attempts = $7, locked_until = $8,
			last_login_at = $9, last_login_ip = $10, updated_at = $11,
			name = $12, profile_picture = $13, two_factor_enabled = $14,
			two_factor_secret = $15
		WHERE id = $1
	`

	user.UpdatedAt = time.Now()

	result, err := s.db.ExecContext(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.EmailVerified,
		user.EmailVerifiedAt, user.VerificationToken,
		user.FailedLoginAttempts, user.LockedUntil, user.LastLoginAt,
		user.LastLoginIP, user.UpdatedAt, user.Name, user.ProfilePicture,
		user.TwoFactorEnabled, user.TwoFactorSecret,
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
func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

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
func (s *PostgresStore) IncrementFailedLogins(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
			updated_at = $2
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, query, userID, time.Now())
	return err
}

// ResetFailedLogins resets failed login attempts to 0
func (s *PostgresStore) ResetFailedLogins(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = $2
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, query, userID, time.Now())
	return err
}

// LockUser locks a user account until specified time
func (s *PostgresStore) LockUser(ctx context.Context, userID string, until *time.Time) error {
	query := `
		UPDATE users
		SET locked_until = $2,
			updated_at = $3
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, query, userID, until, time.Now())
	return err
}

// Session operations would follow similar patterns
// Continuing with CreateSession as an example

// CreateSession creates a new session
func (s *PostgresStore) CreateSession(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
func (s *PostgresStore) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		FROM sessions WHERE token = $1
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

// GetUserSessions retrieves all sessions for a user
func (s *PostgresStore) GetUserSessions(ctx context.Context, userID string) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent,
			remember_me, expires_at, created_at, last_seen_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > $2
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
func (s *PostgresStore) UpdateSession(ctx context.Context, session *models.Session) error {
	query := `
		UPDATE sessions SET
			last_seen_at = $2,
			expires_at = $3
		WHERE token = $1
	`

	_, err := s.db.ExecContext(ctx, query, session.Token, session.LastSeenAt, session.ExpiresAt)
	return err
}

// DeleteSession deletes a session
func (s *PostgresStore) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = $1`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

// DeleteUserSessions deletes all sessions for a user
func (s *PostgresStore) DeleteUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// DeleteExpiredSessions deletes expired sessions
func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	return err
}

// Password reset operations

// CreatePasswordResetToken creates a new password reset token
func (s *PostgresStore) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (
			id, user_id, token, expires_at, used, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := s.db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Token, token.ExpiresAt,
		token.Used, token.CreatedAt,
	)

	return err
}

// GetPasswordResetToken retrieves a password reset token
func (s *PostgresStore) GetPasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used, created_at, used_at
		FROM password_reset_tokens WHERE token = $1
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
func (s *PostgresStore) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	query := `UPDATE password_reset_tokens SET used = true, used_at = $2 WHERE token = $1`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, token, now)
	return err
}

// DeletePasswordResetToken deletes a token
func (s *PostgresStore) DeletePasswordResetToken(ctx context.Context, token string) error {
	query := `DELETE FROM password_reset_tokens WHERE token = $1`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

// DeleteUserPasswordResetTokens deletes all reset tokens for a user
func (s *PostgresStore) DeleteUserPasswordResetTokens(ctx context.Context, userID string) error {
	query := `DELETE FROM password_reset_tokens WHERE user_id = $1`
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

// Password history operations

// AddPasswordHistory adds a password to history
func (s *PostgresStore) AddPasswordHistory(ctx context.Context, userID, passwordHash string) error {
	query := `
		INSERT INTO password_history (id, user_id, password_hash, created_at)
		VALUES ($1, $2, $3, $4)
	`

	id := fmt.Sprintf("%s_%d", userID, time.Now().Unix())
	_, err := s.db.ExecContext(ctx, query, id, userID, passwordHash, time.Now())
	return err
}

// GetPasswordHistory retrieves password history for a user
func (s *PostgresStore) GetPasswordHistory(ctx context.Context, userID string, limit int) ([]*models.PasswordHistory, error) {
	query := `
		SELECT id, user_id, password_hash, created_at
		FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
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
func (s *PostgresStore) DeleteOldPasswordHistory(ctx context.Context, userID string, keepCount int) error {
	query := `
		DELETE FROM password_history
		WHERE user_id = $1
		AND id NOT IN (
			SELECT id FROM password_history
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		)
	`

	_, err := s.db.ExecContext(ctx, query, userID, keepCount)
	return err
}
