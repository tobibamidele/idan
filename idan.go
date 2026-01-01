package idan

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tobibamidele/idan/config"
	"github.com/tobibamidele/idan/crypto"
	"github.com/tobibamidele/idan/errors"
	"github.com/tobibamidele/idan/handlers"
	"github.com/tobibamidele/idan/middleware"
	"github.com/tobibamidele/idan/models"
	"github.com/tobibamidele/idan/store"

	// "github.com/tobibamidele/idan/store/mysql"
	"github.com/tobibamidele/idan/store/mysql"
	"github.com/tobibamidele/idan/store/postgres"
	"github.com/tobibamidele/idan/store/sqlite"

	// "github.com/tobibamidele/idan/store/sqlite"
	"github.com/tobibamidele/idan/validator"
)

// Idan is the main authentication handler
type Idan struct {
	config            *config.Config
	store             store.Store
	passwordValidator *validator.PasswordValidator
	authHandler       *handlers.AuthHandler
	middleware        *middleware.Middleware
}

// New creates a new Idan instance with the provided configuration
func New(cfg *config.Config) (*Idan, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Initialize the appropriate database store
	var st store.Store
	var err error

	switch cfg.Database.Type {
	case config.PostgreSQL:
		st, err = postgres.New(
			cfg.Database.ConnectionURL,
			cfg.Database.MaxOpenConns,
			cfg.Database.MaxIdleConns,
			cfg.Database.ConnMaxLife,
		)
	case config.MySQL:
		st, err = mysql.New(
			cfg.Database.ConnectionURL,
			cfg.Database.MaxOpenConns,
			cfg.Database.MaxIdleConns,
			cfg.Database.ConnMaxLife,
		)
	case config.SQLite:
		st, err = sqlite.New(
			cfg.Database.ConnectionURL,
			cfg.Database.MaxOpenConns,
			cfg.Database.MaxIdleConns,
			cfg.Database.ConnMaxLife,
		)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Run migrations if enabled
	if cfg.Database.AutoMigrate {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := st.RunMigrations(ctx); err != nil {
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	// Initialize password validator
	pwValidator := validator.NewPasswordValidator(cfg.PasswordPolicy)

	// Create Idan instance
	i := &Idan{
		config:            cfg,
		store:             st,
		passwordValidator: pwValidator,
	}

	// Initialize handlers
	i.authHandler = handlers.NewAuthHandler(st, cfg, pwValidator)

	// Initialize middleware
	i.middleware = middleware.New(st, *cfg)

	// Start background tasks
	go i.cleanupExpiredSessions()

	return i, nil
}

// Close closes the database connection
func (i *Idan) Close() error {
	return i.store.Close()
}

// cleanupExpiredSessions periodically removes expired sessions
func (i *Idan) cleanupExpiredSessions() {
	ticker := time.NewTicker(i.config.RateLimit.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := i.store.DeleteExpiredSessions(ctx); err != nil {
			log.Printf("failed to cleanup expired sessions: %v", err)
		}
		cancel()
	}
}

// Handler Methods - These return http.HandlerFunc for easy mounting

// RegisterHandler returns the registration handler
func (i *Idan) RegisterHandler() http.HandlerFunc {
	return i.authHandler.Register
}

// LoginHandler returns the login handler
func (i *Idan) LoginHandler() http.HandlerFunc {
	return i.authHandler.Login
}

// LogoutHandler returns the logout handler
func (i *Idan) LogoutHandler() http.HandlerFunc {
	return i.authHandler.Logout
}

// MeHandler returns the current user handler
func (i *Idan) MeHandler() http.HandlerFunc {
	return i.authHandler.Me
}

// RefreshHandler returns the session refresh handler
func (i *Idan) RefreshHandler() http.HandlerFunc {
	return i.authHandler.Refresh
}

// Middleware Methods - For protecting routes

// Require returns middleware that requires authentication
// Use this to protect routes that need authentication
func (i *Idan) Require() func(http.Handler) http.Handler {
	return i.middleware.Require
}

// Optional returns middleware that optionally loads user if authenticated
// Use this for routes that work both with and without authentication
func (i *Idan) Optional() func(http.Handler) http.Handler {
	return i.middleware.Optional
}

// Exclude returns middleware that explicitly excludes authentication
// This is useful for public routes in an otherwise protected section
func (i *Idan) Exclude() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next // Pass through without checking auth
	}
}

// Helper Methods - For custom implementations

// CreateUser creates a new user (useful for custom registration flows)
func (i *Idan) CreateUser(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	// Validate email
	if err := validator.ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	// Validate password
	if err := i.passwordValidator.Validate(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hash, err := crypto.HashPassword(req.Password, i.config.Security.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create verification token if email verification is required
	var verificationToken *string
	if i.config.Features.RequireEmailVerification {
		token, err := crypto.GenerateVerificationToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate verification token: %w", err)
		}
		verificationToken = &token
	}

	// Create user
	user := &models.User{
		ID:                  uuid.New().String(),
		Email:               req.Email,
		PasswordHash:        hash,
		EmailVerified:       !i.config.Features.RequireEmailVerification,
		VerificationToken:   verificationToken,
		FailedLoginAttempts: 0,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		Name:                req.Name,
		TwoFactorEnabled:    false,
	}

	if err := i.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Add password to history if prevention is enabled
	if i.config.PasswordPolicy.PreventReuse > 0 {
		_ = i.store.AddPasswordHistory(ctx, user.ID, hash)
	}

	return user, nil
}

// AuthenticateUser authenticates a user and creates a session
func (i *Idan) AuthenticateUser(ctx context.Context, email, password, ipAddress, userAgent string, rememberMe bool) (*models.Session, *models.User, error) {
	// Get user by email
	user, err := i.store.GetUserByEmail(ctx, email)
	if err != nil {
		if err == errors.ErrUserNotFound {
			return nil, nil, errors.ErrInvalidCredentials
		}
		return nil, nil, err
	}

	// Check if account is locked
	if user.IsLocked() {
		return nil, nil, errors.ErrAccountLocked
	}

	// Verify password
	if !crypto.CheckPassword(password, user.PasswordHash) {
		// Increment failed attempts
		_ = i.store.IncrementFailedLogins(ctx, user.ID)

		// Lock account if max attempts reached
		if i.config.Features.EnableAccountLockout &&
			user.FailedLoginAttempts+1 >= i.config.Security.MaxLoginAttempts {
			lockUntil := time.Now().Add(i.config.Security.LockoutDuration)
			_ = i.store.LockUser(ctx, user.ID, &lockUntil)
		}

		return nil, nil, errors.ErrInvalidCredentials
	}

	// Check email verification requirement
	if i.config.Features.RequireEmailVerification && !user.EmailVerified {
		return nil, nil, errors.ErrEmailNotVerified
	}

	// Reset failed login attempts
	_ = i.store.ResetFailedLogins(ctx, user.ID)

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	_ = i.store.UpdateUser(ctx, user)

	// Create session
	token, err := crypto.GenerateSessionToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	duration := i.config.Session.Duration
	if rememberMe && i.config.Features.EnableRememberMe {
		duration = i.config.Session.RememberMeDuration
	}

	session := &models.Session{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Token:      token,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		RememberMe: rememberMe,
		ExpiresAt:  time.Now().Add(duration),
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
	}

	if err := i.store.CreateSession(ctx, session); err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, user, nil
}

// GetUserFromRequest extracts the authenticated user from the request context
// Returns nil if no user is authenticated
func (i *Idan) GetUserFromRequest(r *http.Request) *models.User {
	return middleware.GetUser(r)
}

// GetSessionFromRequest extracts the session from the request context
// Returns nil if no session exists
func (i *Idan) GetSessionFromRequest(r *http.Request) *models.Session {
	return middleware.GetSession(r)
}

// Store returns the underlying store (for advanced use cases)
func (i *Idan) Store() store.Store {
	return i.store
}
