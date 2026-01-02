package config

import "time"

type DatabaseType string

const (
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
	SQLite     DatabaseType = "sqlite"
)

// Config holds all configurations for the authentication lib
type Config struct {
	Database       DatabaseConfig
	Session        SessionConfig
	PasswordPolicy PasswordPolicy
	PasswordConfig *PasswordConfig
	Security       SecurityConfig
	Email          *EmailConfig
	Features       FeatureConfig
	RateLimit      RateLimitConfig
}

// DatabaseConfig holds the database connection settings
type DatabaseConfig struct {
	Type          DatabaseType
	ConnectionURL string
	MaxOpenConns  int
	MaxIdleConns  int
	ConnMaxLife   time.Duration
	AutoMigrate   bool // Automatically run migrations
}

// SessionConfig holds session management settings
type SessionConfig struct {
	Duration           time.Duration
	CookieName         string
	CookiePath         string
	CookieDomain       string
	CookieSecure       bool
	CookieHTTPOnly     bool
	CookieSameSite     string
	RememberMe         bool
	RememberMeDuration time.Duration
}

// SecurityConfig holds security related settings
type SecurityConfig struct {
	CSRFProtection   bool
	CSRFTokenLength  int
	BcryptCost       int
	TokenLength      int
	MaxLoginAttempts int           // Max failed login attempts
	LockoutDuration  time.Duration // Account lock out duration
}

// EmailConfig holds email settings for notifications
type EmailConfig struct {
	From         string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	UseTLS       bool
}

// FeatureConfig holds feature flags
type FeatureConfig struct {
	EnableRegistration       bool
	RequireEmailVerification bool
	EnablePasswordReset      bool
	EnableRememberMe         bool
	EnableAccountLockout     bool
}

type RateLimitConfig struct {
	Enabled         bool
	RequestsPerMin  int           // Number of requests per min per ip
	LoginPerMin     int           // Max no of login attempts per min per ip
	BurstSize       int           // Burst size for rate limiter
	CleanupInterval time.Duration // How often to clean up old enntries
}

func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Type:          SQLite,
			ConnectionURL: "idan.db",
			MaxOpenConns:  25,
			MaxIdleConns:  5,
			ConnMaxLife:   5 * time.Minute,
			AutoMigrate:   true,
		},
		Session: SessionConfig{
			Duration:           24 * time.Hour,
			CookieName:         "idan_session",
			CookiePath:         "/",
			CookieDomain:       "",
			CookieSecure:       true,
			CookieHTTPOnly:     true,
			CookieSameSite:     "Lax",
			RememberMe:         true,
			RememberMeDuration: 30 * 24 * time.Hour,
		},
		PasswordPolicy: DefaultPasswordPolicy(),
		Security: SecurityConfig{
			CSRFProtection:   true,
			CSRFTokenLength:  32,
			BcryptCost:       12,
			TokenLength:      32,
			MaxLoginAttempts: 5,
			LockoutDuration:  15 * time.Minute,
		},
		Features: FeatureConfig{
			EnableRegistration:       true,
			RequireEmailVerification: false,
			EnablePasswordReset:      true,
			EnableRememberMe:         true,
			EnableAccountLockout:     true,
		},
		RateLimit: RateLimitConfig{
			Enabled:         true,
			RequestsPerMin:  60,
			LoginPerMin:     5,
			BurstSize:       10,
			CleanupInterval: 5 * time.Minute,
		},
	}
}

// ConfigBuilder provides a interface for building Config
type ConfigBuilder struct {
	config *Config
}

// NewConfigBuilder creates a new ConfigBuilder with default values
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: DefaultConfig(),
	}
}

// WithDatabase sets the database configuration
func (cb *ConfigBuilder) WithDatabase(dbType DatabaseType, connURL string) *ConfigBuilder {
	cb.config.Database.Type = dbType
	cb.config.Database.ConnectionURL = connURL
	return cb
}

// WithSessionDuration sets the session duration
func (cb *ConfigBuilder) WithSessionDuration(duration time.Duration) *ConfigBuilder {
	cb.config.Session.Duration = duration
	return cb
}

// WithPasswordPolicy sets the password policy
func (cb *ConfigBuilder) WithPasswordPolicy(policy PasswordPolicy) *ConfigBuilder {
	cb.config.PasswordPolicy = policy
	return cb
}

// WithPasswordConfig sets the password config
func (cb *ConfigBuilder) WithPasswordConfig(hash func(string) (string, error), check func(string, string) bool) *ConfigBuilder {
	if hash == nil || check == nil {
		panic("password hashing and check function must be defined when implementing custon password config.")
	}

	cb.config.PasswordConfig = &PasswordConfig{
		HashPassword:  hash,
		CheckPassword: check,
	}

	return cb
}

// WithCSRFProtection enables/disables CSRF protection
func (cb *ConfigBuilder) WithCSRFProtection(enabled bool) *ConfigBuilder {
	cb.config.Security.CSRFProtection = enabled
	return cb
}

// WithBcryptCost sets the bcrypt cost
func (cb *ConfigBuilder) WithBcryptCost(cost int) *ConfigBuilder {
	cb.config.Security.BcryptCost = cost
	return cb
}

// WithRateLimit configures rate limiting
func (cb *ConfigBuilder) WithRateLimit(enabled bool, requestsPerMin, loginPerMin int) *ConfigBuilder {
	cb.config.RateLimit.Enabled = enabled
	cb.config.RateLimit.RequestsPerMin = requestsPerMin
	cb.config.RateLimit.LoginPerMin = loginPerMin
	return cb
}

// DisableRegistration disables new user registration
func (cb *ConfigBuilder) DisableRegistration() *ConfigBuilder {
	cb.config.Features.EnableRegistration = false
	return cb
}

// RequireEmailVerification requires email verification for new accounts
func (cb *ConfigBuilder) RequireEmailVerification() *ConfigBuilder {
	cb.config.Features.RequireEmailVerification = true
	return cb
}

// WithEmailConfig sets email configuration
func (cb *ConfigBuilder) WithEmailConfig(cfg EmailConfig) *ConfigBuilder {
	cb.config.Email = &cfg
	return cb
}

// Build returns the final Config
func (cb *ConfigBuilder) Build() *Config {
	return cb.config
}
