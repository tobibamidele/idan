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

// WithCSRFProtection enables/disables CSRF protection
func (b *ConfigBuilder) WithCSRFProtection(enabled bool) *ConfigBuilder {
	b.config.Security.CSRFProtection = enabled
	return b
}

// WithBcryptCost sets the bcrypt cost
func (b *ConfigBuilder) WithBcryptCost(cost int) *ConfigBuilder {
	b.config.Security.BcryptCost = cost
	return b
}

// WithRateLimit configures rate limiting
func (b *ConfigBuilder) WithRateLimit(enabled bool, requestsPerMin, loginPerMin int) *ConfigBuilder {
	b.config.RateLimit.Enabled = enabled
	b.config.RateLimit.RequestsPerMin = requestsPerMin
	b.config.RateLimit.LoginPerMin = loginPerMin
	return b
}

// DisableRegistration disables new user registration
func (b *ConfigBuilder) DisableRegistration() *ConfigBuilder {
	b.config.Features.EnableRegistration = false
	return b
}

// RequireEmailVerification requires email verification for new accounts
func (b *ConfigBuilder) RequireEmailVerification() *ConfigBuilder {
	b.config.Features.RequireEmailVerification = true
	return b
}

// WithEmailConfig sets email configuration
func (b *ConfigBuilder) WithEmailConfig(cfg EmailConfig) *ConfigBuilder {
	b.config.Email = &cfg
	return b
}

// Build returns the final Config
func (b *ConfigBuilder) Build() *Config {
	return b.config
}
