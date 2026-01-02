# Idan

A production-grade, highly configurable authentication library for Go's standard `net/http` library. Idan provides session-based authentication with support for multiple databases, customizable password policies, and comprehensive security features.

## Features

**Easy to Use** - Simple API with sensible defaults  
**Highly Configurable** - Customize every aspect via builder pattern  
**Multi-Database Support** - PostgreSQL, MySQL, and SQLite  
**Security First** - Bcrypt hashing, CSRF protection, rate limiting  
**Email Verification** - Optional email verification flow  
**Password Reset** - Built-in password reset functionality  
**Account Lockout** - Automatic lockout after failed attempts  
**Password History** - Prevent password reuse  
**Session Management** - Secure session handling with "remember me"  
**Flexible Middleware** - Require, optional, or exclude authentication  

## Installation

```bash
go get github.com/tobibamidele/idan
```

## Quick Start

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/tobibamidele/idan"
    "github.com/tobibamidele/idan/config"
)

func main() {
    // Create configuration
    cfg := config.NewConfigBuilder().
        WithDatabase(config.SQLite, "auth.db").
        WithSessionDuration(24 * time.Hour).
        Build()

    // Initialize Idan
    auth, err := idan.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    // Create router
    mux := http.NewServeMux()

    // Public routes
    mux.HandleFunc("/api/auth/register", auth.RegisterHandler())
    mux.HandleFunc("/api/auth/login", auth.LoginHandler())

    // Protected routes
    mux.Handle("/api/auth/me", auth.Require()(http.HandlerFunc(auth.MeHandler())))
    mux.Handle("/api/dashboard", auth.Require()(http.HandlerFunc(dashboardHandler)))

    log.Fatal(http.ListenAndServe(":8080", mux))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // User is guaranteed to be authenticated here
    w.Write([]byte("Welcome to your dashboard!"))
}
```

## Configuration

### Basic Configuration

```go
cfg := config.NewConfigBuilder().
    WithDatabase(config.PostgreSQL, "postgres://user:pass@localhost/db").
    WithSessionDuration(24 * time.Hour).
    WithPasswordPolicy(config.DefaultPasswordPolicy()).
    Build()
```

### Advanced Configuration

```go
cfg := config.NewConfigBuilder().
    // Database configuration
    WithDatabase(
        config.PostgreSQL,
        "postgres://user:pass@localhost/db",
    ).

    // Session configuration
    WithSessionDuration(24 * time.Hour).

    // Password policy (validation rules)
    WithPasswordPolicy(config.PasswordPolicy{
        MinLength:        12,
        RequireUppercase: true,
        RequireLowercase: true,
        RequireNumber:    true,
        RequireSpecial:   true,
        PreventCommon:    true,
        PreventReuse:     5,
    }).

    // Password hashing and verification
    WithPasswordConfig(
        // Custom hash function
        func(password string) (string, error) {
            hash := sha256.Sum256([]byte(password))
            return hex.EncodeToString(hash[:]), nil
        },

        // Custom password verification function
        func(password, storedHash string) bool {
            hash := sha256.Sum256([]byte(password))
            computed := hex.EncodeToString(hash[:])

            return subtle.ConstantTimeCompare(
                []byte(computed),
                []byte(storedHash),
            ) == 1
        },
    ).

    // Security settings
    WithBcryptCost(12).
    WithCSRFProtection(true).

    // Rate limiting
    WithRateLimit(
        true, // enabled
        60,   // requests per minute per IP
        5,    // login attempts per minute per IP
    ).

    // Feature flags
    RequireEmailVerification().

    Build()
```
### Password Policies

Idan provides three pre-configured password policies:

```go
// Default - Balanced security (recommended)
config.DefaultPasswordPolicy()

// Weak - Lenient (not recommended for production)
config.WeakPasswordPolicy()

// Strong - Maximum security
config.StrongPasswordPolicy()
```

Or create your own:

```go
policy := config.PasswordPolicy{
    MinLength:        12,
    MaxLength:        128,
    RequireUppercase: true,
    RequireLowercase: true,
    RequireNumber:    true,
    RequireSpecial:   true,
    SpecialChars:     "!@#$%^&*()_+-=[]{}|;:,.<>?",
    PreventCommon:    true,
    PreventReuse:     5, // Prevent reusing last 5 passwords
}
```

### Password Config

Idan allows for customization of the hashing algorithm. The default hash mode is bcrypt.

Passwords are first hashed with SHA256 to prevent the error when a password is longer than 72 chars in Bcrypt.
The SHA256 sum is then rehashed with bcrypt.

To define a custom hashing algorithm, create a PasswordConfig and pass it when building the config

```go
pwConfig := config.PasswordConfig{
		func (s string) (string, error) {}, // Custom hash implementation, returns a string and error
		func (s1, s2 string) bool {} // Custom function to check if the password is the plaintext equivalent of the hash
}
````

## Middleware Usage

### Require Authentication

Use `Require()` for routes that must have authentication:

```go
// User MUST be authenticated
mux.Handle("/api/protected", auth.Require()(http.HandlerFunc(handler)))
```

### Optional Authentication

Use `Optional()` for routes that work with or without authentication:

```go
// User MAY be authenticated
mux.Handle("/api/posts", auth.Optional()(http.HandlerFunc(handler)))

func handler(w http.ResponseWriter, r *http.Request) {
    user := auth.GetUserFromRequest(r)
    if user != nil {
        // Show personalized content
    } else {
        // Show public content
    }
}
```

### Exclude Authentication

Use `Exclude()` for explicitly public routes:

```go
// No authentication check
mux.Handle("/api/public", auth.Exclude()(http.HandlerFunc(handler)))
```

## API Endpoints

### Built-in Handlers

Idan provides ready-to-use HTTP handlers:

| Handler | Method | Description |
|---------|--------|-------------|
| `RegisterHandler()` | POST | User registration |
| `LoginHandler()` | POST | User login |
| `LogoutHandler()` | POST | User logout (protected) |
| `MeHandler()` | GET | Get current user (protected) |
| `RefreshHandler()` | POST | Refresh session (protected) |

### Registration

**POST** `/api/auth/register`

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe"
}
```

Response:
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": false,
    "created_at": "2024-01-01T00:00:00Z",
    "name": "John Doe"
  },
  "email_verified": false,
  "verification_sent": true
}
```

### Login

**POST** `/api/auth/login`

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": true
}
```

Response:
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true,
    "last_login_at": "2024-01-01T00:00:00Z"
  },
  "session": {
    "id": "session-id",
    "expires_at": "2024-01-02T00:00:00Z"
  }
}
```

## Advanced Usage

### Custom User Operations

```go
// Create a user programmatically
user, err := auth.CreateUser(ctx, models.CreateUserRequest{
    Email:    "user@example.com",
    Password: "SecurePassword123!",
    Name:     ptr("John Doe"),
})

// Authenticate and create session
session, user, err := auth.AuthenticateUser(
    ctx,
    "user@example.com",
    "password",
    "192.168.1.1",
    "Mozilla/5.0...",
    true, // remember me
)
```

### Access User in Handlers

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user
    user := auth.GetUserFromRequest(r)
    
    // Get session
    session := auth.GetSessionFromRequest(r)
    
    // Use the user
    fmt.Fprintf(w, "Hello, %s!", user.Email)
}
```

### Direct Store Access

For advanced use cases, you can access the underlying store:

```go
store := auth.Store()

// Perform custom queries
user, err := store.GetUserByEmail(ctx, "user@example.com")
sessions, err := store.GetUserSessions(ctx, userID)
```

## Database Support

### PostgreSQL

```go
cfg := config.NewConfigBuilder().
    WithDatabase(
        config.PostgreSQL,
        "postgres://user:password@localhost:5432/dbname?sslmode=disable",
    ).
    Build()
```

### MySQL

```go
cfg := config.NewConfigBuilder().
    WithDatabase(
        config.MySQL,
        "user:password@tcp(localhost:3306)/dbname?parseTime=true",
    ).
    Build()
```

### SQLite

```go
cfg := config.NewConfigBuilder().
    WithDatabase(config.SQLite, "auth.db").
    Build()
```

## Security Features

### Automatic Protections

- **Bcrypt password hashing** with configurable cost
- **CSRF protection** (optional)
- **Rate limiting** per IP address
- **Account lockout** after failed login attempts
- **Secure session tokens** using crypto/rand
- **HTTPOnly cookies** to prevent XSS
- **SameSite cookies** for CSRF mitigation
- **Password history** to prevent reuse
- **Common password checking**

### Best Practices

1. Always use HTTPS in production (`CookieSecure: true`)
2. Enable CSRF protection for state-changing operations
3. Use strong password policies
4. Enable rate limiting
5. Implement email verification for sensitive applications
6. Monitor failed login attempts
7. Regular session cleanup (automatic)

## Error Handling

Idan provides typed errors for better error handling:

```go
import "github.com/tobibamidele/idan/errors"

// Check for specific errors
if err == errors.ErrUserNotFound {
    // Handle user not found
}

if err == errors.ErrInvalidCredentials {
    // Handle invalid login
}

if err == errors.ErrAccountLocked {
    // Handle locked account
}
```

## Testing

```bash
go test ./...
```

## Examples

Check the `examples/` directory for:

- `basic/` - Basic authentication setup
- `custom-handlers/` - Custom authentication handlers
- `with-middleware/` - Advanced middleware patterns

## Roadmap

- [ ] OAuth2 support
- [ ] Two-factor authentication (TOTP)
- [ ] Magic link authentication
- [ ] Redis session store
- [ ] WebAuthn/Passkey support
- [ ] Admin dashboard
- [ ] Audit logging
- [ ] More granular permissions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

**Tobi Bamidele** - [GitHub](https://github.com/tobibamidele)

## Acknowledgments

Built with ❤️ for the Go community

---
