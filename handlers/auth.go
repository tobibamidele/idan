package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tobibamidele/idan/config"
	"github.com/tobibamidele/idan/crypto"
	"github.com/tobibamidele/idan/errors"
	"github.com/tobibamidele/idan/middleware"
	"github.com/tobibamidele/idan/models"
	"github.com/tobibamidele/idan/store"
	"github.com/tobibamidele/idan/validator"
)

// AuthHandler handles auth related HTTP requests
type AuthHandler struct {
	store             store.Store
	config            *config.Config
	passwordValidator *validator.PasswordValidator
}

func NewAuthHandler(store store.Store, cfg *config.Config, pwValidator *validator.PasswordValidator) *AuthHandler {
	return &AuthHandler{
		store:             store,
		config:            cfg,
		passwordValidator: pwValidator,
	}
}

func (h *AuthHandler) writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}

func (h *AuthHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, errors.ErrInvalidInput)
		return
	}

	if !h.config.Features.EnableRegistration {
		h.writeError(w, http.StatusForbidden, fmt.Errorf("registration is disabled"))
		return
	}

	var req models.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, errors.ErrInvalidInput)
		return
	}

	// Validate
	if err := validator.ValidateEmail(req.Email); err != nil {
		h.writeError(w, http.StatusBadRequest, err)
	}

	if err := h.passwordValidator.Validate(req.Password); err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	var hash string
	var err error

	// Use custom hash if it's set
	if h.config.PasswordConfig != nil {
		hash, err = h.config.PasswordConfig.HashPassword(req.Password)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
			return
		}
	} else {
		hash, err = crypto.HashPassword(req.Password, h.config.Security.BcryptCost)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
			return
		}
	}

	// Create verification token if need
	var verificationToken *string
	if h.config.Features.RequireEmailVerification {
		token, err := crypto.GenerateVerificationToken()
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
			return
		}
		verificationToken = &token
	}

	// Create user
	user := &models.User{
		ID:                  uuid.New().String(),
		Email:               req.Email,
		PasswordHash:        hash,
		EmailVerified:       !h.config.Features.RequireEmailVerification,
		VerificationToken:   verificationToken,
		FailedLoginAttempts: 0,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		Name:                req.Name,
		TwoFactorEnabled:    false,
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if err == errors.ErrUserAlreadyExists {
			h.writeError(w, http.StatusConflict, err)
		} else {
			h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
		}
		return
	}

	// Add password to history if prevention is enabled
	if h.config.PasswordPolicy.PreventReuse > 0 {
		_ = h.store.AddPasswordHistory(r.Context(), user.ID, hash)
	}

	// TODO: Send verification email using email config
	h.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user":              user.ToResponse(),
		"email_verified":    user.EmailVerified,
		"verification_sent": h.config.Features.RequireEmailVerification,
	})
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, errors.ErrInvalidInput)
		return
	}

	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, errors.ErrInvalidInput)
		return
	}

	// Get user by email
	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err == errors.ErrUserNotFound {
			h.writeError(w, http.StatusUnauthorized, errors.ErrInvalidCredentials)
		} else {
			h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
		}
		return
	}

	// Check if account is locked
	if user.IsLocked() {
		h.writeError(w, http.StatusForbidden, errors.ErrAccountLocked)
		return
	}

	// Verify password
	// Use custom checker if set
	var isPasswordCorrect bool
	if h.config.PasswordConfig != nil {
		isPasswordCorrect = h.config.PasswordConfig.CheckPassword(req.Password, user.PasswordHash)
	} else { // Default to basic one
		isPasswordCorrect = crypto.CheckPassword(req.Password, user.PasswordHash)
	}

	if !isPasswordCorrect {
		// Increment failed attempts
		_ = h.store.IncrementFailedLogins(r.Context(), user.ID)

		// Lock account if max attempts reached
		if h.config.Features.EnableAccountLockout &&
			user.FailedLoginAttempts+1 >= h.config.Security.MaxLoginAttempts {
			lockUntil := time.Now().Add(h.config.Security.LockoutDuration)
			_ = h.store.LockUser(r.Context(), user.ID, &lockUntil)
		}

		h.writeError(w, http.StatusUnauthorized, errors.ErrInvalidCredentials)
		return
	}

	// Check email verification requirement
	if h.config.Features.RequireEmailVerification && !user.EmailVerified {
		h.writeError(w, http.StatusForbidden, errors.ErrEmailNotVerified)
		return
	}

	// Reset failed login attempts
	_ = h.store.ResetFailedLogins(r.Context(), user.ID)

	// Update last login
	now := time.Now()
	ipAddress := getIPAddress(r)
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	_ = h.store.UpdateUser(r.Context(), user)

	// Create session
	token, err := crypto.GenerateSessionToken()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
		return
	}

	duration := h.config.Session.Duration
	if req.RememberMe && h.config.Features.EnableRememberMe {
		duration = h.config.Session.RememberMeDuration
	}

	session := &models.Session{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Token:      token,
		IPAddress:  ipAddress,
		UserAgent:  r.UserAgent(),
		RememberMe: req.RememberMe,
		ExpiresAt:  time.Now().Add(duration),
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
	}

	if err := h.store.CreateSession(r.Context(), session); err != nil {
		h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
		return
	}

	// Set session cookie
	h.setSessionCookie(w, token, session.ExpiresAt)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user.ToResponse(),
		"session": session,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, errors.ErrInvalidInput)
		return
	}

	// Get session from context
	session := middleware.GetSession(r)
	if session == nil {
		// Already logged out
		h.writeJSON(w, http.StatusOK, map[string]string{
			"message": "logged out",
		})
		return
	}

	// Delete session
	_ = h.store.DeleteSession(r.Context(), session.Token)

	// Clear cookie
	h.clearSessionCookie(w)

	h.writeJSON(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

// Me returns the currently authenticated user
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, errors.ErrInvalidInput)
		return
	}

	user := middleware.GetUser(r)
	if user == nil {
		h.writeError(w, http.StatusUnauthorized, errors.ErrUnauthorized)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": user.ToResponse(),
	})
}

// Refresh refreshes the session (extends expiration)
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, errors.ErrInvalidInput)
		return
	}

	session := middleware.GetSession(r)
	if session == nil {
		h.writeError(w, http.StatusUnauthorized, errors.ErrUnauthorized)
		return
	}

	// Extend session
	duration := h.config.Session.Duration
	if session.RememberMe {
		duration = h.config.Session.RememberMeDuration
	}

	session.ExpiresAt = time.Now().Add(duration)
	session.LastSeenAt = time.Now()

	if err := h.store.UpdateSession(r.Context(), session); err != nil {
		h.writeError(w, http.StatusInternalServerError, errors.ErrInternalServer)
		return
	}

	// Update cookie
	h.setSessionCookie(w, session.Token, session.ExpiresAt)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"session": session,
	})
}

// Helper methods

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     h.config.Session.CookieName,
		Value:    token,
		Path:     h.config.Session.CookiePath,
		Domain:   h.config.Session.CookieDomain,
		Expires:  expiresAt,
		Secure:   h.config.Session.CookieSecure,
		HttpOnly: h.config.Session.CookieHTTPOnly,
	}

	// Set SameSite attribute
	switch h.config.Session.CookieSameSite {
	case "Strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "Lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "None":
		cookie.SameSite = http.SameSiteNoneMode
	default:
		cookie.SameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, cookie)
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     h.config.Session.CookieName,
		Value:    "",
		Path:     h.config.Session.CookiePath,
		Domain:   h.config.Session.CookieDomain,
		MaxAge:   -1,
		Secure:   h.config.Session.CookieSecure,
		HttpOnly: h.config.Session.CookieHTTPOnly,
	}

	http.SetCookie(w, cookie)
}

func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
