package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/tobibamidele/idan/config"
	"github.com/tobibamidele/idan/errors"
	"github.com/tobibamidele/idan/models"
	"github.com/tobibamidele/idan/store"
)

// Context keys for storing user and session in request context
type contextKey string

const (
	userContextKey    contextKey = "user"
	sessionContextKey contextKey = "session"
)

// Middleware handles authentication middleware
type Middleware struct {
	store  store.Store
	config *config.Config
}

// New creates a new middleware instance
func New(store store.Store, config config.Config) *Middleware {
	return &Middleware{
		store:  store,
		config: &config,
	}
}

func (m *Middleware) authenticate(r *http.Request) (*models.User, *models.Session, error) {
	// Get token from the cookie
	cookie, err := r.Cookie(m.config.Session.CookieName)
	if err != nil {
		return nil, nil, errors.ErrUnauthorized
	}

	token := strings.TrimSpace(cookie.Value)
	if token == "" {
		return nil, nil, errors.ErrUnauthorized
	}

	// Get session from store
	session, err := m.store.GetSessionByToken(r.Context(), token)
	if err != nil {
		return nil, nil, errors.ErrSessionNotFound
	}

	// Check if session is expired
	if session.IsExpired() {
		_ = m.store.DeleteSession(r.Context(), token)
		return nil, nil, errors.ErrSessionExpired
	}

	// Get user
	user, err := m.store.GetUserByID(r.Context(), session.UserID)
	if err != nil {
		return nil, nil, err
	}

	// Check if account is locked
	if user.IsLocked() {
		return nil, nil, errors.ErrAccountLocked
	}

	return user, session, nil
}

func (m Middleware) writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}

// Require is the middleware that requires authentication
// If the user is not authenticated, it returns a 401
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, session, err := m.authenticate(r)
		if err != nil {
			m.writeError(w, http.StatusUnauthorized, err)
			return
		}

		// Update session last seen
		session.LastSeenAt = time.Now()
		_ = m.store.UpdateSession(r.Context(), session)

		// Add user and session to context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Optional is middleware that optionally loads the user if autheticated
// If the user is not authenticated, the request continues without a user in context
func (m *Middleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, session, err := m.authenticate(r)
		if err == nil && user != nil { // Only set if there's an active user
			// Update session last seen
			session.LastSeenAt = time.Now()
			_ = m.store.UpdateSession(r.Context(), session)

			ctx := context.WithValue(r.Context(), userContextKey, user)
			ctx = context.WithValue(ctx, sessionContextKey, session)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// GetUser extracts the user from the request context
func GetUser(r *http.Request) *models.User {
	user, ok := r.Context().Value(userContextKey).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// GetSession extracts the session from the request context
func GetSession(r *http.Request) *models.Session {
	session, ok := r.Context().Value(sessionContextKey).(*models.Session)
	if !ok {
		return nil
	}
	return session
}

// RequireEmailVerification is the middleware that requires email verification
func (m *Middleware) RequireEmailVerification(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			m.writeError(w, http.StatusUnauthorized, errors.ErrUnauthorized)
			return
		}

		if !user.EmailVerified {
			m.writeError(w, http.StatusForbidden, errors.ErrEmailNotVerified)
			return
		}

		next.ServeHTTP(w, r)
	})
}
