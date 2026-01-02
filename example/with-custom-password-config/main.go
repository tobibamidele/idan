package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/tobibamidele/idan"
	"github.com/tobibamidele/idan/config"
)

func main() {
	// Create a more advanced configuration
	cfg := config.NewConfigBuilder().
		WithDatabase(config.SQLite, "idan.db").
		WithSessionDuration(12*time.Hour).
		WithPasswordConfig(
			// Uses a simple sha256
			// Custom hashing function
			func(s string) (string, error) {
				hash := sha256.Sum256([]byte(s))
				return hex.EncodeToString(hash[:]), nil
			},
			// Custom check function
			func(pw, hash string) bool {
				p := sha256.Sum256([]byte(pw))
				pwHash := hex.EncodeToString(p[:])
				return subtle.ConstantTimeCompare([]byte(pwHash), []byte(hash)) == 1
			},
		).
		WithPasswordPolicy(config.DefaultPasswordPolicy()).
		WithBcryptCost(14). // Higher security
		WithCSRFProtection(true).
		WithRateLimit(true, 100, 10). // 100 req/min, 10 login attempts/min
		Build()

	// Initialize Idan
	auth, err := idan.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}
	defer auth.Close()

	// Create router
	mux := http.NewServeMux()

	// Public endpoints - no auth required
	publicRoutes(mux, auth)

	// Protected endpoints - auth required
	protectedRoutes(mux, auth)

	// Mixed endpoints - optional auth
	mixedRoutes(mux, auth)

	// Admin endpoints - auth required + custom checks
	adminRoutes(mux, auth)

	// Start server
	log.Println("Server starting on :8080")
	log.Println("Example endpoints:")
	log.Println("  POST   /api/auth/register")
	log.Println("  POST   /api/auth/login")
	log.Println("  POST   /api/auth/logout")
	log.Println("  GET    /api/auth/me")
	log.Println("  GET    /api/profile")
	log.Println("  PUT    /api/profile")
	log.Println("  GET    /api/feed")
	log.Println("  GET    /api/admin/users")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// publicRoutes sets up public endpoints
func publicRoutes(mux *http.ServeMux, auth *idan.Idan) {
	// Authentication endpoints
	mux.HandleFunc("/api/auth/register", auth.RegisterHandler())
	mux.HandleFunc("/api/auth/login", auth.LoginHandler())

	// Public info endpoint
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Welcome to the API",
			"version": "1.0.0",
		})
	})
}

// protectedRoutes sets up endpoints that require authentication
func protectedRoutes(mux *http.ServeMux, auth *idan.Idan) {
	// Logout requires authentication
	mux.Handle("/api/auth/logout", auth.Require()(http.HandlerFunc(auth.LogoutHandler())))

	// Get current user
	mux.Handle("/api/auth/me", auth.Require()(http.HandlerFunc(auth.MeHandler())))

	// Refresh session
	mux.Handle("/api/auth/refresh", auth.Require()(http.HandlerFunc(auth.RefreshHandler())))

	// User profile endpoints
	mux.Handle("/api/profile", auth.Require()(http.HandlerFunc(profileHandler(auth))))
	mux.Handle("/api/profile/update", auth.Require()(http.HandlerFunc(updateProfileHandler(auth))))

	// User-specific data
	mux.Handle("/api/dashboard", auth.Require()(http.HandlerFunc(dashboardHandler(auth))))
	mux.Handle("/api/settings", auth.Require()(http.HandlerFunc(settingsHandler(auth))))
}

// mixedRoutes sets up endpoints that work with or without authentication
func mixedRoutes(mux *http.ServeMux, auth *idan.Idan) {
	// Feed shows personalized content for logged-in users, generic for others
	mux.Handle("/api/feed", auth.Optional()(http.HandlerFunc(feedHandler(auth))))

	// Posts can show different content based on auth status
	mux.Handle("/api/posts", auth.Optional()(http.HandlerFunc(postsHandler(auth))))

	// Search works for everyone but shows more results for authenticated users
	mux.Handle("/api/search", auth.Optional()(http.HandlerFunc(searchHandler(auth))))
}

// adminRoutes sets up admin-only endpoints
func adminRoutes(mux *http.ServeMux, auth *idan.Idan) {
	// Chain multiple middleware: require auth + check admin role
	adminMiddleware := chainMiddleware(
		auth.Require(),
		requireAdmin(auth),
	)

	mux.Handle("/api/admin/users", adminMiddleware(http.HandlerFunc(adminUsersHandler(auth))))
	mux.Handle("/api/admin/stats", adminMiddleware(http.HandlerFunc(adminStatsHandler(auth))))
}

// Handler implementations

func profileHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := auth.GetUserFromRequest(r)
		session := auth.GetSessionFromRequest(r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user.ToResponse(),
			"session_info": map[string]interface{}{
				"created_at":   session.CreatedAt,
				"last_seen_at": session.LastSeenAt,
				"expires_at":   session.ExpiresAt,
				"ip_address":   session.IPAddress,
			},
		})
	}
}

func updateProfileHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := auth.GetUserFromRequest(r)

		var req struct {
			Name           *string `json:"name"`
			ProfilePicture *string `json:"profile_picture"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Update user fields
		if req.Name != nil {
			user.Name = req.Name
		}
		if req.ProfilePicture != nil {
			user.ProfilePicture = req.ProfilePicture
		}

		// Save to database
		if err := auth.Store().UpdateUser(r.Context(), user); err != nil {
			http.Error(w, "Failed to update profile", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Profile updated successfully",
			"user":    user.ToResponse(),
		})
	}
}

func dashboardHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromRequest(r)

		// Get user's sessions
		sessions, err := auth.Store().GetUserSessions(r.Context(), user.ID)
		if err != nil {
			http.Error(w, "Failed to get sessions", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":            user.ToResponse(),
			"active_sessions": len(sessions),
			"sessions":        sessions,
			"message":         "Welcome to your dashboard!",
		})
	}
}

func settingsHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromRequest(r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user.ToResponse(),
			"settings": map[string]interface{}{
				"email_verified":     user.EmailVerified,
				"two_factor_enabled": user.TwoFactorEnabled,
			},
		})
	}
}

func feedHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromRequest(r)

		feed := []string{"Post 1", "Post 2", "Post 3"}
		response := map[string]interface{}{
			"feed": feed,
		}

		if user != nil {
			// Personalized feed for authenticated users
			response["personalized"] = true
			response["recommended"] = []string{"Post 4", "Post 5"}
			response["user_email"] = user.Email
		} else {
			response["personalized"] = false
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func postsHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromRequest(r)

		posts := []map[string]interface{}{
			{"id": 1, "title": "Public Post 1", "public": true},
			{"id": 2, "title": "Public Post 2", "public": true},
		}

		if user != nil {
			// Add private posts for authenticated users
			posts = append(posts, map[string]interface{}{
				"id": 3, "title": "Member Post 1", "public": false,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"posts":         posts,
			"authenticated": user != nil,
		})
	}
}

func searchHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		user := auth.GetUserFromRequest(r)

		results := []string{"Result 1", "Result 2", "Result 3"}

		if user != nil {
			// More results for authenticated users
			results = append(results, "Result 4", "Result 5", "Result 6")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"query":   query,
			"results": results,
			"count":   len(results),
		})
	}
}

func adminUsersHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This handler only runs if user is authenticated AND is admin
		user := auth.GetUserFromRequest(r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "Admin users list",
			"admin_user": user.Email,
			"users": []map[string]string{
				{"id": "1", "email": "user1@example.com"},
				{"id": "2", "email": "user2@example.com"},
			},
		})
	}
}

func adminStatsHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_users":     100,
			"active_users":    75,
			"active_sessions": 50,
		})
	}
}

// Middleware utilities

// chainMiddleware chains multiple middleware functions
func chainMiddleware(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// requireAdmin is custom middleware that checks if user has admin role
// In a real app, you'd have a roles system in your user model
func requireAdmin(auth *idan.Idan) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUserFromRequest(r)
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// In a real app, check user.Role == "admin" or similar
			// For this example, we'll check if email contains "admin"
			// REPLACE THIS WITH PROPER ROLE CHECKING
			if user.Email != "admin@example.com" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Admin access required",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
