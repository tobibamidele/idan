package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/tobibamidele/idan"
	"github.com/tobibamidele/idan/config"
)

func main() {
	// Create configuration
	cfg := config.NewConfigBuilder().
		WithDatabase(config.SQLite, "auth.db").
		WithSessionDuration(24 * 3600 * 1000000000). // 24 hours
		WithPasswordPolicy(config.DefaultPasswordPolicy()).
		Build()

	// Initialize Idan
	auth, err := idan.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}
	defer auth.Close()

	// Create router
	mux := http.NewServeMux()

	// Public routes - no authentication required
	mux.HandleFunc("/api/auth/register", auth.RegisterHandler())
	mux.HandleFunc("/api/auth/login", auth.LoginHandler())

	// Protected routes - authentication required
	// Wrap handlers with auth.Require() middleware
	mux.Handle("/api/auth/logout", auth.Require()(http.HandlerFunc(auth.LogoutHandler())))
	mux.Handle("/api/auth/me", auth.Require()(http.HandlerFunc(auth.MeHandler())))
	mux.Handle("/api/auth/refresh", auth.Require()(http.HandlerFunc(auth.RefreshHandler())))

	// Example: Protected dashboard endpoint
	mux.Handle("/api/dashboard", auth.Require()(http.HandlerFunc(dashboardHandler(auth))))

	// Example: Public endpoint with optional auth
	mux.Handle("/api/posts", auth.Optional()(http.HandlerFunc(postsHandler(auth))))

	// Example: Public endpoint (explicitly unprotected)
	mux.Handle("/api/public", auth.Exclude()(http.HandlerFunc(publicHandler)))

	// Start server
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// dashboardHandler is an example of a protected endpoint
// Only authenticated users can access this
func dashboardHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the authenticated user from the request
		user := auth.GetUserFromRequest(r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Welcome to your dashboard!",
			"user":    user.ToResponse(),
		})
	}
}

// postsHandler is an example of an endpoint that works with or without auth
// Different content may be shown based on authentication status
func postsHandler(auth *idan.Idan) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromRequest(r)

		response := map[string]interface{}{
			"posts": []string{"Post 1", "Post 2", "Post 3"},
		}

		if user != nil {
			// User is authenticated - show additional info
			response["authenticated"] = true
			response["user_email"] = user.Email
		} else {
			response["authenticated"] = false
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// publicHandler is a completely public endpoint
func publicHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "This is a public endpoint",
	})
}
