package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ContextKey string

// Define the keys that will be used to store/retrieve values from the context.
const (
	UserUUIDKey ContextKey = "userUuid"
	RolesKey    ContextKey = "roles"
	// Add other keys like UserIDKey if you need them.
)

type AppClaims struct {
	// We will use standard JWT claim names for better interoperability.
	// "sub" (Subject) is the standard claim for the user's unique identifier.
	UserUUID string   `json:"sub"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// AuthMiddleware creates a middleware that validates a JWT and populates the context.
func AuthMiddleware(jwtSecret string, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header is required", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader || tokenString == "" {
				http.Error(w, "Invalid token format", http.StatusBadRequest)
				return
			}

			// Parse and validate the token using the shared AppClaims struct.
			token, err := jwt.ParseWithClaims(tokenString, &AppClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(jwtSecret), nil
			})

			// Correctly check for errors OR an invalid token.
			if err != nil || !token.Valid {
				logger.Warn("Token validation failed", "error", err)
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// The type assertion now uses the shared auth.AppClaims.
			if claims, ok := token.Claims.(*AppClaims); ok && claims != nil {
				// Populate the context with the claims.
				ctx := context.WithValue(r.Context(), UserUUIDKey, claims.UserUUID)
				ctx = context.WithValue(ctx, RolesKey, claims.Roles)
				// Pass the new context to the next handler.
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				logger.Error("Could not parse valid token claims, even though token was valid.")
				http.Error(w, "Internal server error: unable to parse token claims", http.StatusInternalServerError)
			}
		})
	}
}

// RequireRole creates a middleware that checks if a user has one of the allowed roles.
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get roles from the context using the correct type assertion.
			userRoles, ok := r.Context().Value(RolesKey).([]string)
			if !ok {
				http.Error(w, "Could not retrieve user roles from context", http.StatusInternalServerError)
				return
			}

			allowedRolesSet := make(map[string]struct{})
			for _, role := range allowedRoles {
				allowedRolesSet[role] = struct{}{}
			}

			for _, role := range userRoles {
				if _, found := allowedRolesSet[role]; found {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden: You don't have the required permissions.", http.StatusForbidden)
		})
	}
}

// GetUserUUIDFromContext securely retrieves and parses the user UUID from the request context.
func GetUserUUIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userUUIDStr, ok := ctx.Value(UserUUIDKey).(string)
	if !ok {
		return uuid.Nil, errors.New("user UUID not found in context")
	}
	if userUUIDStr == "" {
		return uuid.Nil, errors.New("user UUID in context is empty")
	}

	parsedUUID, err := uuid.Parse(userUUIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID format in context: %w", err)
	}

	return parsedUUID, nil
}
