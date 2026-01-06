package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// ErrInvalidTokenFormat is returned when the token format is not recognized.
var ErrInvalidTokenFormat = errors.New("invalid token format")

// TokenManager handles token generation and validation
type TokenManager struct {
	db              Database
	keyFunc         keyfunc.Keyfunc
	apiKeyValidator *APIKeyValidator
}

// Database interface for token operations
type Database interface {
	GetToken(accessToken string) (*types.TokenData, error)
	GetGrant(grantID, userID string) (*types.Grant, error)
}

// NewTokenManager creates a new token manager
func NewTokenManager(db Database) (*TokenManager, error) {
	return NewTokenManagerWithJWKSURLAndAPIKeyAuth(db, "", "")
}

// NewTokenManagerWithJWKSURL creates a new token manager that will also trust JWT tokens from the specified URL.
func NewTokenManagerWithJWKSURL(db Database, jwksURL string) (*TokenManager, error) {
	return NewTokenManagerWithJWKSURLAndAPIKeyAuth(db, jwksURL, "")
}

// NewTokenManagerWithJWKSURLAndAPIKeyAuth creates a new token manager with JWT and API key support.
func NewTokenManagerWithJWKSURLAndAPIKeyAuth(db Database, jwksURL, apiKeyAuthURL string) (*TokenManager, error) {
	var keyFunc keyfunc.Keyfunc
	if jwksURL != "" {
		var err error
		keyFunc, err = keyfunc.NewDefault([]string{jwksURL})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT key: %w", err)
		}
	}

	var apiKeyValidator *APIKeyValidator
	if apiKeyAuthURL != "" {
		apiKeyValidator = NewAPIKeyValidator(apiKeyAuthURL)
	}

	return &TokenManager{
		db:              db,
		keyFunc:         keyFunc,
		apiKeyValidator: apiKeyValidator,
	}, nil
}

// validateAccessToken validates and parses a simple string access token
func (tm *TokenManager) validateAccessToken(tokenString string) (*TokenInfo, error) {
	// Parse the token string
	parts := strings.Split(tokenString, ":")
	if len(parts) != 3 {
		if tm.keyFunc == nil {
			return nil, ErrInvalidTokenFormat
		}

		// If this isn't a token for us, then we should check if it's a JWT token
		token, err := jwt.Parse(tokenString, tm.keyFunc.Keyfunc)
		if err != nil {
			return nil, ErrInvalidTokenFormat
		}
		if !token.Valid {
			return nil, fmt.Errorf("invalid token")
		}

		sub, err := token.Claims.GetSubject()
		if err != nil {
			return nil, fmt.Errorf("invalid JWT token")
		}

		var expTime time.Time
		if exp, _ := token.Claims.GetExpirationTime(); exp != nil {
			expTime = exp.Time
		}

		info, _ := json.Marshal(map[string]any{
			"sub": sub,
		})

		return &TokenInfo{
			UserID: sub,
			Props: map[string]any{
				"access_token": tokenString,
				"info":         string(info),
			},
			ExpiresAt: expTime,
		}, nil
	}

	if tm.db == nil {
		return nil, fmt.Errorf("database not configured for token validation")
	}

	userID := parts[0]
	grantID := parts[1]

	// Get token data from database
	tokenData, err := tm.db.GetToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}

	// Check if token is revoked
	if tokenData.Revoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Check if token is expired
	if time.Now().After(tokenData.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	// Get the grant to access props
	grant, err := tm.db.GetGrant(grantID, userID)
	if err != nil {
		return nil, fmt.Errorf("grant not found: %w", err)
	}

	// Create TokenInfo with the grant's props
	claims := &TokenInfo{
		UserID:    userID,
		GrantID:   grantID,
		Props:     grant.Props,
		ExpiresAt: tokenData.ExpiresAt,
	}

	return claims, nil
}

// GetTokenInfo extracts user information from a valid token
func (tm *TokenManager) GetTokenInfo(tokenString string) (*TokenInfo, error) {
	return tm.GetTokenInfoWithContext(context.Background(), tokenString, "")
}

// GetTokenInfoWithContext extracts user information from a valid token with context support.
// For API keys, mcpID can be provided for scoped authorization.
func (tm *TokenManager) GetTokenInfoWithContext(ctx context.Context, tokenString, mcpID string) (*TokenInfo, error) {
	// Try JWT/simple token validation first
	claims, err := tm.validateAccessToken(tokenString)
	if err != nil {
		// If token format is not recognized, try API key validation
		if errors.Is(err, ErrInvalidTokenFormat) {
			if tm.apiKeyValidator == nil {
				return nil, err // Return the original error
			}
			return tm.apiKeyValidator.ValidateAPIKey(ctx, tokenString, mcpID)
		}
		return nil, err
	}

	return &TokenInfo{
		UserID:    claims.UserID,
		GrantID:   claims.GrantID,
		Props:     claims.Props,
		ExpiresAt: claims.ExpiresAt,
	}, nil
}

// TokenInfo represents token information
type TokenInfo struct {
	UserID    string
	GrantID   string
	Props     map[string]any
	ExpiresAt time.Time
}
