package tokens

import (
	"fmt"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// TokenManager handles token generation and validation
type TokenManager struct {
	DB Database
}

// Database interface for token operations
type Database interface {
	GetToken(accessToken string) (*types.TokenData, error)
	GetGrant(grantID, userID string) (*types.Grant, error)
}

type TokenClaims struct {
	UserID    string         `json:"user_id"`
	GrantID   string         `json:"grant_id"`
	Props     map[string]any `json:"props,omitempty"`
	ExpiresAt time.Time      `json:"expires_at"`
}

// NewTokenManager creates a new token manager
func NewTokenManager(db Database) (*TokenManager, error) {
	return &TokenManager{
		DB: db,
	}, nil
}

// ValidateAccessToken validates and parses a simple string access token
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	if tm.DB == nil {
		return nil, fmt.Errorf("database not configured for token validation")
	}

	// Parse the token string
	parts := strings.Split(tokenString, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	userID := parts[0]
	grantID := parts[1]

	// Get token data from database
	tokenData, err := tm.DB.GetToken(tokenString)
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
	grant, err := tm.DB.GetGrant(grantID, userID)
	if err != nil {
		return nil, fmt.Errorf("grant not found: %w", err)
	}

	// Create TokenClaims with the grant's props
	claims := &TokenClaims{
		UserID:    userID,
		GrantID:   grantID,
		Props:     grant.Props,
		ExpiresAt: tokenData.ExpiresAt,
	}

	return claims, nil
}

// GetTokenInfo extracts user information from a valid token
func (tm *TokenManager) GetTokenInfo(tokenString string) (*TokenInfo, error) {
	claims, err := tm.ValidateAccessToken(tokenString)
	if err != nil {
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
