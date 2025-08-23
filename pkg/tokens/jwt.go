package tokens

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// TokenManager handles token generation and validation
type TokenManager struct {
	secretKey []byte
	db        Database
}

// Database interface for token operations
type Database interface {
	GetToken(accessToken string) (interface{}, error)
	GetGrant(grantID, userID string) (interface{}, error)
}

type TokenClaims struct {
	UserID    string                 `json:"user_id"`
	GrantID   string                 `json:"grant_id"`
	Props     map[string]interface{} `json:"props,omitempty"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// NewTokenManager creates a new token manager
func NewTokenManager() (*TokenManager, error) {
	// Generate a random secret key if not provided
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("failed to generate secret key: %w", err)
	}

	return &TokenManager{
		secretKey: secretKey,
	}, nil
}

// SetDatabase sets the database dependency for token operations
func (tm *TokenManager) SetDatabase(db Database) {
	tm.db = db
}

// ValidateAccessToken validates and parses a simple string access token
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	if tm.db == nil {
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
	tokenDataInterface, err := tm.db.GetToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}

	tokenData, ok := tokenDataInterface.(*types.TokenData)
	if !ok {
		return nil, fmt.Errorf("invalid token data type")
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
	grantInterface, err := tm.db.GetGrant(grantID, userID)
	if err != nil {
		return nil, fmt.Errorf("grant not found: %w", err)
	}

	grant, ok := grantInterface.(*types.Grant)
	if !ok {
		return nil, fmt.Errorf("invalid grant data type")
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
	Props     map[string]interface{}
	ExpiresAt time.Time
}
