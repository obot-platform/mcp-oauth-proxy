package mcpui

import (
	"log"
	"net/http"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// Database interface for MCP UI operations
type Database interface {
	GetToken(accessToken string) (*types.TokenData, error)
	GetTokenByRefreshToken(refreshToken string) (*types.TokenData, error)
}

// Manager handles MCP UI authentication flow
type Manager struct {
	jwtManager    *JWTManager
	cookieManager *CookieManager
	tokenManager  *tokens.TokenManager
	providers     *providers.Manager
	providerName  string
	clientID      string
	clientSecret  string
	encryptionKey []byte
	db            Database
}

// NewManager creates a new MCP UI manager
func NewManager(encryptionKey []byte, tokenManager *tokens.TokenManager, providers *providers.Manager, providerName, clientID, clientSecret string, db Database) *Manager {
	return &Manager{
		jwtManager:    NewJWTManager(encryptionKey, encryptionKey), // Use same key for signing and encryption
		cookieManager: NewCookieManager(),
		tokenManager:  tokenManager,
		providers:     providers,
		providerName:  providerName,
		clientID:      clientID,
		clientSecret:  clientSecret,
		encryptionKey: encryptionKey,
		db:            db,
	}
}

// HandleMCPUIRequest processes requests with mcp-ui-code parameter
func (m *Manager) HandleMCPUIRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Check for mcp-ui-code parameter
	mcpUICode := r.URL.Query().Get(MCPUICookieName)
	if mcpUICode == "" {
		return "", false
	}

	// Validate and extract bearer token from JWT
	bearerToken, refreshToken, err := m.jwtManager.ValidateMCPUICode(mcpUICode)
	if err != nil {
		log.Printf("Invalid MCP UI code: %v", err)
		// JWT expired or invalid, need to initiate OAuth flow
		return "", false
	}

	// Set cookies with the bearer token
	m.cookieManager.SetMCPUICookie(w, r, bearerToken)
	if refreshToken != "" {
		m.cookieManager.SetMCPUIRefreshCookie(w, r, refreshToken)
	}

	log.Printf("Successfully set MCP UI cookies from JWT")
	return bearerToken, true
}

// CheckCookieAuth checks if request has valid cookie authentication
func (m *Manager) CheckCookieAuth(r *http.Request) (string, bool) {
	// Try to get bearer token from cookie
	bearerToken, err := m.cookieManager.GetMCPUICookie(r)
	if err != nil {
		return "", false
	}

	// Validate the bearer token
	_, err = m.tokenManager.ValidateAccessToken(bearerToken)
	if err != nil {
		log.Printf("Bearer token from cookie is invalid: %v", err)
		// Try to refresh the token
		refreshedToken, refreshed := m.tryRefreshToken(r)
		if refreshed {
			return refreshedToken, true
		}
		return "", false
	}

	return bearerToken, true
}

// tryRefreshToken attempts to refresh an expired token using the refresh cookie
func (m *Manager) tryRefreshToken(r *http.Request) (string, bool) {
	// Get refresh token from cookie
	refreshToken, err := m.cookieManager.GetMCPUIRefreshCookie(r)
	if err != nil {
		log.Printf("No refresh token available: %v", err)
		return "", false
	}

	// Get provider for token refresh
	provider, err := m.providers.GetProvider(m.providerName)
	if err != nil {
		log.Printf("Failed to get provider for token refresh: %v", err)
		return "", false
	}

	// Refresh the token
	_, err = provider.RefreshToken(r.Context(), refreshToken, m.clientID, m.clientSecret)
	if err != nil {
		log.Printf("Failed to refresh token: %v", err)
		return "", false
	}

	// For now, return empty as we need database integration to update grants
	// This will be implemented when integrating with the main proxy
	log.Printf("Token refresh successful but grant update not implemented in standalone manager")
	return "", false
}

// GenerateMCPUICodeForDownstream creates a JWT for sending to downstream MCP server
func (m *Manager) GenerateMCPUICodeForDownstream(bearerToken, refreshToken string) (string, error) {
	return m.jwtManager.GenerateMCPUICode(bearerToken, refreshToken)
}
