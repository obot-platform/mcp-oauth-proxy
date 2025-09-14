package validate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/mcpui"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type TokenValidator struct {
	tokenManager    *tokens.TokenManager
	encryptionKey   []byte
	mcpUIManager    *mcpui.Manager     // Optional MCP UI manager for JWT handling
	db              TokenStore         // Database for refresh operations
	provider        providers.Provider // OAuth provider for generating auth URLs
	clientID        string             // OAuth client ID
	clientSecret    string             // OAuth client secret
	scopesSupported []string           // Supported OAuth scopes
}

// TokenStore interface for database operations needed by validator
type TokenStore interface {
	GetToken(accessToken string) (*types.TokenData, error)
	GetTokenByRefreshToken(refreshToken string) (*types.TokenData, error)
	StoreToken(token *types.TokenData) error
	RevokeToken(token string) error
	StoreAuthRequest(key string, data map[string]any) error
}

func NewTokenValidator(tokenManager *tokens.TokenManager, mcpUIManager *mcpui.Manager, encryptionKey []byte, db TokenStore, provider providers.Provider, clientID, clientSecret string, scopesSupported []string) *TokenValidator {
	return &TokenValidator{
		mcpUIManager:    mcpUIManager,
		tokenManager:    tokenManager,
		encryptionKey:   encryptionKey,
		db:              db,
		provider:        provider,
		clientID:        clientID,
		clientSecret:    clientSecret,
		scopesSupported: scopesSupported,
	}
}

func (p *TokenValidator) SetOAuthConfig(provider providers.Provider, clientID, clientSecret string, scopesSupported []string) {
	p.provider = provider
	p.clientID = clientID
	p.clientSecret = clientSecret
	p.scopesSupported = scopesSupported
}

// generatePKCE generates PKCE code verifier and challenge
func generatePKCE() (codeVerifier, codeChallenge string) {
	// Generate a random code verifier (43-128 characters, base64url)
	codeVerifier = encryption.GenerateRandomString(32) // This generates 32 bytes -> ~43 chars in base64

	// Generate code challenge using S256 method
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge
}

// validateCookieAuth handles cookie-based authentication with refresh capability
// Returns (tokenInfo, bearerToken, success)
func (p *TokenValidator) validateCookieAuth(w http.ResponseWriter, r *http.Request, bearerToken string) (*tokens.TokenInfo, string, bool) {
	// Validate the bearer token directly
	tokenInfo, err := p.tokenManager.GetTokenInfo(bearerToken)
	if err == nil {
		return tokenInfo, bearerToken, true
	}

	// Step 2: Token is invalid, check for refresh token
	refreshCookie, refreshErr := r.Cookie(mcpui.MCPUIRefreshCookieName)
	if refreshErr != nil || refreshCookie.Value == "" {
		return nil, "", false
	}

	refreshToken := refreshCookie.Value

	// Step 3: Start refresh process
	return p.performMCPUIRefresh(w, r, bearerToken, refreshToken)
}

// performMCPUIRefresh handles the MCP UI token refresh process
// Returns (tokenInfo, bearerToken, success)
func (p *TokenValidator) performMCPUIRefresh(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) (*tokens.TokenInfo, string, bool) {
	// Get token data by MCP UI refresh token
	tokenData, err := p.db.GetTokenByRefreshToken(refreshToken)
	if err != nil {
		return nil, "", false
	}

	return p.rotateMCPUITokens(w, r, tokenData)
}

// rotateMCPUITokens rotates access token and MCP UI refresh token, keeping regular refresh token unchanged
// Returns (tokenInfo, bearerToken, success)
func (p *TokenValidator) rotateMCPUITokens(w http.ResponseWriter, r *http.Request, tokenData *types.TokenData) (*tokens.TokenInfo, string, bool) {
	// Generate new access token
	accessTokenSecret := encryption.GenerateRandomString(32)
	newAccessToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, accessTokenSecret)

	// Generate new MCP UI refresh token
	mcpUIRefreshTokenSecret := encryption.GenerateRandomString(32)
	newMCPUIRefreshToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, mcpUIRefreshTokenSecret)

	// Create updated token data (regular refresh token stays unchanged)
	updatedTokenData := &types.TokenData{
		AccessToken:           newAccessToken,
		RefreshToken:          newMCPUIRefreshToken,
		ClientID:              tokenData.ClientID,
		UserID:                tokenData.UserID,
		GrantID:               tokenData.GrantID,
		Scope:                 tokenData.Scope,
		ExpiresAt:             time.Now().Add(1 * time.Hour),   // 1 hour
		RefreshTokenExpiresAt: tokenData.RefreshTokenExpiresAt, // Keep unchanged
		CreatedAt:             time.Now(),
		Revoked:               false,
	}

	// Store updated tokens in database
	if err := p.db.StoreToken(updatedTokenData); err != nil {
		return nil, "", false
	}

	// Revoke old access token
	if err := p.db.RevokeToken(tokenData.AccessToken); err != nil {
		log.Printf("❌ Failed to revoke old access token: %v", err)
	}

	// Set cookies with new tokens
	p.setCookiesForRefresh(w, r, newAccessToken, newMCPUIRefreshToken)

	// Validate the new access token and return token info
	newTokenInfo, err := p.tokenManager.GetTokenInfo(newAccessToken)
	if err != nil {
		log.Printf("❌ Failed to validate newly created access token: %v", err)
		return nil, "", false
	}

	return newTokenInfo, newAccessToken, true
}

// setCookiesForRefresh sets the MCP UI cookies after successful refresh
func (p *TokenValidator) setCookiesForRefresh(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     mcpui.MCPUICookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   3600, // 1 hour
	})

	// Set refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     mcpui.MCPUIRefreshCookieName,
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   30 * 24 * 3600, // 30 days
	})
}

func (p *TokenValidator) WithTokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Try cookie-based authentication with refresh capability
			var bearerTokenFromCookie string
			mcpUICodeCookie, err := r.Cookie(mcpui.MCPUICookieName)
			if err == nil && mcpUICodeCookie.Value != "" {
				bearerTokenFromCookie = mcpUICodeCookie.Value
			}

			if tokenInfo, bearerToken, success := p.validateCookieAuth(w, r, bearerTokenFromCookie); success {
				// Add token info to request context
				ctx := context.WithValue(r.Context(), tokenInfoKey{}, tokenInfo)
				ctx = context.WithValue(ctx, bearerTokenKey{}, bearerToken)
				next(w, r.WithContext(ctx))
				return
			} else if bearerTokenFromCookie != "" {
				p.handleOauthFlow(w, r)
				return
			}

			// Fall back to URL parameter (contains JWT)
			mcpUICodeParam := r.URL.Query().Get("mcp-ui-code")
			if mcpUICodeParam != "" {
				bearerToken, handled := p.mcpUIManager.HandleMCPUIRequest(w, r)
				if handled {
					tokenInfo, err := p.tokenManager.GetTokenInfo(bearerToken)
					if err != nil {
						p.handleOauthFlow(w, r)
						return
					}

					// Add token info to request context
					ctx := context.WithValue(r.Context(), tokenInfoKey{}, tokenInfo)
					ctx = context.WithValue(ctx, bearerTokenKey{}, bearerToken)
					next(w, r.WithContext(ctx))
					return
				} else {
					p.handleOauthFlow(w, r)
					return
				}
			}

			// Return 401 with proper WWW-Authenticate header
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Missing Authorization header",
			})
			return
		}

		// Parse Authorization header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid Authorization header format, expected 'Bearer TOKEN'", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid Authorization header format, expected 'Bearer TOKEN'",
			})
			return
		}

		token := parts[1]

		tokenInfo, err := p.tokenManager.GetTokenInfo(token)
		if err != nil {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid or expired token", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid or expired token",
			})
			return
		}

		// Decrypt props if needed before storing in context
		if tokenInfo.Props != nil {
			decryptedProps, err := encryption.DecryptPropsIfNeeded(p.encryptionKey, tokenInfo.Props)
			if err != nil {
				resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource", handlerutils.GetBaseURL(r))
				wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Failed to decrypt token data", resource_metadata="%s"`, resourceMetadataUrl)
				w.Header().Set("WWW-Authenticate", wwwAuthValue)
				handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
					"error":             "invalid_token",
					"error_description": "Failed to decrypt token data",
				})
				return
			}
			tokenInfo.Props = decryptedProps
		}

		// Store both tokenInfo and the original bearer token string
		ctx := context.WithValue(r.Context(), tokenInfoKey{}, tokenInfo)
		ctx = context.WithValue(ctx, bearerTokenKey{}, token)
		next(w, r.WithContext(ctx))
	}
}

func (p *TokenValidator) handleOauthFlow(w http.ResponseWriter, r *http.Request) {
	// Check if this is a browser request by looking at user agent
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		// Not a browser request, return 401
		resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource", handlerutils.GetBaseURL(r))
		wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Authentication required", resource_metadata="%s"`, resourceMetadataUrl)
		w.Header().Set("WWW-Authenticate", wwwAuthValue)
		handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_token",
			"error_description": "Authentication required",
		})
		return
	}

	// Check if OAuth provider is configured
	if p.provider == nil || p.clientID == "" || p.clientSecret == "" {
		handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "OAuth provider not configured",
		})
		return
	}

	// Generate PKCE parameters
	codeVerifier, codeChallenge := generatePKCE()

	// Generate a random state key for this auth request
	stateKey := encryption.GenerateRandomString(32)

	// Get current path for post-auth redirect
	currentPath := r.URL.Path
	if r.URL.RawQuery != "" {
		currentPath += "?" + r.URL.RawQuery
	}

	// Store the auth request data in the database with PKCE parameters
	authData := map[string]any{
		"response_type":         "code",
		"client_id":             p.clientID,
		"redirect_uri":          fmt.Sprintf("%s/callback", handlerutils.GetBaseURL(r)),
		"scope":                 strings.Join(p.scopesSupported, " "),
		"state":                 stateKey,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"code_verifier":         codeVerifier, // Store for later use in token exchange
		"rd":                    currentPath,  // Store original path for post-auth redirect
	}

	if err := p.db.StoreAuthRequest(stateKey, authData); err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to store authorization request",
		})
		return
	}

	// Build the authorization URL directly to OAuth provider (not our /authorize)
	redirectURI := fmt.Sprintf("%s/callback", handlerutils.GetBaseURL(r))
	scope := strings.Join(p.scopesSupported, " ")

	// Generate authorization URL with PKCE
	authURL := p.provider.GetAuthorizationURL(p.clientID, redirectURI, scope, stateKey)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func GetTokenInfo(r *http.Request) *tokens.TokenInfo {
	return r.Context().Value(tokenInfoKey{}).(*tokens.TokenInfo)
}

func GetBearerToken(r *http.Request) string {
	if token := r.Context().Value(bearerTokenKey{}); token != nil {
		return token.(string)
	}
	return ""
}

type tokenInfoKey struct{}
type bearerTokenKey struct{}
