package callback

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/mcpui"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type Store interface {
	StoreGrant(grant *types.Grant) error
	StoreAuthCode(code, grantID, userID string) error
	GetAuthRequest(key string) (map[string]any, error)
	DeleteAuthRequest(key string) error
	StoreToken(token *types.TokenData) error
}

type Handler struct {
	db            Store
	provider      providers.Provider
	encryptionKey []byte
	clientID      string
	clientSecret  string
	mcpUIManager  MCPUIManager
	routePrefix   string
}

// MCPUIManager interface for generating JWT tokens
type MCPUIManager interface {
	GenerateMCPUICodeForDownstream(bearerToken, refreshToken string) (string, error)
}

func NewHandler(db Store, provider providers.Provider, encryptionKey []byte, clientID, clientSecret, routePrefix string, mcpUIManager MCPUIManager) http.Handler {
	return &Handler{
		db:            db,
		provider:      provider,
		encryptionKey: encryptionKey,
		clientID:      clientID,
		clientSecret:  clientSecret,
		mcpUIManager:  mcpUIManager,
		routePrefix:   routePrefix,
	}
}

// scopeContainsProfileOrEmail checks if the given scopes contain profile or email
func (p *Handler) scopeContainsProfileOrEmail(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "profile" || scope == "email" {
			return true
		}
	}
	return false
}

// getStringFromMap safely extracts a string value from a map[string]any
func getStringFromMap(data map[string]any, key string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// setMCPUISessionCookies sets secure HttpOnly session cookies for MCP UI authentication
func (p *Handler) setMCPUISessionCookies(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	// Determine if request is secure
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// Set access token cookie (1 hour)
	http.SetCookie(w, &http.Cookie{
		Name:     mcpui.MCPUICookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600, // 1 hour
	})

	// Set refresh token cookie (30 days)
	http.SetCookie(w, &http.Cookie{
		Name:     mcpui.MCPUIRefreshCookieName,
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 3600, // 30 days
	})
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle OAuth callback from external providers
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Check for OAuth errors
	if error != "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            error,
			ErrorDescription: errorDescription,
		})
		return
	}

	// Validate required parameters
	if code == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing authorization code",
		})
		return
	}

	// Retrieve auth request data from database using state as key
	authData, err := p.db.GetAuthRequest(state)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid or expired state parameter",
		})
		return
	}

	// Convert auth data back to AuthRequest struct
	authReq := types.AuthRequest{
		ResponseType:        getStringFromMap(authData, "response_type"),
		ClientID:            getStringFromMap(authData, "client_id"),
		RedirectURI:         getStringFromMap(authData, "redirect_uri"),
		Scope:               getStringFromMap(authData, "scope"),
		State:               getStringFromMap(authData, "state"),
		CodeChallenge:       getStringFromMap(authData, "code_challenge"),
		CodeChallengeMethod: getStringFromMap(authData, "code_challenge_method"),
	}

	// Clean up the auth request data after successful retrieval
	defer func() {
		if err := p.db.DeleteAuthRequest(state); err != nil {
			log.Printf("Failed to delete auth request: %v", err)
		}
	}()

	// Get provider credentials
	redirectURI := fmt.Sprintf("%s%s/callback", handlerutils.GetBaseURL(r), p.routePrefix)

	// Exchange code for tokens
	tokenInfo, err := p.provider.ExchangeCodeForToken(r.Context(), code, p.clientID, p.clientSecret, redirectURI)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to exchange authorization code",
		})
		return
	}

	// Check if scope includes profile or email before getting user info
	scopes := strings.Fields(authReq.Scope)
	needsUserInfo := p.scopeContainsProfileOrEmail(scopes)

	userInfo := &providers.UserInfo{}
	if needsUserInfo {
		// Get user info from the provider
		userInfo, err = p.provider.GetUserInfo(r.Context(), tokenInfo.AccessToken)
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Failed to get user information",
			})
			return
		}
	}

	// Create a grant for this user
	grantID := encryption.GenerateRandomString(16)
	now := time.Now().Unix()

	// Prepare sensitive props data
	sensitiveProps := map[string]any{
		"access_token":  tokenInfo.AccessToken,
		"refresh_token": tokenInfo.RefreshToken,
		"expires_at":    tokenInfo.Expiry.Unix(),
	}

	// Only add user info if we have it
	if needsUserInfo {
		sensitiveProps["email"] = userInfo.Email
		sensitiveProps["name"] = userInfo.Name
	}

	// Initialize props map
	props := make(map[string]any)

	// Encrypt the sensitive props data
	encryptedProps, err := encryption.EncryptData(sensitiveProps, p.encryptionKey)
	if err != nil {
		log.Printf("Failed to encrypt props data: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to encrypt sensitive data",
		})
		return
	}

	// Store encrypted data
	props["encrypted_data"] = encryptedProps.Data
	props["iv"] = encryptedProps.IV
	props["algorithm"] = encryptedProps.Algorithm
	props["encrypted"] = true

	grant := &types.Grant{
		ID:       grantID,
		ClientID: authReq.ClientID,
		UserID:   userInfo.ID,
		Scope:    scopes,
		Metadata: map[string]any{
			"provider": p.provider,
		},
		Props:               props,
		CreatedAt:           now,
		ExpiresAt:           now + 3600*24*30, // 30 days to expire for grant, same as refresh token
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
	}

	// Store the grant
	if err := p.db.StoreGrant(grant); err != nil {
		log.Printf("Failed to store grant: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store grant",
		})
		return
	}

	// Generate authorization code
	randomPart := encryption.GenerateRandomString(32)
	authCode := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, randomPart)

	// Store the authorization code
	if err := p.db.StoreAuthCode(authCode, grantID, userInfo.ID); err != nil {
		log.Printf("Failed to store authorization code: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store authorization code",
		})
		return
	}

	if rdValue := getStringFromMap(authData, "rd"); rdValue != "" {
		// This is an MCP UI flow - you should be able to issue session cookies
		log.Printf("🔄 Processing MCP UI OAuth callback")

		// Generate internal application tokens (separate from OAuth provider tokens)
		accessTokenSecret := encryption.GenerateRandomString(32)
		accessToken := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, accessTokenSecret)

		mcpUIRefreshTokenSecret := encryption.GenerateRandomString(32)
		mcpUIRefreshToken := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, mcpUIRefreshTokenSecret)

		// Store internal tokens in database
		tokenData := &types.TokenData{
			AccessToken:  accessToken,
			RefreshToken: mcpUIRefreshToken,
			ClientID:     authReq.ClientID,
			UserID:       userInfo.ID,
			GrantID:      grantID,
			Scope:        authReq.Scope,
			ExpiresAt:    time.Now().Add(1 * time.Hour), // 1 hour for access token
			CreatedAt:    time.Now(),
			Revoked:      false,
		}

		if err := p.db.StoreToken(tokenData); err != nil {
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to store tokens",
			})
			return
		}

		// Set secure HttpOnly session cookies
		p.setMCPUISessionCookies(w, r, accessToken, mcpUIRefreshToken)

		// Redirect to success page with original path as parameter
		baseURL := handlerutils.GetBaseURL(r)
		successURL := fmt.Sprintf("%s/auth/mcp-ui/success?rd=%s", baseURL, url.QueryEscape(rdValue))

		http.Redirect(w, r, successURL, http.StatusFound)
		return
	}

	// Build the redirect URL back to the client
	redirectURL := authReq.RedirectURI

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Invalid redirect URL",
		})
		return
	}

	query := parsedURL.Query()
	query.Set("code", authCode)
	if authReq.State != "" {
		query.Set("state", authReq.State)
	}
	parsedURL.RawQuery = query.Encode()

	// Redirect back to the client
	w.Header().Set("Location", parsedURL.String())
	w.WriteHeader(http.StatusFound)
}
