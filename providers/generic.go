package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OAuthMetadata represents OAuth authorization server metadata
type OAuthMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
}

// GenericProvider implements a generic OAuth provider
type GenericProvider struct {
	clientID     string
	clientSecret string
	authorizeURL string
	metadata     *OAuthMetadata
	httpClient   *http.Client
}

// NewGenericProvider creates a new generic OAuth provider
func NewGenericProvider() *GenericProvider {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	authorizeURL := os.Getenv("OAUTH_AUTHORIZE_URL")

	return &GenericProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		authorizeURL: authorizeURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// discoverEndpoints attempts to discover OAuth endpoints using well-known paths
func (p *GenericProvider) discoverEndpoints() error {
	if p.metadata != nil {
		return nil // Already discovered
	}

	// Parse the authorize URL to get the base URL
	parsedURL, err := url.Parse(p.authorizeURL)
	if err != nil {
		return fmt.Errorf("invalid authorize URL: %w", err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Try different well-known paths
	wellKnownPaths := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	}

	for _, path := range wellKnownPaths {
		var metadataURL string
		if path == "/.well-known/oauth-authorization-server" {
			metadataURL = baseURL + path + parsedURL.Path
		} else {
			metadataURL = baseURL + parsedURL.Path + path
		}
		metadata, err := p.fetchMetadata(metadataURL)
		if err == nil && metadata != nil {
			p.metadata = metadata

			// for github, there is no userinfo endpoint, so we need to provide a hardcoded one
			if p.metadata.UserinfoEndpoint == "" && parsedURL.Host == "github.com" {
				p.metadata.UserinfoEndpoint = "https://api.github.com/user"
			}
			return nil
		}
	}

	// If no metadata found, create a basic metadata structure
	p.metadata = &OAuthMetadata{
		Issuer:                 baseURL,
		AuthorizationEndpoint:  p.authorizeURL,
		TokenEndpoint:          baseURL + "/token",
		UserinfoEndpoint:       baseURL + "/userinfo",
		ScopesSupported:        []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}

	return nil
}

// fetchMetadata fetches OAuth metadata from a URL
func (p *GenericProvider) fetchMetadata(metadataURL string) (*OAuthMetadata, error) {
	resp, err := p.httpClient.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the function
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch metadata: %s", resp.Status)
	}

	var metadata OAuthMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// GetAuthorizationURL returns the authorization URL for the provider
func (p *GenericProvider) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	if err := p.discoverEndpoints(); err != nil {
		// Fallback to basic URL construction
		u, _ := url.Parse(p.authorizeURL)
		q := u.Query()
		q.Set("response_type", "code")
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", scope)
		q.Set("state", state)

		// Add provider-specific parameters for refresh tokens
		p.addRefreshTokenParams(q)

		u.RawQuery = q.Encode()
		return u.String()
	}

	u, _ := url.Parse(p.metadata.AuthorizationEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)

	// Add provider-specific parameters for refresh tokens
	p.addRefreshTokenParams(q)

	u.RawQuery = q.Encode()
	return u.String()
}

// GetAuthorizationURLWithPKCE returns the authorization URL with PKCE support
func (p *GenericProvider) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) string {
	if err := p.discoverEndpoints(); err != nil {
		// Fallback to basic URL construction
		u, _ := url.Parse(p.authorizeURL)
		q := u.Query()
		q.Set("response_type", "code")
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("scope", scope)
		q.Set("state", state)
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", codeChallengeMethod)

		// Add provider-specific parameters for refresh tokens
		p.addRefreshTokenParams(q)

		u.RawQuery = q.Encode()
		return u.String()
	}

	u, _ := url.Parse(p.metadata.AuthorizationEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", codeChallengeMethod)

	// Add provider-specific parameters for refresh tokens
	p.addRefreshTokenParams(q)

	u.RawQuery = q.Encode()
	return u.String()
}

// addRefreshTokenParams adds provider-specific parameters to request refresh tokens
func (p *GenericProvider) addRefreshTokenParams(q url.Values) {
	// Detect provider based on authorization URL or discovered endpoints
	var isGoogle, isMicrosoft bool

	if p.metadata != nil && p.metadata.AuthorizationEndpoint != "" {
		isGoogle = strings.Contains(p.metadata.AuthorizationEndpoint, "accounts.google.com")
		isMicrosoft = strings.Contains(p.metadata.AuthorizationEndpoint, "login.microsoftonline.com")
	} else {
		isGoogle = strings.Contains(p.authorizeURL, "accounts.google.com")
		isMicrosoft = strings.Contains(p.authorizeURL, "login.microsoftonline.com")
	}

	// Google OAuth requires specific parameters for refresh tokens
	if isGoogle {
		q.Set("access_type", "offline") // Request refresh token
		q.Set("prompt", "consent")      // Always show consent screen to get refresh token
	}

	// Microsoft OAuth requires specific parameters
	if isMicrosoft {
		q.Set("response_mode", "query")
		// Add offline_access scope for Microsoft to get refresh tokens
		currentScope := q.Get("scope")
		if currentScope != "" && !strings.Contains(currentScope, "offline_access") {
			q.Set("scope", currentScope+" https://graph.microsoft.com/offline_access")
		} else if currentScope == "" {
			q.Set("scope", "https://graph.microsoft.com/offline_access")
		}
	}
}

// ExchangeCodeForToken exchanges authorization code for tokens
func (p *GenericProvider) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	if err := p.discoverEndpoints(); err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", p.metadata.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the function
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", resp.Status)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	tokenInfo := &TokenInfo{
		AccessToken:  getString(tokenResp, "access_token"),
		TokenType:    getString(tokenResp, "token_type"),
		ExpireAt:     time.Now().Add(time.Duration(getInt(tokenResp, "expires_in")) * time.Second).Unix(),
		RefreshToken: getString(tokenResp, "refresh_token"),
		Scope:        getString(tokenResp, "scope"),
		IDToken:      getString(tokenResp, "id_token"),
	}

	return tokenInfo, nil
}

// GetUserInfo retrieves user information using the access token
func (p *GenericProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if err := p.discoverEndpoints(); err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	if p.metadata.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.metadata.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the function
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}

	var userInfoResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfoResp); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	var userInfo *UserInfo
	if p.metadata.UserinfoEndpoint == "https://api.github.com/user" {
		userInfo = &UserInfo{
			ID:    getString(userInfoResp, "login"),
			Email: getString(userInfoResp, "email"),
			Name:  getString(userInfoResp, "name"),
		}
	} else {
		userInfo = &UserInfo{
			ID:    getString(userInfoResp, "sub"),
			Email: getString(userInfoResp, "email"),
			Name:  getString(userInfoResp, "name"),
		}
	}

	// If sub is not available, try other common ID fields
	if userInfo.ID == "" {
		userInfo.ID = getString(userInfoResp, "id")
	}

	return userInfo, nil
}

// RefreshToken refreshes an access token using a refresh token
func (p *GenericProvider) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenInfo, error) {
	if err := p.discoverEndpoints(); err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", p.metadata.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the function
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %s", resp.Status)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	tokenInfo := &TokenInfo{
		AccessToken:  getString(tokenResp, "access_token"),
		TokenType:    getString(tokenResp, "token_type"),
		ExpireAt:     time.Now().Add(time.Duration(getInt(tokenResp, "expires_in")) * time.Second).Unix(),
		RefreshToken: getString(tokenResp, "refresh_token"),
		Scope:        getString(tokenResp, "scope"),
		IDToken:      getString(tokenResp, "id_token"),
	}

	return tokenInfo, nil
}

// GetName returns the provider name
func (p *GenericProvider) GetName() string {
	return "generic"
}

// Helper functions
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return 0
}
