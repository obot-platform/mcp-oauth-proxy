package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GoogleProvider implements the Provider interface for Google OAuth
type GoogleProvider struct {
	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
}

// NewGoogleProvider creates a new Google OAuth provider
func NewGoogleProvider() *GoogleProvider {
	return &GoogleProvider{
		authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		tokenEndpoint:         "https://oauth2.googleapis.com/token",
		userInfoEndpoint:      "https://www.googleapis.com/oauth2/v2/userinfo",
	}
}

// GetAuthorizationURL returns the Google authorization URL
func (g *GoogleProvider) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	return fmt.Sprintf("%s?%s", g.authorizationEndpoint, params.Encode())
}

// GetAuthorizationURLWithPKCE returns the Google authorization URL with PKCE support
func (g *GoogleProvider) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	// Add PKCE parameters if provided
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", codeChallengeMethod)
	}

	return fmt.Sprintf("%s?%s", g.authorizationEndpoint, params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for tokens with Google
func (g *GoogleProvider) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", g.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println(string(body))
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract token information
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing access_token in response")
	}

	tokenType, _ := tokenResp["token_type"].(string)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	expiresIn := 3600 // default
	if exp, ok := tokenResp["expires_in"].(float64); ok {
		expiresIn = int(exp)
	}

	refreshToken, _ := tokenResp["refresh_token"].(string)
	scope, _ := tokenResp["scope"].(string)
	idToken, _ := tokenResp["id_token"].(string)

	return &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        scope,
		IDToken:      idToken,
	}, nil
}

// GetUserInfo retrieves user information from Google
func (g *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", g.userInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d", resp.StatusCode)
	}

	var userResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	userID, _ := userResp["id"].(string)
	email, _ := userResp["email"].(string)
	name, _ := userResp["name"].(string)

	return &UserInfo{
		ID:    userID,
		Email: email,
		Name:  name,
	}, nil
}

// RefreshToken refreshes an access token using a refresh token
func (g *GoogleProvider) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenInfo, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", g.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract token information
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing access_token in response")
	}

	tokenType, _ := tokenResp["token_type"].(string)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	expiresIn := 3600 // default
	if exp, ok := tokenResp["expires_in"].(float64); ok {
		expiresIn = int(exp)
	}

	// Note: Google doesn't return a new refresh token when refreshing
	// The original refresh token remains valid
	scope, _ := tokenResp["scope"].(string)
	idToken, _ := tokenResp["id_token"].(string)

	return &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken, // Keep the original refresh token
		Scope:        scope,
		IDToken:      idToken,
	}, nil
}

// GetName returns the provider name
func (g *GoogleProvider) GetName() string {
	return "google"
}
