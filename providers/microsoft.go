package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// MicrosoftProvider implements OAuth provider for Microsoft
type MicrosoftProvider struct {
	baseURL string
}

// NewMicrosoftProvider creates a new Microsoft provider
func NewMicrosoftProvider() *MicrosoftProvider {
	return &MicrosoftProvider{
		baseURL: "https://login.microsoftonline.com",
	}
}

// GetName returns the provider name
func (p *MicrosoftProvider) GetName() string {
	return "microsoft"
}

// GetAuthorizationURL generates the authorization URL for Microsoft
func (p *MicrosoftProvider) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	if state != "" {
		params.Set("state", state)
	}

	return fmt.Sprintf("%s/common/oauth2/v2.0/authorize?%s", p.baseURL, params.Encode())
}

// GetAuthorizationURLWithPKCE generates the authorization URL with PKCE for Microsoft
func (p *MicrosoftProvider) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	if state != "" {
		params.Set("state", state)
	}
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)

	return fmt.Sprintf("%s/common/oauth2/v2.0/authorize?%s", p.baseURL, params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for tokens
func (p *MicrosoftProvider) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/common/oauth2/v2.0/token", p.baseURL), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &TokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}, nil
}

// RefreshToken refreshes an access token using a refresh token
func (p *MicrosoftProvider) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenInfo, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/common/oauth2/v2.0/token", p.baseURL), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &TokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}, nil
}

// GetUserInfo retrieves user information from Microsoft Graph API
func (p *MicrosoftProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info with status: %d", resp.StatusCode)
	}

	var userResp struct {
		ID    string `json:"id"`
		Email string `json:"userPrincipalName"`
		Name  string `json:"displayName"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}

	return &UserInfo{
		ID:    userResp.ID,
		Email: userResp.Email,
		Name:  userResp.Name,
	}, nil
}
