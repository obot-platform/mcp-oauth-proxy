package providers

import (
	"context"

	"golang.org/x/oauth2"
)

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// TokenInfo represents token information from OAuth provider
type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpireAt     int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Provider interface for OAuth providers
type Provider interface {
	// GetAuthorizationURL returns the authorization URL for the provider
	GetAuthorizationURL(clientID, redirectURI, scope, state string) string

	// GetAuthorizationURLWithPKCE returns the authorization URL with PKCE support
	GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge string) string

	// ExchangeCodeForToken exchanges authorization code for tokens
	ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*oauth2.Token, error)

	// GetUserInfo retrieves user information using the access token
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// RefreshToken refreshes an access token using a refresh token
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*oauth2.Token, error)

	// GetName returns the provider name
	GetName() string
}
