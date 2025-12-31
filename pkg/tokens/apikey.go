package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

const (
	// APIKeyPrefix is the prefix that identifies Obot API keys.
	APIKeyPrefix = "ok1-"
)

// IsAPIKey checks if the token is an Obot API key (starts with "ok1-").
func IsAPIKey(token string) bool {
	return strings.HasPrefix(token, APIKeyPrefix)
}

// APIKeyValidator validates API keys by calling the authentication webhook.
type APIKeyValidator struct {
	authURL    string
	httpClient *http.Client
}

// NewAPIKeyValidator creates a new API key validator.
func NewAPIKeyValidator(authURL string) *APIKeyValidator {
	return &APIKeyValidator{
		authURL: authURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ValidateAPIKey validates an API key by calling the authentication webhook.
// Returns TokenInfo on success, or an error if authentication/authorization fails.
func (v *APIKeyValidator) ValidateAPIKey(ctx context.Context, apiKey, mcpID string) (*TokenInfo, error) {
	if v.authURL == "" {
		return nil, fmt.Errorf("API key auth URL not configured")
	}

	// Build request body
	reqBody := types.APIKeyAuthRequest{
		MCPID: mcpID,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.authURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Make the request
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call auth webhook: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Parse response
	var authResp types.APIKeyAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !authResp.Authenticated {
		errMsg := "authentication failed"
		if authResp.Error != "" {
			errMsg = authResp.Error
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	if !authResp.Authorized {
		errMsg := "authorization failed"
		if authResp.Error != "" {
			errMsg = authResp.Error
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Build user info JSON for props
	userInfo, _ := json.Marshal(map[string]any{
		"sub":      fmt.Sprintf("%d", authResp.UserID),
		"username": authResp.Username,
	})

	// Return token info
	return &TokenInfo{
		UserID: fmt.Sprintf("%d", authResp.UserID),
		Props: map[string]any{
			"info":         string(userInfo),
			"api_key":      true,
			"access_token": apiKey,
		},
	}, nil
}
