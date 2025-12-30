package tokens

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

func TestIsAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "valid API key prefix",
			token:    "ok1-123-456-secret",
			expected: true,
		},
		{
			name:     "API key with just prefix",
			token:    "ok1-",
			expected: true,
		},
		{
			name:     "JWT token",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expected: false,
		},
		{
			name:     "simple token format",
			token:    "user123:grant456:secret789",
			expected: false,
		},
		{
			name:     "empty token",
			token:    "",
			expected: false,
		},
		{
			name:     "similar but different prefix",
			token:    "ok2-123-456-secret",
			expected: false,
		},
		{
			name:     "prefix in middle of token",
			token:    "someprefix-ok1-123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAPIKey(tt.token)
			if result != tt.expected {
				t.Errorf("IsAPIKey(%q) = %v, want %v", tt.token, result, tt.expected)
			}
		})
	}
}

func TestAPIKeyValidator_ValidateAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		apiKey         string
		mcpServerID    string
		mcpInstanceID  string
		serverResponse *types.APIKeyAuthResponse
		serverStatus   int
		expectError    bool
		expectedUserID string
	}{
		{
			name:          "successful authentication and authorization",
			apiKey:        "ok1-1-2-secret",
			mcpServerID:   "server-123",
			mcpInstanceID: "instance-456",
			serverResponse: &types.APIKeyAuthResponse{
				Authenticated: true,
				Authorized:    true,
				UserID:        42,
				Username:      "testuser",
			},
			serverStatus:   http.StatusOK,
			expectError:    false,
			expectedUserID: "42",
		},
		{
			name:          "authentication failed",
			apiKey:        "ok1-invalid-key",
			mcpServerID:   "server-123",
			mcpInstanceID: "instance-456",
			serverResponse: &types.APIKeyAuthResponse{
				Authenticated: false,
				Authorized:    false,
				Error:         "invalid API key",
			},
			serverStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:          "authenticated but not authorized",
			apiKey:        "ok1-1-2-secret",
			mcpServerID:   "server-123",
			mcpInstanceID: "instance-456",
			serverResponse: &types.APIKeyAuthResponse{
				Authenticated: true,
				Authorized:    false,
				Error:         "access denied to this MCP server",
			},
			serverStatus: http.StatusOK,
			expectError:  true,
		},
		{
			name:          "server error",
			apiKey:        "ok1-1-2-secret",
			mcpServerID:   "server-123",
			mcpInstanceID: "instance-456",
			serverResponse: &types.APIKeyAuthResponse{
				Authenticated: false,
				Authorized:    false,
				Error:         "internal error",
			},
			serverStatus: http.StatusInternalServerError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the request
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}

				authHeader := r.Header.Get("Authorization")
				expectedAuth := "Bearer " + tt.apiKey
				if authHeader != expectedAuth {
					t.Errorf("expected Authorization header %q, got %q", expectedAuth, authHeader)
				}

				// Verify request body
				var reqBody types.APIKeyAuthRequest
				if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if reqBody.MCPServerID != tt.mcpServerID {
					t.Errorf("expected MCPServerID %q, got %q", tt.mcpServerID, reqBody.MCPServerID)
				}
				if reqBody.MCPServerInstanceID != tt.mcpInstanceID {
					t.Errorf("expected MCPServerInstanceID %q, got %q", tt.mcpInstanceID, reqBody.MCPServerInstanceID)
				}

				w.WriteHeader(tt.serverStatus)
				if err := json.NewEncoder(w).Encode(tt.serverResponse); err != nil {
					t.Errorf("failed to encode response: %v", err)
				}
			}))
			defer server.Close()

			// Create validator with test server URL
			validator := NewAPIKeyValidator(server.URL)

			// Validate the API key
			tokenInfo, err := validator.ValidateAPIKey(context.Background(), tt.apiKey, tt.mcpServerID, tt.mcpInstanceID)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tokenInfo.UserID != tt.expectedUserID {
				t.Errorf("expected UserID %q, got %q", tt.expectedUserID, tokenInfo.UserID)
			}

			// Verify props contain expected values
			if tokenInfo.Props["api_key"] != true {
				t.Errorf("expected api_key prop to be true")
			}
			if tokenInfo.Props["access_token"] != tt.apiKey {
				t.Errorf("expected access_token prop to be %q, got %v", tt.apiKey, tokenInfo.Props["access_token"])
			}
		})
	}
}

func TestAPIKeyValidator_EmptyAuthURL(t *testing.T) {
	validator := NewAPIKeyValidator("")

	_, err := validator.ValidateAPIKey(context.Background(), "ok1-test", "", "")
	if err == nil {
		t.Error("expected error for empty auth URL, got none")
	}
}
