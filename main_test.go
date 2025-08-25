package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationFlow(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Note: Using standard HTTP handlers instead of Gin

	// Set required environment variables for testing
	oldVars := map[string]string{
		"OAUTH_CLIENT_ID":     os.Getenv("OAUTH_CLIENT_ID"),
		"OAUTH_CLIENT_SECRET": os.Getenv("OAUTH_CLIENT_SECRET"),
		"OAUTH_AUTHORIZE_URL": os.Getenv("OAUTH_AUTHORIZE_URL"),
		"SCOPES_SUPPORTED":    os.Getenv("SCOPES_SUPPORTED"),
		"MCP_SERVER_URL":      os.Getenv("MCP_SERVER_URL"),
		"DATABASE_DSN":        os.Getenv("DATABASE_DSN"),
	}

	// Set test environment variables
	testEnvVars := map[string]string{
		"OAUTH_CLIENT_ID":     "test_client_id",
		"OAUTH_CLIENT_SECRET": "test_client_secret",
		"OAUTH_AUTHORIZE_URL": "https://accounts.google.com",
		"SCOPES_SUPPORTED":    "openid,profile,email",
		"MCP_SERVER_URL":      "http://localhost:8081",
		"DATABASE_DSN":        os.Getenv("TEST_DATABASE_DSN"), // Use test database if available
	}

	for key, value := range testEnvVars {
		if value != "" {
			if err := os.Setenv(key, value); err != nil {
				t.Logf("Failed to set %s: %v", key, err)
			}
		}
	}

	// Restore environment variables after test
	defer func() {
		for key, value := range oldVars {
			if value != "" {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()

	// Create OAuth proxy
	config := proxy.LoadConfigFromEnv()
	oauthProxy, err := proxy.NewOAuthProxy(config)
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	defer func() {
		if err := oauthProxy.Close(); err != nil {
			t.Logf("Error closing OAuth proxy: %v", err)
		}
	}()

	// Get HTTP handler
	handler := oauthProxy.GetHandler()

	// Test health endpoint
	t.Run("HealthEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/health", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	// Test OAuth metadata endpoints
	t.Run("OAuthMetadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "authorization_endpoint")
		assert.Contains(t, w.Body.String(), "token_endpoint")
	})

	// Test protected resource metadata
	t.Run("ProtectedResourceMetadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "resource")
		assert.Contains(t, w.Body.String(), "authorization_servers")
	})

	// Test MCP endpoint requires authorization
	t.Run("MCPEndpointRequiresAuth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/mcp", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer")
	})

	// Test authorization endpoint redirects (basic validation)
	t.Run("AuthorizationEndpointRedirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8080/callback&scope=openid", nil)
		handler.ServeHTTP(w, req)

		// Should get a redirect to the OAuth provider or an error about invalid client
		assert.True(t, w.Code == http.StatusFound || w.Code == http.StatusBadRequest)
	})
}

func TestOAuthProxyCreation(t *testing.T) {
	// Test that we can create an OAuth proxy without errors when all required env vars are set
	oldVars := map[string]string{
		"OAUTH_CLIENT_ID":     os.Getenv("OAUTH_CLIENT_ID"),
		"OAUTH_CLIENT_SECRET": os.Getenv("OAUTH_CLIENT_SECRET"),
		"OAUTH_AUTHORIZE_URL": os.Getenv("OAUTH_AUTHORIZE_URL"),
		"SCOPES_SUPPORTED":    os.Getenv("SCOPES_SUPPORTED"),
		"MCP_SERVER_URL":      os.Getenv("MCP_SERVER_URL"),
	}

	// Set minimal required environment
	testEnvVars := map[string]string{
		"OAUTH_CLIENT_ID":     "test_client_id",
		"OAUTH_CLIENT_SECRET": "test_client_secret",
		"OAUTH_AUTHORIZE_URL": "https://accounts.google.com",
		"SCOPES_SUPPORTED":    "openid,profile,email",
		"MCP_SERVER_URL":      "http://localhost:8081",
	}

	for key, value := range testEnvVars {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	// Restore environment variables after test
	defer func() {
		for key, value := range oldVars {
			if value != "" {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()

	// Create OAuth proxy
	config := proxy.LoadConfigFromEnv()
	oauthProxy, err := proxy.NewOAuthProxy(config)
	require.NoError(t, err, "Should be able to create OAuth proxy with valid environment")
	require.NotNil(t, oauthProxy, "OAuth proxy should not be nil")

	// Test that we can get handler without error
	require.NotPanics(t, func() {
		handler := oauthProxy.GetHandler()
		require.NotNil(t, handler)
	}, "GetHandler should not panic and should return non-nil handler")

	// Clean up
	err = oauthProxy.Close()
	assert.NoError(t, err, "Should be able to close OAuth proxy")
}

func TestOAuthProxyStart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OAuth proxy start test in short mode")
	}

	// Set minimal required environment
	testEnvVars := map[string]string{
		"OAUTH_CLIENT_ID":     "test_client_id",
		"OAUTH_CLIENT_SECRET": "test_client_secret",
		"OAUTH_AUTHORIZE_URL": "https://accounts.google.com",
		"SCOPES_SUPPORTED":    "openid,profile,email",
		"MCP_SERVER_URL":      "http://localhost:8081",
	}

	oldVars := make(map[string]string)
	for key, value := range testEnvVars {
		oldVars[key] = os.Getenv(key)
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	// Restore environment variables after test
	defer func() {
		for key, value := range oldVars {
			if value != "" {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()

	// Create OAuth proxy
	config := proxy.LoadConfigFromEnv()
	oauthProxy, err := proxy.NewOAuthProxy(config)
	require.NoError(t, err)
	defer func() {
		_ = oauthProxy.Close()
	}()

	// Test starting and stopping the proxy
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the proxy in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- oauthProxy.Start(ctx)
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to stop the server
	cancel()

	// Wait for the server to stop
	select {
	case err := <-errCh:
		// Server stopped, which is expected when context is cancelled
		if err != nil {
			assert.Contains(t, err.Error(), "context canceled", "Expected context cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Server did not stop within timeout")
	}
}
