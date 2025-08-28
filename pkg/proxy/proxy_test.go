package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigFromEnv(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"PROXY_MODE":     os.Getenv("PROXY_MODE"),
		"PORT":           os.Getenv("PORT"),
		"MCP_SERVER_URL": os.Getenv("MCP_SERVER_URL"),
	}

	// Restore env vars after test
	defer func() {
		for key, value := range originalVars {
			if value != "" {
				os.Setenv(key, value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	t.Run("DefaultMode", func(t *testing.T) {
		os.Unsetenv("PROXY_MODE")
		os.Setenv("MCP_SERVER_URL", "http://localhost:8081")

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, ModeProxy, config.Mode)
	})

	t.Run("DefaultPort", func(t *testing.T) {
		os.Unsetenv("PORT")
		os.Setenv("PROXY_MODE", ModeForwardAuth)

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "8080", config.Port)
	})

	t.Run("CustomPort", func(t *testing.T) {
		os.Setenv("PORT", "9090")
		os.Setenv("PROXY_MODE", ModeForwardAuth)

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "9090", config.Port)
	})

	t.Run("ValidProxyMode", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeProxy)
		os.Setenv("MCP_SERVER_URL", "http://localhost:8081")

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, ModeProxy, config.Mode)
	})

	t.Run("ValidForwardAuthMode", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeForwardAuth)
		os.Unsetenv("MCP_SERVER_URL") // Not required for forward auth mode

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, ModeForwardAuth, config.Mode)
	})

	t.Run("InvalidMode", func(t *testing.T) {
		os.Setenv("PROXY_MODE", "invalid_mode")

		config, err := LoadConfigFromEnv()
		assert.Error(t, err)
		assert.Nil(t, config)
		assert.Contains(t, err.Error(), "invalid mode: invalid_mode")
	})

	t.Run("ProxyModeRequiresMCPServerURL", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeProxy)
		os.Unsetenv("MCP_SERVER_URL")

		config, err := LoadConfigFromEnv()
		assert.Error(t, err)
		assert.Nil(t, config)
		assert.Contains(t, err.Error(), "invalid MCP server URL")
	})

	t.Run("ForwardAuthModeDoesNotRequireMCPServerURL", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeForwardAuth)
		os.Unsetenv("MCP_SERVER_URL")

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, ModeForwardAuth, config.Mode)
		assert.Empty(t, config.MCPServerURL)
	})

	t.Run("ValidMCPServerURL", func(t *testing.T) {
		testCases := []struct {
			name string
			url  string
		}{
			{"HTTP", "http://localhost:8081"},
			{"HTTPS", "https://api.example.com"},
			{"HTTPWithPort", "http://localhost:3000"},
			{"HTTPSWithPort", "https://api.example.com:8443"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				os.Setenv("PROXY_MODE", ModeProxy)
				os.Setenv("MCP_SERVER_URL", tc.url)

				config, err := LoadConfigFromEnv()
				require.NoError(t, err)
				assert.Equal(t, tc.url, config.MCPServerURL)
			})
		}
	})

	t.Run("InvalidMCPServerURL", func(t *testing.T) {
		testCases := []struct {
			name string
			url  string
		}{
			{"WithPath", "http://localhost:8081/path"},
			{"WithQuery", "http://localhost:8081?query=value"},
			{"WithFragment", "http://localhost:8081#fragment"},
			{"InvalidScheme", "ftp://localhost:8081"},
			{"NoScheme", "localhost:8081"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				os.Setenv("PROXY_MODE", ModeProxy)
				os.Setenv("MCP_SERVER_URL", tc.url)

				config, err := LoadConfigFromEnv()
				assert.Error(t, err)
				assert.Nil(t, config)
			})
		}
	})
}

func TestSetHeaders(t *testing.T) {
	t.Run("AllProperties", func(t *testing.T) {
		header := make(http.Header)
		props := map[string]any{
			"user_id":      "user123",
			"email":        "user@example.com",
			"name":         "John Doe",
			"access_token": "token123",
		}

		setHeaders(header, props)

		assert.Equal(t, "user123", header.Get("X-Forwarded-User"))
		assert.Equal(t, "user@example.com", header.Get("X-Forwarded-Email"))
		assert.Equal(t, "John Doe", header.Get("X-Forwarded-Name"))
		assert.Equal(t, "token123", header.Get("X-Forwarded-Access-Token"))
	})

	t.Run("MissingProperties", func(t *testing.T) {
		header := make(http.Header)
		props := map[string]any{
			"user_id": "user123",
			// Missing email, name, access_token
		}

		setHeaders(header, props)

		assert.Equal(t, "user123", header.Get("X-Forwarded-User"))
		assert.Empty(t, header.Get("X-Forwarded-Email"))
		assert.Empty(t, header.Get("X-Forwarded-Name"))
		assert.Empty(t, header.Get("X-Forwarded-Access-Token"))
	})

	t.Run("EmptyProperties", func(t *testing.T) {
		header := make(http.Header)
		props := map[string]any{}

		setHeaders(header, props)

		assert.Empty(t, header.Get("X-Forwarded-User"))
		assert.Empty(t, header.Get("X-Forwarded-Email"))
		assert.Empty(t, header.Get("X-Forwarded-Name"))
		assert.Empty(t, header.Get("X-Forwarded-Access-Token"))
	})

	t.Run("WrongTypeProperties", func(t *testing.T) {
		header := make(http.Header)
		props := map[string]any{
			"user_id":      123,        // int instead of string
			"email":        true,       // bool instead of string
			"name":         []string{}, // slice instead of string
			"access_token": "token123", // correct type
		}

		setHeaders(header, props)

		// Only the correctly typed property should be set
		assert.Empty(t, header.Get("X-Forwarded-User"))
		assert.Empty(t, header.Get("X-Forwarded-Email"))
		assert.Empty(t, header.Get("X-Forwarded-Name"))
		assert.Equal(t, "token123", header.Get("X-Forwarded-Access-Token"))
	})

	t.Run("NilProperties", func(t *testing.T) {
		header := make(http.Header)

		// Should not panic
		assert.NotPanics(t, func() {
			setHeaders(header, nil)
		})

		assert.Empty(t, header.Get("X-Forwarded-User"))
		assert.Empty(t, header.Get("X-Forwarded-Email"))
		assert.Empty(t, header.Get("X-Forwarded-Name"))
		assert.Empty(t, header.Get("X-Forwarded-Access-Token"))
	})
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "proxy", ModeProxy)
	assert.Equal(t, "forward_auth", ModeForwardAuth)
}

// TestOAuthProxyCreationWithModes tests creating OAuth proxy with different modes
func TestOAuthProxyCreationWithModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OAuth proxy creation tests in short mode")
	}

	baseEnvVars := map[string]string{
		"OAUTH_CLIENT_ID":     "test_client_id",
		"OAUTH_CLIENT_SECRET": "test_client_secret",
		"OAUTH_AUTHORIZE_URL": "https://accounts.google.com",
		"SCOPES_SUPPORTED":    "openid,profile,email",
	}

	// Save and restore environment
	oldVars := make(map[string]string)
	for key := range baseEnvVars {
		oldVars[key] = os.Getenv(key)
	}
	oldVars["PROXY_MODE"] = os.Getenv("PROXY_MODE")
	oldVars["MCP_SERVER_URL"] = os.Getenv("MCP_SERVER_URL")

	defer func() {
		for key, value := range oldVars {
			if value != "" {
				os.Setenv(key, value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	// Set base environment
	for key, value := range baseEnvVars {
		os.Setenv(key, value)
	}

	t.Run("ProxyMode", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeProxy)
		os.Setenv("MCP_SERVER_URL", "http://localhost:8081")

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)

		proxy, err := NewOAuthProxy(config)
		if err != nil {
			t.Skipf("Skipping test due to database connection error: %v", err)
		}
		require.NotNil(t, proxy)

		handler := proxy.GetHandler()
		require.NotNil(t, handler)

		err = proxy.Close()
		assert.NoError(t, err)
	})

	t.Run("ForwardAuthMode", func(t *testing.T) {
		os.Setenv("PROXY_MODE", ModeForwardAuth)
		os.Unsetenv("MCP_SERVER_URL") // Not required for forward auth

		config, err := LoadConfigFromEnv()
		require.NoError(t, err)

		proxy, err := NewOAuthProxy(config)
		if err != nil {
			t.Skipf("Skipping test due to database connection error: %v", err)
		}
		require.NotNil(t, proxy)

		handler := proxy.GetHandler()
		require.NotNil(t, handler)

		err = proxy.Close()
		assert.NoError(t, err)
	})
}

// TestForwardAuthModeIntegration tests forward auth mode behavior with mock requests
func TestForwardAuthModeIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Set up test environment for forward auth mode
	testEnvVars := map[string]string{
		"OAUTH_CLIENT_ID":     "test_client_id",
		"OAUTH_CLIENT_SECRET": "test_client_secret",
		"OAUTH_AUTHORIZE_URL": "https://accounts.google.com",
		"SCOPES_SUPPORTED":    "openid,profile,email",
		"PROXY_MODE":          ModeForwardAuth,
		"PORT":                "8080",
	}

	// Save original environment
	oldVars := make(map[string]string)
	for key, value := range testEnvVars {
		oldVars[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	// Restore environment after test
	defer func() {
		for key, value := range oldVars {
			if value != "" {
				os.Setenv(key, value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	// Create OAuth proxy in forward auth mode
	config, err := LoadConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, ModeForwardAuth, config.Mode)

	oauthProxy, err := NewOAuthProxy(config)
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	defer func() {
		_ = oauthProxy.Close()
	}()

	handler := oauthProxy.GetHandler()

	t.Run("ForwardAuthRequiresAuth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		handler.ServeHTTP(w, req)

		// Should require authorization
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer")
	})

	t.Run("HealthEndpointStillWorks", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/health", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	t.Run("MetadataEndpointsWork", func(t *testing.T) {
		// Test OAuth authorization server metadata
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "authorization_endpoint")

		// Test protected resource metadata
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "resource")

		// Test protected resource metadata with path
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/test/path", nil)
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "resource")
	})
}

// TestModeSpecificValidation tests that validation rules work correctly for different modes
func TestModeSpecificValidation(t *testing.T) {
	testCases := []struct {
		name           string
		mode           string
		mcpServerURL   string
		expectError    bool
		errorContains  string
	}{
		{
			name:         "ProxyModeValidURL",
			mode:         ModeProxy,
			mcpServerURL: "http://localhost:8081",
			expectError:  false,
		},
		{
			name:         "ProxyModeHTTPSURL",
			mode:         ModeProxy,
			mcpServerURL: "https://api.example.com",
			expectError:  false,
		},
		{
			name:          "ProxyModeMissingURL",
			mode:          ModeProxy,
			mcpServerURL:  "",
			expectError:   true,
			errorContains: "invalid MCP server URL",
		},
		{
			name:          "ProxyModeInvalidScheme",
			mode:          ModeProxy,
			mcpServerURL:  "ftp://localhost:8081",
			expectError:   true,
			errorContains: "invalid MCP server URL",
		},
		{
			name:          "ProxyModeWithPath",
			mode:          ModeProxy,
			mcpServerURL:  "http://localhost:8081/path",
			expectError:   true,
			errorContains: "must not contain a path",
		},
		{
			name:          "ProxyModeWithQuery",
			mode:          ModeProxy,
			mcpServerURL:  "http://localhost:8081?query=value",
			expectError:   true,
			errorContains: "must not contain a path, query",
		},
		{
			name:        "ForwardAuthNoURL",
			mode:        ModeForwardAuth,
			mcpServerURL: "",
			expectError: false,
		},
		{
			name:         "ForwardAuthWithURL",
			mode:         ModeForwardAuth,
			mcpServerURL: "http://localhost:8081",
			expectError:  false,
		},
		{
			name:         "ForwardAuthInvalidURL",
			mode:         ModeForwardAuth,
			mcpServerURL: "invalid-url",
			expectError:  false, // URL validation is skipped for forward auth mode
		},
	}

	// Save original environment
	originalMode := os.Getenv("PROXY_MODE")
	originalURL := os.Getenv("MCP_SERVER_URL")
	defer func() {
		if originalMode != "" {
			os.Setenv("PROXY_MODE", originalMode)
		} else {
			os.Unsetenv("PROXY_MODE")
		}
		if originalURL != "" {
			os.Setenv("MCP_SERVER_URL", originalURL)
		} else {
			os.Unsetenv("MCP_SERVER_URL")
		}
	}()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("PROXY_MODE", tc.mode)
			if tc.mcpServerURL != "" {
				os.Setenv("MCP_SERVER_URL", tc.mcpServerURL)
			} else {
				os.Unsetenv("MCP_SERVER_URL")
			}

			config, err := LoadConfigFromEnv()

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				assert.Equal(t, tc.mode, config.Mode)
				assert.Equal(t, tc.mcpServerURL, config.MCPServerURL)
			}
		})
	}
}

// TestHeaderOverwriting tests that headers are properly overwritten
func TestHeaderOverwriting(t *testing.T) {
	header := make(http.Header)
	
	// Set initial headers
	header.Set("X-Forwarded-User", "old-user")
	header.Set("X-Forwarded-Email", "old@example.com")

	props := map[string]any{
		"user_id": "new-user",
		"email":   "new@example.com",
		"name":    "New Name",
	}

	setHeaders(header, props)

	// Headers should be overwritten
	assert.Equal(t, "new-user", header.Get("X-Forwarded-User"))
	assert.Equal(t, "new@example.com", header.Get("X-Forwarded-Email"))
	assert.Equal(t, "New Name", header.Get("X-Forwarded-Name"))
	assert.Empty(t, header.Get("X-Forwarded-Access-Token"))
}

// TestSpecialCharactersInHeaders tests handling of special characters
func TestSpecialCharactersInHeaders(t *testing.T) {
	header := make(http.Header)
	props := map[string]any{
		"user_id": "user@domain.com",
		"email":   "test+tag@example.com",
		"name":    "John O'Doe",
		"access_token": "token-with-special-chars_123",
	}

	setHeaders(header, props)

	assert.Equal(t, "user@domain.com", header.Get("X-Forwarded-User"))
	assert.Equal(t, "test+tag@example.com", header.Get("X-Forwarded-Email"))
	assert.Equal(t, "John O'Doe", header.Get("X-Forwarded-Name"))
	assert.Equal(t, "token-with-special-chars_123", header.Get("X-Forwarded-Access-Token"))
}

// BenchmarkSetHeaders benchmarks the header setting function
func BenchmarkSetHeaders(t *testing.B) {
	header := make(http.Header)
	props := map[string]any{
		"user_id":      "user123",
		"email":        "user@example.com",
		"name":         "John Doe",
		"access_token": "token123",
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		// Clear headers between iterations
		for key := range header {
			delete(header, key)
		}
		setHeaders(header, props)
	}
}