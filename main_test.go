package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mcp-oauth-proxy/database"
	"mcp-oauth-proxy/providers"
	"mcp-oauth-proxy/tokens"
)

// MockProvider implements the Provider interface for testing
type MockProvider struct {
	name string
}

func (m *MockProvider) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("response_type", "code")
	return fmt.Sprintf("https://mock-provider.com/oauth/authorize?%s", params.Encode())
}

func (m *MockProvider) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("response_type", "code")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)
	return fmt.Sprintf("https://mock-provider.com/oauth/authorize?%s", params.Encode())
}

func (m *MockProvider) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*providers.TokenInfo, error) {
	// Mock token response
	return &providers.TokenInfo{
		AccessToken:  "mock_access_token_" + code,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "mock_refresh_token_" + code,
		Scope:        "read write",
		IDToken:      "mock_id_token_" + code,
	}, nil
}

func (m *MockProvider) GetUserInfo(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	// Mock user info
	return &providers.UserInfo{
		ID:    "mock_user_123",
		Email: "test@example.com",
		Name:  "Test User",
	}, nil
}

func (m *MockProvider) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*providers.TokenInfo, error) {
	// Mock refresh response
	return &providers.TokenInfo{
		AccessToken:  "mock_new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "mock_new_refresh_token",
		Scope:        "read write",
	}, nil
}

func (m *MockProvider) GetName() string {
	return m.name
}

// TestSuite holds test configuration and dependencies
type TestSuite struct {
	proxy    *OAuthProxy
	router   *gin.Engine
	server   *httptest.Server
	db       *database.Database
	provider *MockProvider
}

// setupTestSuite creates a test environment with mock dependencies
func setupTestSuite(t *testing.T) *TestSuite {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Set environment variables for testing
	if err := os.Setenv("OAUTH_CLIENT_ID", "test_client"); err != nil {
		t.Logf("Failed to set OAUTH_CLIENT_ID: %v", err)
	}
	if err := os.Setenv("OAUTH_CLIENT_SECRET", "test_secret"); err != nil {
		t.Logf("Failed to set OAUTH_CLIENT_SECRET: %v", err)
	}
	if err := os.Setenv("MCP_SERVER_URL", "http://localhost:8081"); err != nil {
		t.Logf("Failed to set MCP_SERVER_URL: %v", err)
	}

	// Create test database (in-memory SQLite would be better for tests)
	// For now, we'll use a test PostgreSQL instance
	testDSN := os.Getenv("TEST_DATABASE_DSN")
	if testDSN == "" {
		testDSN = "postgres://test:test@localhost:5432/oauth_test?sslmode=disable"
	}

	db, err := database.NewDatabase(testDSN)
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
	}

	// Create mock provider
	mockProvider := &MockProvider{name: "mock"}

	// Create provider manager
	providerManager := providers.NewManager()
	providerManager.RegisterProvider("mock", mockProvider)

	// Create token manager
	tokenManager, err := tokens.NewTokenManager()
	require.NoError(t, err)
	tokenManager.SetDatabase(&databaseAdapter{db: db})

	// Create OAuth proxy
	proxy := &OAuthProxy{
		metadata: &OAuthMetadata{
			Issuer:                                   "https://test.example.com",
			AuthorizationEndpoint:                    "https://test.example.com/oauth/authorize",
			TokenEndpoint:                            "https://test.example.com/oauth/token",
			RevocationEndpoint:                       "https://test.example.com/oauth/revoke",
			RegistrationEndpoint:                     "https://test.example.com/oauth/register",
			ResponseTypesSupported:                   []string{"code"},
			CodeChallengeMethodsSupported:            []string{"S256"},
			TokenEndpointAuthMethodsSupported:        []string{"client_secret_basic", "client_secret_post"},
			GrantTypesSupported:                      []string{"authorization_code", "refresh_token"},
			ScopesSupported:                          []string{"read", "write", "admin"},
			RevocationEndpointAuthMethodsSupported:   []string{"client_secret_basic"},
			RegistrationEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		db:           db,
		rateLimiter:  NewRateLimiter(1*time.Minute, 100),
		providers:    providerManager,
		tokenManager: tokenManager,
		provider:     "mock",
		resourceName: "test-resource",
	}

	// Setup routes
	router := gin.New()
	proxy.setupRoutes(router)

	// Create test server
	server := httptest.NewServer(router)

	return &TestSuite{
		proxy:    proxy,
		router:   router,
		server:   server,
		db:       db,
		provider: mockProvider,
	}
}

// cleanupTestSuite cleans up test resources
func (ts *TestSuite) cleanupTestSuite() {
	if ts.server != nil {
		ts.server.Close()
	}
	if ts.db != nil {
		if err := ts.db.Close(); err != nil {
			// Log error but don't fail the test
			fmt.Printf("Error closing database: %v\n", err)
		}
	}
}

// generateCodeVerifier generates a PKCE code verifier
func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge generates a PKCE code challenge
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// TestOAuthMetadataEndpoint tests the OAuth metadata endpoint
func TestOAuthMetadataEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	req, err := http.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	require.NoError(t, err)
	req.Host = "test.example.com"

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var metadata OAuthMetadata
	err = json.Unmarshal(w.Body.Bytes(), &metadata)
	require.NoError(t, err)

	assert.Equal(t, "http://test.example.com", metadata.Issuer)
	assert.Equal(t, "http://test.example.com/authorize", metadata.AuthorizationEndpoint)
	assert.Equal(t, "http://test.example.com/token", metadata.TokenEndpoint)
	assert.Contains(t, metadata.ResponseTypesSupported, "code")
	assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")
}

// TestProtectedResourceMetadataEndpoint tests the protected resource metadata endpoint
func TestProtectedResourceMetadataEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	req, err := http.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	require.NoError(t, err)
	req.Host = "test.example.com"

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var metadata OAuthProtectedResourceMetadata
	err = json.Unmarshal(w.Body.Bytes(), &metadata)
	require.NoError(t, err)

	assert.Equal(t, "http://test.example.com/mcp", metadata.Resource)
	assert.Contains(t, metadata.AuthorizationServers, "http://test.example.com")
}

// TestAuthorizationEndpoint tests the OAuth authorization endpoint
func TestAuthorizationEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// create a random client ID
	clientID := "test_client_" + generateRandomStringSafe(8)

	// Register a test client first
	clientInfo := &database.ClientInfo{
		ClientID:                clientID,
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	err := ts.db.StoreClient(clientInfo)
	require.NoError(t, err)

	// Test authorization request
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "https://test.example.com/callback")
	params.Set("scope", "read write")
	params.Set("state", "test_state")

	req, err := http.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	// Should redirect to mock provider
	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://mock-provider.com/oauth/authorize")
	assert.Contains(t, location, "client_id=test_client")
}

// TestCallbackEndpoint tests the OAuth callback endpoint
func TestCallbackEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Test callback with authorization code
	params := url.Values{}
	params.Set("code", "test_code")

	authReq := &AuthRequest{
		ResponseType: "code",
		ClientID:     "test_client",
		RedirectURI:  "https://test.example.com/callback",
		Scope:        "read write",
		State:        "test_state",
	}

	authReqData, err := json.Marshal(authReq)
	require.NoError(t, err)
	encodedState := base64.StdEncoding.EncodeToString(authReqData)
	params.Set("state", encodedState)

	req, err := http.NewRequest("GET", "/callback?"+params.Encode(), nil)
	require.NoError(t, err)
	req.Host = "test.example.com"

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	// Should redirect back to client with authorization code
	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "test.example.com/callback")
	assert.Contains(t, location, "code=mock_user_123")
	assert.Contains(t, location, "state=test_state")
}

// TestTokenEndpoint tests the OAuth token endpoint
func TestTokenEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// create a random client ID
	clientID := "test_client_" + generateRandomStringSafe(8)

	// Register a test client first
	clientInfo := &database.ClientInfo{
		ClientID:                clientID,
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client Token",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	err := ts.db.StoreClient(clientInfo)
	require.NoError(t, err)

	// create a random grant ID
	grantID := "test_grant_" + generateRandomStringSafe(8)

	// Create a test grant
	grant := &database.Grant{
		ID:        grantID,
		ClientID:  clientID,
		UserID:    "mock_user_123",
		Scope:     []string{"read", "write"},
		Metadata:  map[string]interface{}{"provider": "mock"},
		Props:     map[string]interface{}{"email": "test@example.com"},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	err = ts.db.StoreGrant(grant)
	require.NoError(t, err)

	// Create a test authorization code
	authCode := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))
	err = ts.db.StoreAuthCode(authCode, grant.ID, grant.UserID)
	require.NoError(t, err)

	// Test token exchange with authorization code
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", authCode)
	tokenData.Set("client_id", clientID)
	tokenData.Set("redirect_uri", "https://test.example.com/callback")

	req, err := http.NewRequest("POST", "/token", strings.NewReader(tokenData.Encode()))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, 3600, tokenResponse.ExpiresIn)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
	assert.Equal(t, "read write", tokenResponse.Scope)
}

// TestTokenEndpointWithPKCE tests the OAuth token endpoint with PKCE
func TestTokenEndpointWithPKCE(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// create a random client ID
	clientID := "test_client_pkce_token_" + generateRandomStringSafe(8)

	// Register a test client first
	clientInfo := &database.ClientInfo{
		ClientID:                clientID,
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client PKCE Token",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	err := ts.db.StoreClient(clientInfo)
	require.NoError(t, err)

	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// create a random grant ID
	grantID := "test_grant_pkce_" + generateRandomStringSafe(8)

	// Create a test grant with PKCE
	grant := &database.Grant{
		ID:                  grantID,
		ClientID:            clientID,
		UserID:              "mock_user_123",
		Scope:               []string{"read", "write"},
		Metadata:            map[string]interface{}{"provider": "mock"},
		Props:               map[string]interface{}{"email": "test@example.com"},
		CreatedAt:           time.Now().Unix(),
		ExpiresAt:           time.Now().Add(10 * time.Minute).Unix(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}
	err = ts.db.StoreGrant(grant)
	require.NoError(t, err)

	// Create a test authorization code
	authCode := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))
	err = ts.db.StoreAuthCode(authCode, grant.ID, grant.UserID)
	require.NoError(t, err)

	// Test token exchange with PKCE
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", authCode)
	tokenData.Set("client_id", clientID)
	tokenData.Set("redirect_uri", "https://test.example.com/callback")
	tokenData.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", "/token", strings.NewReader(tokenData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test_client_pkce_token:test_secret")))

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, 3600, tokenResponse.ExpiresIn)
}

// TestRefreshTokenEndpoint tests the OAuth refresh token endpoint
func TestRefreshTokenEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// create a random client ID
	clientID := "test_client_refresh_" + generateRandomStringSafe(8)

	// Register a test client first
	clientInfo := &database.ClientInfo{
		ClientID:                clientID,
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client Refresh",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	err := ts.db.StoreClient(clientInfo)
	require.NoError(t, err)

	// create a random grant ID
	grantID := "test_grant_refresh_" + generateRandomStringSafe(8)

	grant := &database.Grant{
		ID:        grantID,
		ClientID:  clientID,
		UserID:    "mock_user_123",
		Scope:     []string{"read", "write"},
		Metadata:  map[string]interface{}{"provider": "mock"},
		Props:     map[string]interface{}{"email": "test@example.com"},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	err = ts.db.StoreGrant(grant)
	require.NoError(t, err)

	// Create a test token with refresh token
	accessToken := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))
	refreshToken := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))

	tokenData := &database.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       "mock_user_123",
		GrantID:      grantID,
		Scope:        "read write",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	err = ts.db.StoreToken(tokenData)
	require.NoError(t, err)

	// Test refresh token request
	refreshData := url.Values{}
	refreshData.Set("grant_type", "refresh_token")
	refreshData.Set("refresh_token", refreshToken)
	refreshData.Set("client_id", clientID)

	req, err := http.NewRequest("POST", "/token", strings.NewReader(refreshData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test_client_refresh:test_secret")))

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, 3600, tokenResponse.ExpiresIn)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
	assert.Equal(t, "read write", tokenResponse.Scope)
}

// TestRevokeEndpoint tests the OAuth revocation endpoint
func TestRevokeEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// create a random client ID
	clientID := "test_client_revoke_" + generateRandomStringSafe(8)

	// Register a test client first
	clientInfo := &database.ClientInfo{
		ClientID:                clientID,
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client Revoke",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	err := ts.db.StoreClient(clientInfo)
	require.NoError(t, err)

	// create a random grant ID
	grantID := "test_grant_revoke_" + generateRandomStringSafe(8)

	grant := &database.Grant{
		ID:        grantID,
		ClientID:  clientID,
		UserID:    "mock_user_123",
		Scope:     []string{"read", "write"},
		Metadata:  map[string]interface{}{"provider": "mock"},
		Props:     map[string]interface{}{"email": "test@example.com"},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	err = ts.db.StoreGrant(grant)
	require.NoError(t, err)

	accessToken := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))
	refreshToken := fmt.Sprintf("%s:%s:%s", grant.UserID, grantID, generateRandomStringSafe(8))

	// Create a test token
	tokenData := &database.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       "mock_user_123",
		GrantID:      grantID,
		Scope:        "read write",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	err = ts.db.StoreToken(tokenData)
	require.NoError(t, err)

	// Test token revocation
	revokeData := url.Values{}
	revokeData.Set("token", accessToken)
	revokeData.Set("client_id", clientID)
	revokeData.Set("token_type_hint", "access_token")

	req, err := http.NewRequest("POST", "/revoke", strings.NewReader(revokeData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify token is revoked
	revokedToken, err := ts.db.GetToken(accessToken)
	require.NoError(t, err)
	assert.True(t, revokedToken.Revoked)
}

// TestRegisterEndpoint tests the OAuth client registration endpoint
func TestRegisterEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Test client registration
	registrationData := map[string]interface{}{
		"redirect_uris":              []string{"https://test.example.com/callback"},
		"client_name":                "Test Registration Client",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
	}

	jsonData, err := json.Marshal(registrationData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var clientInfo ClientInfo
	err = json.Unmarshal(w.Body.Bytes(), &clientInfo)
	require.NoError(t, err)

	assert.NotEmpty(t, clientInfo.ClientID)
	assert.NotEmpty(t, clientInfo.ClientSecret)
	assert.Equal(t, "Test Registration Client", clientInfo.ClientName)
	assert.Equal(t, []string{"https://test.example.com/callback"}, clientInfo.RedirectUris)
	assert.Equal(t, []string{"authorization_code"}, clientInfo.GrantTypes)
	assert.Equal(t, []string{"code"}, clientInfo.ResponseTypes)
}

type TestResponseRecorder struct {
	*httptest.ResponseRecorder
	closeChannel chan bool
}

func (r *TestResponseRecorder) CloseNotify() <-chan bool {
	return r.closeChannel
}

func CreateTestResponseRecorder() *TestResponseRecorder {
	return &TestResponseRecorder{
		httptest.NewRecorder(),
		make(chan bool, 1),
	}
}

// TestMCPProxyEndpoint tests the MCP proxy endpoint
func TestMCPProxyEndpoint(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Create a real HTTP server for the MCP server
	mcpServer := &http.Server{
		Addr: ":8081",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify forwarded headers
			assert.Equal(t, "mock_user_123", r.Header.Get("X-Forwarded-User"))
			assert.Equal(t, "test@example.com", r.Header.Get("X-Forwarded-Email"))
			assert.Equal(t, "Test User", r.Header.Get("X-Forwarded-Name"))

			// Return a mock MCP response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"jsonrpc": "2.0", "result": "success", "id": 1}`)); err != nil {
				t.Logf("Failed to write response: %v", err)
			}
		}),
	}

	// Start the MCP server in a goroutine
	go func() {
		if err := mcpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("MCP server error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Ensure the server is stopped at the end
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mcpServer.Shutdown(ctx); err != nil {
			t.Logf("Failed to shutdown MCP server: %v", err)
		}
	}()

	// create a random grant ID
	grantID := "test_grant_mcp_" + generateRandomStringSafe(8)

	grant := &database.Grant{
		ID:       grantID,
		ClientID: "test_client_mcp",
		UserID:   "mock_user_123",
		Scope:    []string{"read", "write"},
		Metadata: map[string]interface{}{"provider": "mock"},
		Props:    map[string]interface{}{"email": "test@example.com", "user_id": "mock_user_123", "name": "Test User"},
	}
	err := ts.db.StoreGrant(grant)
	require.NoError(t, err)

	// create a random access token
	accessToken := fmt.Sprintf("%s:%s:%s", "mock_user_123", grantID, generateRandomStringSafe(8))
	refreshToken := fmt.Sprintf("%s:%s:%s", "mock_user_123", "test_grant_mcp_123", generateRandomStringSafe(8))

	// Create a test token
	tokenData := &database.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     "test_client_mcp",
		UserID:       "mock_user_123",
		GrantID:      grantID,
		Scope:        "read write",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	err = ts.db.StoreToken(tokenData)
	require.NoError(t, err)

	// Test MCP proxy request with valid token
	req, err := http.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc": "2.0", "method": "test", "params": {}}`))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	// The request should pass authentication but may fail at the proxy level
	// We're testing that the authentication middleware works correctly
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)

	// If the proxy fails due to no MCP server, that's expected in test environment
	// The important thing is that authentication passed
	if w.Code == http.StatusBadGateway {
		t.Log("Proxy failed as expected (no MCP server running)")
	} else {
		t.Logf("Request completed with status: %d", w.Code)
	}
}

// TestMCPProxyEndpointUnauthorized tests the MCP proxy endpoint without authentication
func TestMCPProxyEndpointUnauthorized(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Test MCP proxy request without token
	req, err := http.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc": "2.0", "method": "test", "params": {}}`))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRateLimiting tests the rate limiting functionality
func TestRateLimiting(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Make multiple requests to trigger rate limiting
	for i := 0; i < 105; i++ {
		req, err := http.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		require.NoError(t, err)
		req.Host = "test.example.com"

		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)

		if i < 100 {
			assert.Equal(t, http.StatusOK, w.Code)
		} else {
			// After 100 requests, should be rate limited
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
		}
	}
}

// TestErrorHandling tests various error scenarios
func TestErrorHandling(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		{
			name:           "Invalid Authorization Request - Missing client_id",
			method:         "GET",
			path:           "/authorize?response_type=code&redirect_uri=https://test.example.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "Should return 400 when client_id is missing",
		},
		{
			name:           "Invalid Authorization Request - Invalid response_type",
			method:         "GET",
			path:           "/authorize?response_type=invalid&client_id=test&redirect_uri=https://test.example.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "Should return 400 when response_type is invalid",
		},
		{
			name:           "Non-existent endpoint",
			method:         "GET",
			path:           "/non-existent",
			expectedStatus: http.StatusNotFound,
			description:    "Should return 404 for non-existent endpoints",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			var err error

			if tt.method == "POST" {
				req, err = http.NewRequest(tt.method, tt.path, strings.NewReader("grant_type=invalid"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req, err = http.NewRequest(tt.method, tt.path, nil)
			}
			require.NoError(t, err)

			w := httptest.NewRecorder()
			ts.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

// TestIntegrationFlow tests a complete OAuth flow
func TestIntegrationFlow(t *testing.T) {
	ts := setupTestSuite(t)
	defer ts.cleanupTestSuite()

	// Create a real HTTP server for the MCP server
	mcpServer := &http.Server{
		Addr: ":8081",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify forwarded headers
			assert.Equal(t, "mock_user_123", r.Header.Get("X-Forwarded-User"))
			assert.Equal(t, "test@example.com", r.Header.Get("X-Forwarded-Email"))
			assert.Equal(t, "Test User", r.Header.Get("X-Forwarded-Name"))

			// Return a mock MCP response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"jsonrpc": "2.0", "result": "success", "id": 1}`)); err != nil {
				t.Logf("Failed to write response: %v", err)
			}
		}),
	}

	// Start the MCP server in a goroutine
	go func() {
		if err := mcpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("MCP server error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Ensure the server is stopped at the end
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mcpServer.Shutdown(ctx); err != nil {
			t.Logf("Failed to shutdown MCP server: %v", err)
		}
	}()

	// Step 1: Register a client
	registrationData := map[string]interface{}{
		"redirect_uris":              []string{"https://test.example.com/callback"},
		"client_name":                "Integration Test Client",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}

	jsonData, err := json.Marshal(registrationData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/json")

	w := CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var clientInfo ClientInfo
	err = json.Unmarshal(w.Body.Bytes(), &clientInfo)
	require.NoError(t, err)

	// Step 2: Start authorization flow
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", clientInfo.ClientID)
	authParams.Set("redirect_uri", "https://test.example.com/callback")
	authParams.Set("scope", "read write")
	authParams.Set("state", "integration_test_state")

	req, err = http.NewRequest("GET", "/authorize?"+authParams.Encode(), nil)
	require.NoError(t, err)

	w = CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)

	// Step 3: Simulate callback with authorization code
	// In a real scenario, this would come from the OAuth provider
	// For testing, we'll create a mock authorization code

	grantID, err := generateRandomString(16)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}

	grant := &database.Grant{
		ID:        grantID,
		ClientID:  clientInfo.ClientID,
		UserID:    "mock_user_123",
		Scope:     []string{"read", "write"},
		Metadata:  map[string]interface{}{"provider": "mock"},
		Props:     map[string]interface{}{"email": "test@example.com", "user_id": "mock_user_123", "name": "Test User"},
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	err = ts.db.StoreGrant(grant)
	require.NoError(t, err)

	authCode := fmt.Sprintf("%s:%s:%s", "mock_user_123", grantID, generateRandomStringSafe(8))
	err = ts.db.StoreAuthCode(authCode, grant.ID, grant.UserID)
	require.NoError(t, err)

	// Step 4: Exchange authorization code for tokens
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", authCode)
	tokenData.Set("client_id", clientInfo.ClientID)
	tokenData.Set("redirect_uri", "https://test.example.com/callback")

	req, err = http.NewRequest("POST", "/token", strings.NewReader(tokenData.Encode()))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientInfo.ClientID+":"+clientInfo.ClientSecret)))

	w = CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.NotEmpty(t, tokenResponse.RefreshToken)

	// Step 5: Use access token to access protected resource
	req, err = http.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc": "2.0", "method": "test", "params": {}}`))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	w = CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusUnauthorized, w.Code)

	// Step 6: Refresh the access token
	refreshData := url.Values{}
	refreshData.Set("grant_type", "refresh_token")
	refreshData.Set("client_id", clientInfo.ClientID)
	refreshData.Set("refresh_token", tokenResponse.RefreshToken)

	req, err = http.NewRequest("POST", "/token", strings.NewReader(refreshData.Encode()))
	require.NoError(t, err)
	req.Host = "test.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientInfo.ClientID+":"+clientInfo.ClientSecret)))

	w = CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var refreshResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &refreshResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, refreshResponse.AccessToken)
	assert.NotEqual(t, tokenResponse.AccessToken, refreshResponse.AccessToken)

	// Step 7: Revoke the token
	revokeData := url.Values{}
	revokeData.Set("token", refreshResponse.AccessToken)
	revokeData.Set("client_id", clientInfo.ClientID)

	req, err = http.NewRequest("POST", "/revoke", strings.NewReader(revokeData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientInfo.ClientID+":"+clientInfo.ClientSecret)))

	w = CreateTestResponseRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMockProvider tests the mock OAuth provider functionality
func TestMockProvider(t *testing.T) {
	provider := &MockProvider{name: "test_mock"}

	// Test GetAuthorizationURL
	authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "read write", "test_state")
	assert.Contains(t, authURL, "https://mock-provider.com/oauth/authorize")
	assert.Contains(t, authURL, "client_id=test_client")
	assert.Contains(t, authURL, "state=test_state")

	// Test GetAuthorizationURLWithPKCE
	codeChallenge := generateCodeChallenge("test_verifier")
	authURLPKCE := provider.GetAuthorizationURLWithPKCE("test_client", "https://test.example.com/callback", "read write", "test_state", codeChallenge, "S256")
	assert.Contains(t, authURLPKCE, "code_challenge="+codeChallenge)
	assert.Contains(t, authURLPKCE, "code_challenge_method=S256")

	// Test ExchangeCodeForToken
	ctx := context.Background()
	tokenInfo, err := provider.ExchangeCodeForToken(ctx, "test_code", "test_client", "test_secret", "https://test.example.com/callback")
	require.NoError(t, err)
	assert.Equal(t, "mock_access_token_test_code", tokenInfo.AccessToken)
	assert.Equal(t, "Bearer", tokenInfo.TokenType)
	assert.Equal(t, 3600, tokenInfo.ExpiresIn)

	// Test GetUserInfo
	userInfo, err := provider.GetUserInfo(ctx, "test_token")
	require.NoError(t, err)
	assert.Equal(t, "mock_user_123", userInfo.ID)
	assert.Equal(t, "test@example.com", userInfo.Email)
	assert.Equal(t, "Test User", userInfo.Name)

	// Test RefreshToken
	refreshInfo, err := provider.RefreshToken(ctx, "test_refresh", "test_client", "test_secret")
	require.NoError(t, err)
	assert.Equal(t, "mock_new_access_token", refreshInfo.AccessToken)
	assert.Equal(t, "mock_new_refresh_token", refreshInfo.RefreshToken)

	// Test GetName
	assert.Equal(t, "test_mock", provider.GetName())
}
