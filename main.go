package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"mcp-oauth-proxy/database"
	"mcp-oauth-proxy/providers"
	"mcp-oauth-proxy/tokens"
)

// Config represents the YAML configuration structure
type Config struct {
	Server struct {
		Port       int    `yaml:"port"`
		Host       string `yaml:"host"`
		PathPrefix string `yaml:"path_prefix"`
	} `yaml:"server"`

	Database struct {
		DSN string `yaml:"dsn"`
	} `yaml:"database"`

	OAuth struct {
		IssuerURL                                string   `yaml:"issuer_url"`
		BaseURL                                  string   `yaml:"base_url"`
		ServiceDocumentationURL                  string   `yaml:"service_documentation_url"`
		ScopesSupported                          []string `yaml:"scopes_supported"`
		ResourceName                             string   `yaml:"resource_name"`
		AccessTokenTTL                           int      `yaml:"access_token_ttl"` // in seconds, default 3600
		AllowImplicitFlow                        bool     `yaml:"allow_implicit_flow"`
		RegistrationEndpoint                     string   `yaml:"registration_endpoint"`
		RegistrationEndpointAuthMethodsSupported []string `yaml:"registration_endpoint_auth_methods_supported"`
		RevocationEndpoint                       string   `yaml:"revocation_endpoint"`
		RevocationEndpointAuthMethodsSupported   []string `yaml:"revocation_endpoint_auth_methods_supported"`
		TokenEndpoint                            string   `yaml:"token_endpoint"`
		TokenEndpointAuthMethodsSupported        []string `yaml:"token_endpoint_auth_methods_supported"`
		EncryptionKey                            string   `yaml:"encryption_key"` // Base64 encoded AES-256 key for encrypting sensitive data
	} `yaml:"oauth"`

	MCP struct {
		ServerURL string `yaml:"server_url"`
	} `yaml:"mcp"`

	RateLimit struct {
		Enabled bool `yaml:"enabled"`
		Window  int  `yaml:"window_minutes"`
		Max     int  `yaml:"max_requests"`
	} `yaml:"rate_limit"`

	Providers struct {
		Google struct {
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"google"`
		Microsoft struct {
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"microsoft"`
	} `yaml:"providers"`
}

// OAuthMetadata represents OAuth authorization server metadata
type OAuthMetadata struct {
	Issuer                                   string   `json:"issuer"`
	ServiceDocumentation                     string   `json:"service_documentation,omitempty"`
	AuthorizationEndpoint                    string   `json:"authorization_endpoint"`
	ResponseTypesSupported                   []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported            []string `json:"code_challenge_methods_supported"`
	TokenEndpoint                            string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported        []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported                      []string `json:"grant_types_supported"`
	ScopesSupported                          []string `json:"scopes_supported,omitempty"`
	RevocationEndpoint                       string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported   []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RegistrationEndpoint                     string   `json:"registration_endpoint,omitempty"`
	RegistrationEndpointAuthMethodsSupported []string `json:"registration_endpoint_auth_methods_supported,omitempty"`
}

// OAuthProtectedResourceMetadata represents protected resource metadata
type OAuthProtectedResourceMetadata struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers"`
	Scopes                []string `json:"scopes,omitempty"`
	ResourceName          string   `json:"resource_name,omitempty"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthError represents OAuth error response
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// AuthRequest represents parsed OAuth authorization request parameters
type AuthRequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// ClientInfo represents OAuth client registration information
type ClientInfo struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectUris            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	RegistrationDate        int64    `json:"registration_date,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// RateLimiter simple in-memory rate limiter
type RateLimiter struct {
	requests map[string][]time.Time
	window   time.Duration
	max      int
}

func NewRateLimiter(window time.Duration, max int) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		max:      max,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Clean old requests
	var validRequests []time.Time
	for _, reqTime := range rl.requests[key] {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}

	if len(validRequests) >= rl.max {
		return false
	}

	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests
	return true
}

// EncryptedProps represents encrypted properties with metadata
type EncryptedProps struct {
	Data      string `json:"data"`      // Base64 encoded encrypted data
	IV        string `json:"iv"`        // Base64 encoded initialization vector
	Algorithm string `json:"algorithm"` // Encryption algorithm used
}

// encryptData encrypts sensitive data using AES-256-GCM
func encryptData(data map[string]interface{}, encryptionKey []byte) (*EncryptedProps, error) {
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, iv, jsonData, nil)

	return &EncryptedProps{
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		IV:        base64.StdEncoding.EncodeToString(iv),
		Algorithm: "AES-256-GCM",
	}, nil
}

// decryptData decrypts encrypted data using AES-256-GCM
func decryptData(encryptedProps *EncryptedProps, encryptionKey []byte) (map[string]interface{}, error) {
	// Decode base64 data
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedProps.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(encryptedProps.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Unmarshal JSON data
	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted data: %w", err)
	}

	return data, nil
}

// decryptPropsIfNeeded decrypts props data if it's encrypted, otherwise returns the original data
func (p *OAuthProxy) decryptPropsIfNeeded(props map[string]interface{}) (map[string]interface{}, error) {
	// Check if data is encrypted
	encrypted, ok := props["encrypted"].(bool)
	if !ok || !encrypted {
		// Data is not encrypted, return as is
		return props, nil
	}

	// Check if encryption key is configured
	if p.encryptionKey == "" {
		return nil, fmt.Errorf("encrypted data found but no encryption key configured")
	}

	// Decode the encryption key
	encryptionKey, err := base64.StdEncoding.DecodeString(p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// Extract encrypted data
	encryptedData, ok := props["encrypted_data"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_data field not found")
	}

	iv, ok := props["iv"].(string)
	if !ok {
		return nil, fmt.Errorf("iv field not found")
	}

	algorithm, ok := props["algorithm"].(string)
	if !ok {
		return nil, fmt.Errorf("algorithm field not found")
	}

	// Create EncryptedProps struct
	encryptedProps := &EncryptedProps{
		Data:      encryptedData,
		IV:        iv,
		Algorithm: algorithm,
	}

	// Decrypt the data
	decryptedData, err := decryptData(encryptedProps, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Merge decrypted data with non-sensitive props
	result := make(map[string]interface{})
	for key, value := range props {
		if key != "encrypted_data" && key != "iv" && key != "algorithm" && key != "encrypted" {
			result[key] = value
		}
	}
	for key, value := range decryptedData {
		result[key] = value
	}

	return result, nil
}

// updateGrant updates a grant with new token information
func (p *OAuthProxy) updateGrant(grantID, userID string, oldTokenInfo *tokens.TokenInfo, newTokenInfo *providers.TokenInfo) error {
	// Get the existing grant
	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		return fmt.Errorf("failed to get grant: %w", err)
	}

	// Prepare sensitive props data
	sensitiveProps := map[string]interface{}{
		"access_token":  newTokenInfo.AccessToken,
		"refresh_token": newTokenInfo.RefreshToken,
		"expires_at":    newTokenInfo.ExpireAt,
	}

	// Add existing user info if available
	if grant.Props != nil {
		if email, ok := grant.Props["email"].(string); ok {
			sensitiveProps["email"] = email
		}
		if name, ok := grant.Props["name"].(string); ok {
			sensitiveProps["name"] = name
		}
		if userID, ok := grant.Props["user_id"].(string); ok {
			sensitiveProps["user_id"] = userID
		}
	}

	// use old refresh token in case new one is not provided
	if sensitiveProps["refresh_token"] == "" {
		sensitiveProps["refresh_token"] = oldTokenInfo.Props["refresh_token"]
	}

	// Initialize props map
	props := make(map[string]interface{})

	// Check if encryption is enabled
	if p.encryptionKey != "" {
		// Decode the encryption key from base64
		encryptionKey, err := base64.StdEncoding.DecodeString(p.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decode encryption key: %w", err)
		}

		// Validate key length (must be 32 bytes for AES-256)
		if len(encryptionKey) != 32 {
			return fmt.Errorf("invalid encryption key length: %d bytes (expected 32)", len(encryptionKey))
		}

		// Encrypt the sensitive props data
		encryptedProps, err := encryptData(sensitiveProps, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt props data: %w", err)
		}

		// Store encrypted data
		props["encrypted_data"] = encryptedProps.Data
		props["iv"] = encryptedProps.IV
		props["algorithm"] = encryptedProps.Algorithm
		props["encrypted"] = true
	} else {
		// Store data in plain text if no encryption key is provided
		for key, value := range sensitiveProps {
			props[key] = value
		}
		props["encrypted"] = false
	}

	// Update the grant with new props
	grant.Props = props

	// Update the grant in the database
	if err := p.db.UpdateGrant(grant); err != nil {
		return fmt.Errorf("failed to update grant: %w", err)
	}

	return nil
}

// databaseAdapter adapts the database to the tokens.Database interface
type databaseAdapter struct {
	db *database.Database
}

func (da *databaseAdapter) GetToken(accessToken string) (interface{}, error) {
	return da.db.GetToken(accessToken)
}

func (da *databaseAdapter) GetGrant(grantID, userID string) (interface{}, error) {
	return da.db.GetGrant(grantID, userID)
}

// OAuthProxy represents the OAuth proxy server
type OAuthProxy struct {
	metadata      *OAuthMetadata
	db            *database.Database
	rateLimiter   *RateLimiter
	providers     *providers.Manager
	tokenManager  *tokens.TokenManager
	provider      string
	encryptionKey string
	resourceName  string
	pathPrefix    string
	lock          sync.Mutex
}

func NewOAuthProxy() (*OAuthProxy, error) {
	databaseDSN := os.Getenv("DATABASE_DSN")

	// Log database configuration
	if databaseDSN == "" {
		log.Println("DATABASE_DSN not set, using SQLite database at data/oauth_proxy.db")
	} else if strings.HasPrefix(databaseDSN, "postgres://") || strings.HasPrefix(databaseDSN, "postgresql://") {
		log.Println("Using PostgreSQL database")
	} else {
		log.Printf("Using SQLite database at: %s", databaseDSN)
	}

	// Initialize database
	db, err := database.NewDatabase(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(
		time.Duration(15)*time.Minute,
		100,
	)

	// Initialize provider manager
	providerManager := providers.NewManager()
	provider := ""

	// Register generic provider
	if os.Getenv("OAUTH_CLIENT_ID") != "" && os.Getenv("OAUTH_CLIENT_SECRET") != "" && os.Getenv("OAUTH_AUTHORIZE_URL") != "" {
		genericProvider := providers.NewGenericProvider()
		providerManager.RegisterProvider("generic", genericProvider)
		provider = "generic"
	}

	// Initialize token manager
	tokenManager, err := tokens.NewTokenManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token manager: %w", err)
	}

	// Set database dependency for token validation
	tokenManager.SetDatabase(&databaseAdapter{db: db})

	// Split and trim scopes to handle whitespace
	scopesSupported := ParseScopesSupported(os.Getenv("SCOPES_SUPPORTED"))

	metadata := &OAuthMetadata{
		ResponseTypesSupported:                   []string{"code"},
		CodeChallengeMethodsSupported:            []string{"S256"},
		TokenEndpointAuthMethodsSupported:        []string{"client_secret_post"},
		GrantTypesSupported:                      []string{"authorization_code", "refresh_token"},
		ScopesSupported:                          scopesSupported,
		RevocationEndpointAuthMethodsSupported:   []string{"client_secret_post"},
		RegistrationEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}

	// Get path prefix from environment variable
	pathPrefix := os.Getenv("PATH_PREFIX")
	if pathPrefix != "" && !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}
	if pathPrefix != "" && strings.HasSuffix(pathPrefix, "/") {
		pathPrefix = strings.TrimSuffix(pathPrefix, "/")
	}

	return &OAuthProxy{
		metadata:      metadata,
		db:            db,
		rateLimiter:   rateLimiter,
		providers:     providerManager,
		tokenManager:  tokenManager,
		provider:      provider,
		resourceName:  "MCP Tools",
		encryptionKey: os.Getenv("ENCRYPTION_KEY"),
		pathPrefix:    pathPrefix,
	}, nil
}

// getBaseURL returns the base URL from the request
func (p *OAuthProxy) getBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}

// getEndpointURL returns the full URL for an endpoint, including the path prefix
func (p *OAuthProxy) getEndpointURL(c *gin.Context, path string) string {
	baseURL := p.getBaseURL(c)
	if p.pathPrefix == "" {
		return fmt.Sprintf("%s%s", baseURL, path)
	}
	return fmt.Sprintf("%s%s%s", baseURL, p.pathPrefix, path)
}

func (p *OAuthProxy) setupRoutes(r *gin.Engine) {
	// Helper function to add prefix to paths
	addPrefix := func(path string) string {
		if p.pathPrefix == "" {
			return path
		}
		return p.pathPrefix + path
	}

	// Global CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "mcp-protocol-version", "*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health endpoint (no prefix)
	r.GET("/health", p.healthHandler)

	// Rate limiting middleware
	if p.rateLimiter != nil {
		r.Use(p.rateLimitMiddleware())
	}

	// OAuth endpoints (with prefix)
	r.GET(addPrefix("/authorize"), p.authorizeHandler)
	r.POST(addPrefix("/authorize"), p.authorizeHandler)
	r.GET(addPrefix("/callback"), p.callbackHandler)
	r.POST(addPrefix("/token"), p.tokenHandler)
	r.POST(addPrefix("/revoke"), p.revokeHandler)
	r.POST(addPrefix("/register"), p.registerHandler)

	// Metadata endpoints (with prefix)
	r.GET(addPrefix("/.well-known/oauth-authorization-server"), p.oauthMetadataHandler)
	r.GET(addPrefix("/.well-known/oauth-protected-resource/mcp"), p.protectedResourceMetadataHandler)

	// Add protected resource endpoints (with prefix)
	r.Any(addPrefix("/mcp"), p.validateTokenMiddleware(), p.mcpProxyHandler)
	r.Any(addPrefix("/mcp/*path"), p.validateTokenMiddleware(), p.mcpProxyHandler)
}

func (p *OAuthProxy) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if !p.rateLimiter.Allow(clientIP) {
			c.JSON(http.StatusTooManyRequests, OAuthError{
				Error:            "too_many_requests",
				ErrorDescription: "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (p *OAuthProxy) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (p *OAuthProxy) authorizeHandler(c *gin.Context) {
	// Get parameters from query or form
	var params url.Values
	if c.Request.Method == "GET" {
		params = c.Request.URL.Query()
	} else {
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "Failed to parse form data",
			})
			return
		}
		params = c.Request.Form
	}

	// Parse authorization request
	authReq := AuthRequest{
		ResponseType:        params.Get("response_type"),
		ClientID:            params.Get("client_id"),
		RedirectURI:         params.Get("redirect_uri"),
		Scope:               params.Get("scope"),
		State:               params.Get("state"),
		CodeChallenge:       params.Get("code_challenge"),
		CodeChallengeMethod: params.Get("code_challenge_method"),
	}

	if authReq.Scope == "" {
		authReq.Scope = strings.Join(p.metadata.ScopesSupported, " ")
	}

	// Validate required parameters
	if authReq.ResponseType == "" || authReq.ClientID == "" || authReq.RedirectURI == "" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing required parameters",
		})
		return
	}

	// Validate response type
	if authReq.ResponseType != "code" && authReq.ResponseType != "token" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "unsupported_response_type",
			ErrorDescription: "Only 'code' and 'token' response types are supported",
		})
		return
	}

	// Validate client exists
	clientInfo, err := p.db.GetClient(authReq.ClientID)
	if err != nil || clientInfo == nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
		return
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range clientInfo.RedirectUris {
		if uri == authReq.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect URI",
		})
		return
	}

	providerName := p.provider

	// Get the provider
	provider, err := p.providers.GetProvider(providerName)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: fmt.Sprintf("Provider '%s' not available", providerName),
		})
		return
	}

	// Get the provider's client ID and secret
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")

	// Check if provider is configured
	if clientID == "" || clientSecret == "" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "OAuth provider not configured",
		})
		return
	}

	stateData, err := json.Marshal(authReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to marshal state data",
		})
	}

	encodedState := base64.URLEncoding.EncodeToString(stateData)
	redirectURI := fmt.Sprintf("%s/callback", p.getBaseURL(c))

	// Generate authorization URL with the provider
	authURL := provider.GetAuthorizationURL(
		clientID,
		redirectURI,
		authReq.Scope,
		encodedState,
	)

	// Redirect to the provider's authorization URL
	c.Redirect(http.StatusFound, authURL)
}

func (p *OAuthProxy) callbackHandler(c *gin.Context) {
	// Handle OAuth callback from external providers
	code := c.Query("code")
	state := c.Query("state")
	error := c.Query("error")
	errorDescription := c.Query("error_description")

	// Check for OAuth errors
	if error != "" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            error,
			ErrorDescription: errorDescription,
		})
		return
	}

	// Validate required parameters
	if code == "" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing authorization code",
		})
		return
	}

	var authReq AuthRequest
	stateData, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid state parameter",
		})
		return
	}
	if err := json.Unmarshal(stateData, &authReq); err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid state parameter",
		})
		return
	}

	// Get the provider
	provider, err := p.providers.GetProvider(p.provider)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Provider not available",
		})
		return
	}

	// Get provider credentials
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	redirectURI := fmt.Sprintf("%s/callback", p.getBaseURL(c))

	// Exchange code for tokens
	tokenInfo, err := provider.ExchangeCodeForToken(c.Request.Context(), code, clientID, clientSecret, redirectURI)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to exchange authorization code",
		})
		return
	}

	// Get user info from the provider
	userInfo, err := provider.GetUserInfo(c.Request.Context(), tokenInfo.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to get user information",
		})
		return
	}

	// Create a grant for this user
	grantID, err := generateRandomString(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to generate grant ID",
		})
		return
	}
	now := time.Now().Unix()

	// Prepare sensitive props data
	sensitiveProps := map[string]interface{}{
		"email":         userInfo.Email,
		"name":          userInfo.Name,
		"access_token":  tokenInfo.AccessToken,
		"refresh_token": tokenInfo.RefreshToken,
		"expires_at":    tokenInfo.ExpireAt,
	}

	// Initialize props map
	props := make(map[string]interface{})

	// Check if encryption is enabled
	if p.encryptionKey != "" {
		// Decode the encryption key from base64
		encryptionKey, err := base64.StdEncoding.DecodeString(p.encryptionKey)
		if err != nil {
			log.Printf("Failed to decode encryption key: %v", err)
			c.JSON(http.StatusInternalServerError, OAuthError{
				Error:            "server_error",
				ErrorDescription: "Invalid encryption key configuration",
			})
			return
		}

		// Validate key length (must be 32 bytes for AES-256)
		if len(encryptionKey) != 32 {
			log.Printf("Invalid encryption key length: %d bytes (expected 32)", len(encryptionKey))
			c.JSON(http.StatusInternalServerError, OAuthError{
				Error:            "server_error",
				ErrorDescription: "Invalid encryption key length",
			})
			return
		}

		// Encrypt the sensitive props data
		encryptedProps, err := encryptData(sensitiveProps, encryptionKey)
		if err != nil {
			log.Printf("Failed to encrypt props data: %v", err)
			c.JSON(http.StatusInternalServerError, OAuthError{
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
	} else {
		// Store data in plain text if no encryption key is provided
		for key, value := range sensitiveProps {
			props[key] = value
		}
		props["encrypted"] = false
	}

	// Add non-sensitive data
	props["user_id"] = userInfo.ID

	grant := &database.Grant{
		ID:       grantID,
		ClientID: authReq.ClientID,
		UserID:   userInfo.ID,
		Scope:    strings.Fields(authReq.Scope),
		Metadata: map[string]interface{}{
			"provider": p.provider,
			"label":    userInfo.Name,
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
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store grant",
		})
		return
	}

	// Generate authorization code
	randomPart, err := generateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to generate authorization code",
		})
		return
	}
	authCode := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, randomPart)

	// Store the authorization code
	if err := p.db.StoreAuthCode(authCode, grantID, userInfo.ID); err != nil {
		log.Printf("Failed to store authorization code: %v", err)
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store authorization code",
		})
		return
	}

	// Build the redirect URL back to the client
	redirectURL := authReq.RedirectURI

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, OAuthError{
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
	c.Redirect(http.StatusFound, parsedURL.String())
}

func (p *OAuthProxy) oauthMetadataHandler(c *gin.Context) {
	baseURL := p.getBaseURL(c)

	// Create dynamic metadata based on the request
	metadata := &OAuthMetadata{
		Issuer:                                   baseURL,
		ServiceDocumentation:                     p.metadata.ServiceDocumentation,
		AuthorizationEndpoint:                    p.getEndpointURL(c, "/authorize"),
		ResponseTypesSupported:                   p.metadata.ResponseTypesSupported,
		CodeChallengeMethodsSupported:            p.metadata.CodeChallengeMethodsSupported,
		TokenEndpoint:                            p.getEndpointURL(c, "/token"),
		TokenEndpointAuthMethodsSupported:        p.metadata.TokenEndpointAuthMethodsSupported,
		GrantTypesSupported:                      p.metadata.GrantTypesSupported,
		ScopesSupported:                          p.metadata.ScopesSupported,
		RevocationEndpoint:                       p.getEndpointURL(c, "/revoke"),
		RevocationEndpointAuthMethodsSupported:   p.metadata.RevocationEndpointAuthMethodsSupported,
		RegistrationEndpoint:                     p.getEndpointURL(c, "/register"),
		RegistrationEndpointAuthMethodsSupported: p.metadata.RegistrationEndpointAuthMethodsSupported,
	}

	c.JSON(http.StatusOK, metadata)
}

func (p *OAuthProxy) protectedResourceMetadataHandler(c *gin.Context) {
	metadata := OAuthProtectedResourceMetadata{
		Resource:              p.getEndpointURL(c, "/mcp"),
		AuthorizationServers:  []string{p.getBaseURL(c)},
		Scopes:                p.metadata.ScopesSupported,
		ResourceName:          p.resourceName,
		ResourceDocumentation: p.metadata.ServiceDocumentation,
	}

	c.JSON(http.StatusOK, metadata)
}

func (p *OAuthProxy) validateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Return 401 with proper WWW-Authenticate header
			resourceMetadataUrl := p.getEndpointURL(c, "/.well-known/oauth-protected-resource/mcp")
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="%s"`, resourceMetadataUrl)
			c.Header("WWW-Authenticate", wwwAuthValue)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Missing Authorization header",
			})
			c.Abort()
			return
		}

		// Parse Authorization header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
			resourceMetadataUrl := p.getEndpointURL(c, "/.well-known/oauth-protected-resource/mcp")
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid Authorization header format, expected 'Bearer TOKEN'", resource_metadata="%s"`, resourceMetadataUrl)
			c.Header("WWW-Authenticate", wwwAuthValue)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Invalid Authorization header format, expected 'Bearer TOKEN'",
			})
			c.Abort()
			return
		}

		token := parts[1]

		tokenInfo, err := p.tokenManager.GetTokenInfo(token)
		if err != nil {
			resourceMetadataUrl := p.getEndpointURL(c, "/.well-known/oauth-protected-resource/mcp")
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid or expired token", resource_metadata="%s"`, resourceMetadataUrl)
			c.Header("WWW-Authenticate", wwwAuthValue)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Decrypt props if needed before storing in context
		if tokenInfo.Props != nil {
			decryptedProps, err := p.decryptPropsIfNeeded(tokenInfo.Props)
			if err != nil {
				resourceMetadataUrl := p.getEndpointURL(c, "/.well-known/oauth-protected-resource/mcp")
				wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Failed to decrypt token data", resource_metadata="%s"`, resourceMetadataUrl)
				c.Header("WWW-Authenticate", wwwAuthValue)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":             "invalid_token",
					"error_description": "Failed to decrypt token data",
				})
				c.Abort()
				return
			}
			tokenInfo.Props = decryptedProps
		}

		// Store token info in context for MCP server
		c.Set("token_info", tokenInfo)
		c.Next()
	}
}

func (p *OAuthProxy) mcpProxyHandler(c *gin.Context) {
	tokenInfo := c.MustGet("token_info").(*tokens.TokenInfo)
	path := c.Param("path")

	// Check if the access token is expired and refresh if needed
	if tokenInfo.Props != nil {
		if _, ok := tokenInfo.Props["access_token"].(string); ok {
			// Check if token is expired (with a 5-minute buffer)
			expiresAt, ok := tokenInfo.Props["expires_at"].(float64)
			if ok && expiresAt > 0 {
				if time.Now().Add(5 * time.Minute).After(time.Unix(int64(expiresAt), 0)) {
					// when refreshing token, we need to lock the database to avoid race conditions
					// otherwise we could get save the old access token into the database when another refresh process is running
					p.lock.Lock()
					log.Printf("Access token is expired or will expire soon, attempting to refresh")

					// Get the refresh token
					refreshToken, ok := tokenInfo.Props["refresh_token"].(string)
					if !ok || refreshToken == "" {
						log.Printf("No refresh token available, cannot refresh access token")
						c.JSON(http.StatusUnauthorized, gin.H{
							"error":             "invalid_token",
							"error_description": "Access token expired and no refresh token available",
						})
						p.lock.Unlock()
						return
					}

					// Get the provider
					provider, err := p.providers.GetProvider(p.provider)
					if err != nil {
						log.Printf("Failed to get provider for token refresh: %v", err)
						c.JSON(http.StatusInternalServerError, gin.H{
							"error":             "server_error",
							"error_description": "Failed to refresh token",
						})
						p.lock.Unlock()
						return
					}

					// Get provider credentials
					clientID := os.Getenv("OAUTH_CLIENT_ID")
					clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
					if clientID == "" || clientSecret == "" {
						log.Printf("OAuth credentials not configured for token refresh")
						c.JSON(http.StatusInternalServerError, gin.H{
							"error":             "server_error",
							"error_description": "OAuth credentials not configured",
						})
						p.lock.Unlock()
						return
					}

					// Refresh the token
					newTokenInfo, err := provider.RefreshToken(c.Request.Context(), refreshToken, clientID, clientSecret)
					if err != nil {
						log.Printf("Failed to refresh token: %v", err)
						c.JSON(http.StatusUnauthorized, gin.H{
							"error":             "invalid_token",
							"error_description": "Failed to refresh access token",
						})
						p.lock.Unlock()
						return
					}

					// Update the grant with new token information
					if err := p.updateGrant(tokenInfo.GrantID, tokenInfo.UserID, tokenInfo, newTokenInfo); err != nil {
						log.Printf("Failed to update grant: %v", err)
						c.JSON(http.StatusInternalServerError, gin.H{
							"error":             "server_error",
							"error_description": "Failed to update grant with new token",
						})
						p.lock.Unlock()
						return
					}

					// Update the token info with the new access token for the current request
					tokenInfo.Props["access_token"] = newTokenInfo.AccessToken
					p.lock.Unlock()

					log.Printf("Successfully refreshed access token")
				}
			}
		}
	}

	// Create target URL
	var targetURL string
	if path == "" {
		// If no path is provided, use the MCP server URL directly
		targetURL = os.Getenv("MCP_SERVER_URL")
	} else {
		// If path is provided, append it to the MCP server URL
		targetURL = os.Getenv("MCP_SERVER_URL") + "/" + path
	}

	// Log the proxy request for debugging
	log.Printf("Proxying request: %s %s -> %s", c.Request.Method, c.Request.URL.Path, targetURL)

	// Create reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL, _ = url.Parse(targetURL)
			req.Host = req.URL.Host

			// Add forwarded headers from token props
			if tokenInfo.Props != nil {
				if userID, ok := tokenInfo.Props["user_id"].(string); ok {
					req.Header.Set("X-Forwarded-User", userID)
				}
				if email, ok := tokenInfo.Props["email"].(string); ok {
					req.Header.Set("X-Forwarded-Email", email)
				}
				if name, ok := tokenInfo.Props["name"].(string); ok {
					req.Header.Set("X-Forwarded-Name", name)
				}
				if accessToken, ok := tokenInfo.Props["access_token"].(string); ok {
					req.Header.Set("X-Forwarded-Access-Token", accessToken)
				}
			}

			// Forward original headers
			for key, values := range c.Request.Header {
				lowerCaseKey := strings.ToLower(key)
				if lowerCaseKey == "authorization" {
					req.Header.Del(key)
				} else {
					for _, value := range values {
						req.Header.Add(key, value)
					}
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			c.AbortWithStatus(http.StatusBadGateway)
		},
	}

	// Serve the request
	proxy.ServeHTTP(c.Writer, c.Request)
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// generateRandomStringSafe is a helper that panics on error for cases where we can't handle errors gracefully
func generateRandomStringSafe(length int) string {
	str, err := generateRandomString(length)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random string: %v", err))
	}
	return str
}

// ParseScopesSupported parses a comma-separated scopes string and trims whitespace from each scope.
func ParseScopesSupported(envScopes string) []string {
	scopesRaw := strings.Split(envScopes, ",")
	scopesSupported := make([]string, 0, len(scopesRaw))
	for _, scope := range scopesRaw {
		if trimmed := strings.TrimSpace(scope); trimmed != "" {
			scopesSupported = append(scopesSupported, trimmed)
		}
	}
	return scopesSupported
}

func main() {
	proxy, err := NewOAuthProxy()
	if err != nil {
		log.Fatalf("Failed to create OAuth proxy: %v", err)
	}
	defer func() {
		if err := proxy.db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Setup cleanup goroutine for expired tokens
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
		defer ticker.Stop()
		for range ticker.C {
			if err := proxy.db.CleanupExpiredTokens(); err != nil {
				log.Printf("Failed to cleanup expired tokens: %v", err)
			}
		}
	}()

	// Setup Gin router
	r := gin.Default()
	proxy.setupRoutes(r)

	// Start server
	log.Printf("Starting OAuth proxy server on localhost:8080")
	log.Fatal(r.Run(":8080"))
}

func (p *OAuthProxy) tokenHandler(c *gin.Context) {
	// Parse form data
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	grantType := c.PostForm("grant_type")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Check for client ID
	if clientID == "" {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client ID is required",
		})
		return
	}

	// Get client info to determine authentication method
	clientInfo, err := p.db.GetClient(clientID)
	if err != nil || clientInfo == nil {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
		return
	}

	// Check if this is a public client (auth method "none")
	isPublicClient := clientInfo.TokenEndpointAuthMethod == "none"

	// For public clients, client_secret is not required
	// For confidential clients, client_secret is required
	if !isPublicClient {
		if clientSecret == "" {
			c.JSON(http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client secret is required for confidential clients",
			})
			return
		}

		// Validate client secret for confidential clients
		if clientInfo.ClientSecret != clientSecret {
			c.JSON(http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client secret",
			})
			return
		}
	}

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(c, clientID)
	case "refresh_token":
		p.handleRefreshTokenGrant(c, clientID)
	default:
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "unsupported_grant_type",
			ErrorDescription: "The grant type is not supported by this authorization server",
		})
	}
}

func (p *OAuthProxy) handleAuthorizationCodeGrant(c *gin.Context, clientID string) {
	code := c.PostForm("code")
	codeVerifier := c.PostForm("code_verifier")
	redirectURI := c.PostForm("redirect_uri")

	// Validate authorization code
	grantID, userID, err := p.db.ValidateAuthCode(code)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid authorization code",
		})
		return
	}

	// Get the grant
	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Grant not found",
		})
		return
	}

	// Verify client ID matches
	if grant.ClientID != clientID {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Client ID mismatch",
		})
		return
	}

	// Validate redirect_uri if provided
	if redirectURI != "" {
		// Get client info to validate redirect URI
		clientInfo, err := p.db.GetClient(clientID)
		if err != nil || clientInfo == nil {
			c.JSON(http.StatusBadRequest, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client not found",
			})
			return
		}

		// Check if redirect URI is registered for this client
		validRedirect := false
		for _, uri := range clientInfo.RedirectUris {
			if uri == redirectURI {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			c.JSON(http.StatusBadRequest, OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Invalid redirect URI",
			})
			return
		}
	}

	// Check if PKCE is being used
	isPkceEnabled := grant.CodeChallenge != ""

	// OAuth 2.1 requires redirect_uri parameter unless PKCE is used
	if redirectURI == "" && !isPkceEnabled {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "redirect_uri is required when not using PKCE",
		})
		return
	}

	// Check PKCE if code_verifier is provided
	if codeVerifier != "" {
		if !isPkceEnabled {
			c.JSON(http.StatusBadRequest, OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "code_verifier provided for a flow that did not use PKCE",
			})
			return
		}

		// Verify PKCE code_verifier
		calculatedChallenge := ""
		if grant.CodeChallengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			calculatedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
		} else {
			calculatedChallenge = codeVerifier
		}

		if calculatedChallenge != grant.CodeChallenge {
			c.JSON(http.StatusBadRequest, OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Invalid PKCE code_verifier",
			})
			return
		}
	}

	// Props are stored in the grant and will be accessed when needed
	// For simple string token generation, we don't need to decrypt them here

	// Generate access token in format: userId:grantId:accessTokenSecret
	accessTokenSecret := generateRandomStringSafe(32)
	accessToken := fmt.Sprintf("%s:%s:%s", userID, grantID, accessTokenSecret)

	// Generate refresh token in format: userId:grantId:refreshTokenSecret
	refreshTokenSecret := generateRandomStringSafe(32)
	refreshToken := fmt.Sprintf("%s:%s:%s", userID, grantID, refreshTokenSecret)

	// Store tokens in database
	tokenData := &database.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       userID,
		GrantID:      grantID,
		Scope:        strings.Join(grant.Scope, " "),
		ExpiresAt:    time.Now().Add(time.Duration(3600) * time.Second),
		CreatedAt:    time.Now(),
	}

	if err := p.db.StoreToken(tokenData); err != nil {
		log.Printf("Failed to store token: %v", err)
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store token",
		})
		return
	}

	// Delete the authorization code (single-use)
	if err := p.db.DeleteAuthCode(code); err != nil {
		log.Printf("Error deleting authorization code: %v", err)
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        strings.Join(grant.Scope, " "),
	}

	c.JSON(http.StatusOK, response)
}

func (p *OAuthProxy) handleRefreshTokenGrant(c *gin.Context, clientID string) {
	refreshToken := c.PostForm("refresh_token")

	// Validate refresh token from database
	tokenData, err := p.db.GetTokenByRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid refresh token",
		})
		return
	}

	// Check if token is revoked
	if tokenData.Revoked {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token has been revoked",
		})
		return
	}

	// Check if refresh token is expired
	if time.Now().After(tokenData.RefreshTokenExpiresAt) {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Refresh token has expired",
		})
		return
	}

	// Check if token belongs to the requesting client
	if tokenData.ClientID != clientID {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token does not belong to the requesting client",
		})
		return
	}

	// Get the grant to access props
	_, err = p.db.GetGrant(tokenData.GrantID, tokenData.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Grant not found",
		})
		return
	}

	// Props are stored in the grant and will be accessed when needed
	// For simple string token generation, we don't need to decrypt them here

	// Generate new access token in format: userId:grantId:accessTokenSecret
	accessTokenSecret := generateRandomStringSafe(32)
	accessToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, accessTokenSecret)

	// Generate new refresh token in format: userId:grantId:refreshTokenSecret (OAuth 2.1 refresh token rotation)
	refreshTokenSecret := generateRandomStringSafe(32)
	newRefreshToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, refreshTokenSecret)

	// Store new token in database (replaces the old one)
	newTokenData := &database.TokenData{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ClientID:     clientID,
		UserID:       tokenData.UserID,
		GrantID:      tokenData.GrantID,
		Scope:        tokenData.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(3600) * time.Second),
		CreatedAt:    time.Now(),
	}

	if err := p.db.StoreToken(newTokenData); err != nil {
		log.Printf("Failed to store new token: %v", err)
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store new token",
		})
		return
	}

	// Revoke the old token
	if err := p.db.RevokeToken(tokenData.AccessToken); err != nil {
		log.Printf("Failed to revoke old token: %v", err)
		// Don't fail the request, but log the error
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken,
		Scope:        tokenData.Scope,
	}

	c.JSON(http.StatusOK, response)
}

func (p *OAuthProxy) revokeHandler(c *gin.Context) {
	// Parse form data
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint") // RFC 7009: token_type_hint parameter
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Validate client ID
	if clientID == "" {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client ID is required",
		})
		return
	}

	// Get client info to determine authentication method
	clientInfo, err := p.db.GetClient(clientID)
	if err != nil || clientInfo == nil {
		c.JSON(http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
		return
	}

	// Check if this is a public client (auth method "none")
	isPublicClient := clientInfo.TokenEndpointAuthMethod == "none"

	// For public clients, client_secret is not required
	// For confidential clients, client_secret is required
	if !isPublicClient {
		if clientSecret == "" {
			c.JSON(http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client secret is required for confidential clients",
			})
			return
		}

		// Validate client secret for confidential clients
		if clientInfo.ClientSecret != clientSecret {
			c.JSON(http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client secret",
			})
			return
		}
	}

	// Validate token parameter
	if token == "" {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Token parameter is required",
		})
		return
	}

	// Optional: Validate that the token belongs to the requesting client
	// This is a security best practice but not required by RFC 7009
	var tokenData *database.TokenData
	var tokenErr error

	// Use token_type_hint to optimize lookup if provided
	switch tokenTypeHint {
	case "refresh_token":
		tokenData, tokenErr = p.db.GetTokenByRefreshToken(token)
	case "access_token":
		tokenData, tokenErr = p.db.GetToken(token)
	default:
		// No hint or invalid hint, try both
		tokenData, tokenErr = p.db.GetToken(token)
		if tokenErr != nil {
			tokenData, tokenErr = p.db.GetTokenByRefreshToken(token)
		}
	}

	if tokenErr == nil && tokenData != nil {
		// Token found, check client ownership
		if tokenData.ClientID != clientID {
			log.Printf("Revocation attempt by wrong client: token belongs to %s, requested by %s", tokenData.ClientID, clientID)
			// Still return 200 OK as per RFC 7009
		}
	}

	// Revoke the token in database
	if err := p.db.RevokeToken(token); err != nil {
		log.Printf("Failed to revoke token: %v", err)
		// Don't return error to client for security reasons
		// RFC 7009: "The authorization server responds with HTTP status code 200 if the token
		// has been revoked successfully or if the client submitted an invalid token."
	}

	// Always return 200 OK as per RFC 7009
	c.Status(http.StatusOK)
}

func (p *OAuthProxy) registerHandler(c *gin.Context) {
	// Client registration is always enabled when this endpoint is accessible

	// Only allow POST method
	if c.Request.Method != "POST" {
		c.JSON(http.StatusMethodNotAllowed, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		return
	}

	// Check content length (max 1MB)
	if c.Request.ContentLength > 1024*1024 {
		c.JSON(http.StatusRequestEntityTooLarge, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Request payload too large, must be under 1 MiB",
		})
		return
	}

	// Parse JSON body
	var clientMetadata map[string]interface{}
	if err := c.ShouldBindJSON(&clientMetadata); err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON payload",
		})
		return
	}

	// Validate and extract client metadata
	clientInfo, err := p.validateClientMetadata(clientMetadata)
	if err != nil {
		c.JSON(http.StatusBadRequest, OAuthError{
			Error:            "invalid_client_metadata",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Generate client ID and secret
	clientID := generateRandomStringSafe(16)
	var clientSecret string

	// Generate client secret for confidential clients
	if clientInfo.TokenEndpointAuthMethod != "none" {
		clientSecret = generateRandomStringSafe(32)
	}

	// Set registration date
	clientInfo.ClientID = clientID
	clientInfo.RegistrationDate = time.Now().Unix()

	// Convert to database.ClientInfo
	dbClientInfo := &database.ClientInfo{
		ClientID:                clientInfo.ClientID,
		ClientSecret:            clientSecret,
		RedirectUris:            clientInfo.RedirectUris,
		ClientName:              clientInfo.ClientName,
		LogoURI:                 clientInfo.LogoURI,
		ClientURI:               clientInfo.ClientURI,
		PolicyURI:               clientInfo.PolicyURI,
		TosURI:                  clientInfo.TosURI,
		JwksURI:                 clientInfo.JwksURI,
		Contacts:                clientInfo.Contacts,
		GrantTypes:              clientInfo.GrantTypes,
		ResponseTypes:           clientInfo.ResponseTypes,
		RegistrationDate:        clientInfo.RegistrationDate,
		TokenEndpointAuthMethod: clientInfo.TokenEndpointAuthMethod,
	}

	// Store client in database
	if err := p.db.StoreClient(dbClientInfo); err != nil {
		log.Printf("Failed to store client: %v", err)
		c.JSON(http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to register client",
		})
		return
	}

	// Build response
	baseURL := p.getBaseURL(c)
	response := map[string]interface{}{
		"client_id":                  clientInfo.ClientID,
		"redirect_uris":              clientInfo.RedirectUris,
		"client_name":                clientInfo.ClientName,
		"logo_uri":                   clientInfo.LogoURI,
		"client_uri":                 clientInfo.ClientURI,
		"policy_uri":                 clientInfo.PolicyURI,
		"tos_uri":                    clientInfo.TosURI,
		"jwks_uri":                   clientInfo.JwksURI,
		"contacts":                   clientInfo.Contacts,
		"grant_types":                clientInfo.GrantTypes,
		"response_types":             clientInfo.ResponseTypes,
		"token_endpoint_auth_method": clientInfo.TokenEndpointAuthMethod,
		"registration_client_uri":    fmt.Sprintf("%s/register/%s", baseURL, clientID),
		"client_id_issued_at":        clientInfo.RegistrationDate,
	}

	// Include client secret for confidential clients
	if clientInfo.TokenEndpointAuthMethod != "none" && clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	c.JSON(http.StatusCreated, response)
}

func (p *OAuthProxy) validateClientMetadata(metadata map[string]interface{}) (*ClientInfo, error) {
	// Helper function to validate string fields
	validateStringField := func(field interface{}, name string) (string, error) {
		if field == nil {
			return "", nil
		}
		if str, ok := field.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("field %s must be a string", name)
	}

	// Helper function to validate string arrays
	validateStringArray := func(arr interface{}, name string) ([]string, error) {
		if arr == nil {
			return nil, nil
		}
		if array, ok := arr.([]interface{}); ok {
			result := make([]string, len(array))
			for i, item := range array {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					return nil, fmt.Errorf("all elements in %s must be strings", name)
				}
			}
			return result, nil
		}
		return nil, fmt.Errorf("field %s must be an array", name)
	}

	// Validate token_endpoint_auth_method
	authMethod, err := validateStringField(metadata["token_endpoint_auth_method"], "token_endpoint_auth_method")
	if err != nil {
		return nil, err
	}
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}

	// Validate redirect_uris (required)
	redirectUris, err := validateStringArray(metadata["redirect_uris"], "redirect_uris")
	if err != nil {
		return nil, err
	}
	if len(redirectUris) == 0 {
		return nil, fmt.Errorf("at least one redirect URI is required")
	}

	// Validate other fields
	clientName, err := validateStringField(metadata["client_name"], "client_name")
	if err != nil {
		return nil, err
	}

	logoURI, err := validateStringField(metadata["logo_uri"], "logo_uri")
	if err != nil {
		return nil, err
	}

	clientURI, err := validateStringField(metadata["client_uri"], "client_uri")
	if err != nil {
		return nil, err
	}

	policyURI, err := validateStringField(metadata["policy_uri"], "policy_uri")
	if err != nil {
		return nil, err
	}

	tosURI, err := validateStringField(metadata["tos_uri"], "tos_uri")
	if err != nil {
		return nil, err
	}

	jwksURI, err := validateStringField(metadata["jwks_uri"], "jwks_uri")
	if err != nil {
		return nil, err
	}

	contacts, err := validateStringArray(metadata["contacts"], "contacts")
	if err != nil {
		return nil, err
	}
	// inspector will check the schema and see if it is null, so this is a workaround
	if len(contacts) == 0 {
		contacts = []string{}
	}

	grantTypes, err := validateStringArray(metadata["grant_types"], "grant_types")
	if err != nil {
		return nil, err
	}
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	responseTypes, err := validateStringArray(metadata["response_types"], "response_types")
	if err != nil {
		return nil, err
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	return &ClientInfo{
		RedirectUris:            redirectUris,
		ClientName:              clientName,
		LogoURI:                 logoURI,
		ClientURI:               clientURI,
		PolicyURI:               policyURI,
		TosURI:                  tosURI,
		JwksURI:                 jwksURI,
		Contacts:                contacts,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
	}, nil
}
