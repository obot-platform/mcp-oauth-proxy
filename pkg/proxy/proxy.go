package proxy

import (
	"context"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/db"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/ratelimit"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type OAuthProxy struct {
	metadata      *OAuthMetadata
	db            *db.Store
	rateLimiter   *ratelimit.RateLimiter
	providers     *providers.Manager
	tokenManager  *tokens.TokenManager
	provider      string
	encryptionKey string
	resourceName  string
	lock          sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

// JSON is a helper function to write JSON responses
func JSON(w http.ResponseWriter, statusCode int, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if obj != nil {
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			// Write error response if encoding fails
			errText, _ := json.Marshal(map[string]string{
				"error":             "internal_server_error",
				"error_description": "Failed to encode JSON response",
				"error_detail":      err.Error(),
			})
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(errText)
		}
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Get the first IP in the comma-separated list
		ifs := strings.Split(xff, ",")
		return strings.TrimSpace(ifs[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	return ip
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
	db, err := db.New(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize rate limiter
	rateLimiter := ratelimit.NewRateLimiter(
		time.Duration(15)*time.Minute,
		5000,
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

	return &OAuthProxy{
		metadata:      metadata,
		db:            db,
		rateLimiter:   rateLimiter,
		providers:     providerManager,
		tokenManager:  tokenManager,
		provider:      provider,
		resourceName:  "MCP Tools",
		encryptionKey: os.Getenv("ENCRYPTION_KEY"),
	}, nil
}

func (p *OAuthProxy) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *OAuthProxy) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Setup cleanup goroutine for expired tokens
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
		defer ticker.Stop()
		context.AfterFunc(p.ctx, ticker.Stop)
		for range ticker.C {
			if err := p.db.CleanupExpiredTokens(); err != nil {
				log.Printf("Failed to cleanup expired tokens: %v", err)
			}
		}
	}()

	return nil
}

// getBaseURL returns the base URL from the request
func (p *OAuthProxy) getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func (p *OAuthProxy) SetupRoutes(mux *http.ServeMux) {
	// Health endpoint
	mux.HandleFunc("/health", p.withCORS(p.healthHandler))

	// OAuth endpoints
	mux.HandleFunc("/authorize", p.withCORS(p.withRateLimit(p.authorizeHandler)))
	mux.HandleFunc("/callback", p.withCORS(p.withRateLimit(p.callbackHandler)))
	mux.HandleFunc("/token", p.withCORS(p.withRateLimit(p.tokenHandler)))
	mux.HandleFunc("/revoke", p.withCORS(p.withRateLimit(p.revokeHandler)))
	mux.HandleFunc("/register", p.withCORS(p.withRateLimit(p.registerHandler)))

	// Metadata endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", p.withCORS(p.oauthMetadataHandler))
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", p.withCORS(p.protectedResourceMetadataHandler))

	// Protected resource endpoints
	mux.HandleFunc("/mcp", p.withCORS(p.withRateLimit(p.withTokenValidation(p.mcpProxyHandler))))
	mux.HandleFunc("/mcp/{path...}", p.withCORS(p.withRateLimit(p.withTokenValidation(p.mcpProxyHandler))))
}

// GetHandler returns an http.Handler for the OAuth proxy
func (p *OAuthProxy) GetHandler() http.Handler {
	mux := http.NewServeMux()
	p.SetupRoutes(mux)

	// Wrap with logging middleware
	loggedHandler := handlers.LoggingHandler(os.Stdout, mux)

	return loggedHandler
}

// withCORS wraps a handler with CORS headers
func (p *OAuthProxy) withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, mcp-protocol-version")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(int((12 * time.Hour).Seconds())))

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// withRateLimit wraps a handler with rate limiting
func (p *OAuthProxy) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.rateLimiter != nil {
			clientIP := getClientIP(r)
			if !p.rateLimiter.Allow(clientIP) {
				JSON(w, http.StatusTooManyRequests, OAuthError{
					Error:            "too_many_requests",
					ErrorDescription: "Rate limit exceeded",
				})
				return
			}
		}
		next(w, r)
	}
}

func (p *OAuthProxy) healthHandler(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *OAuthProxy) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Get parameters from query or form
	var params url.Values
	if r.Method == "GET" {
		params = r.URL.Query()
	} else {
		if err := r.ParseForm(); err != nil {
			JSON(w, http.StatusBadRequest, OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "Failed to parse form data",
			})
			return
		}
		params = r.Form
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
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing required parameters",
		})
		return
	}

	// Validate response type
	if authReq.ResponseType != "code" && authReq.ResponseType != "token" {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "unsupported_response_type",
			ErrorDescription: "Only 'code' and 'token' response types are supported",
		})
		return
	}

	// Validate client exists
	clientInfo, err := p.db.GetClient(authReq.ClientID)
	if err != nil || clientInfo == nil {
		JSON(w, http.StatusBadRequest, OAuthError{
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
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect URI",
		})
		return
	}

	providerName := p.provider

	// Get the provider
	provider, err := p.providers.GetProvider(providerName)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
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
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "OAuth provider not configured",
		})
		return
	}

	stateData, err := json.Marshal(authReq)
	if err != nil {
		JSON(w, http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to marshal state data",
		})
		return
	}

	encodedState := base64.URLEncoding.EncodeToString(stateData)
	redirectURI := fmt.Sprintf("%s/callback", p.getBaseURL(r))

	// Generate authorization URL with the provider
	authURL := provider.GetAuthorizationURL(
		clientID,
		redirectURI,
		authReq.Scope,
		encodedState,
	)

	// Redirect to the provider's authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *OAuthProxy) callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Handle OAuth callback from external providers
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Check for OAuth errors
	if error != "" {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            error,
			ErrorDescription: errorDescription,
		})
		return
	}

	// Validate required parameters
	if code == "" {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing authorization code",
		})
		return
	}

	var authReq AuthRequest
	stateData, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid state parameter",
		})
		return
	}
	if err := json.Unmarshal(stateData, &authReq); err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid state parameter",
		})
		return
	}

	// Get the provider
	provider, err := p.providers.GetProvider(p.provider)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Provider not available",
		})
		return
	}

	// Get provider credentials
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	redirectURI := fmt.Sprintf("%s/callback", p.getBaseURL(r))

	// Exchange code for tokens
	tokenInfo, err := provider.ExchangeCodeForToken(r.Context(), code, clientID, clientSecret, redirectURI)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to exchange authorization code",
		})
		return
	}

	// Get user info from the provider
	userInfo, err := provider.GetUserInfo(r.Context(), tokenInfo.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to get user information",
		})
		return
	}

	// Create a grant for this user
	grantID, err := generateRandomString(16)
	if err != nil {
		JSON(w, http.StatusInternalServerError, OAuthError{
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
			JSON(w, http.StatusInternalServerError, OAuthError{
				Error:            "server_error",
				ErrorDescription: "Invalid encryption key configuration",
			})
			return
		}

		// Validate key length (must be 32 bytes for AES-256)
		if len(encryptionKey) != 32 {
			log.Printf("Invalid encryption key length: %d bytes (expected 32)", len(encryptionKey))
			JSON(w, http.StatusInternalServerError, OAuthError{
				Error:            "server_error",
				ErrorDescription: "Invalid encryption key length",
			})
			return
		}

		// Encrypt the sensitive props data
		encryptedProps, err := encryptData(sensitiveProps, encryptionKey)
		if err != nil {
			log.Printf("Failed to encrypt props data: %v", err)
			JSON(w, http.StatusInternalServerError, OAuthError{
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

	grant := &types.Grant{
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
		JSON(w, http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store grant",
		})
		return
	}

	// Generate authorization code
	randomPart, err := generateRandomString(32)
	if err != nil {
		JSON(w, http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to generate authorization code",
		})
		return
	}
	authCode := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, randomPart)

	// Store the authorization code
	if err := p.db.StoreAuthCode(authCode, grantID, userInfo.ID); err != nil {
		log.Printf("Failed to store authorization code: %v", err)
		JSON(w, http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store authorization code",
		})
		return
	}

	// Build the redirect URL back to the client
	redirectURL := authReq.RedirectURI

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		JSON(w, http.StatusInternalServerError, OAuthError{
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
	w.Header().Set("Location", parsedURL.String())
	w.WriteHeader(http.StatusFound)
}

func (p *OAuthProxy) oauthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := p.getBaseURL(r)

	// Create dynamic metadata based on the request
	metadata := &OAuthMetadata{
		Issuer:                                   baseURL,
		ServiceDocumentation:                     p.metadata.ServiceDocumentation,
		AuthorizationEndpoint:                    fmt.Sprintf("%s/authorize", baseURL),
		ResponseTypesSupported:                   p.metadata.ResponseTypesSupported,
		CodeChallengeMethodsSupported:            p.metadata.CodeChallengeMethodsSupported,
		TokenEndpoint:                            fmt.Sprintf("%s/token", baseURL),
		TokenEndpointAuthMethodsSupported:        p.metadata.TokenEndpointAuthMethodsSupported,
		GrantTypesSupported:                      p.metadata.GrantTypesSupported,
		ScopesSupported:                          p.metadata.ScopesSupported,
		RevocationEndpoint:                       fmt.Sprintf("%s/revoke", baseURL),
		RevocationEndpointAuthMethodsSupported:   p.metadata.RevocationEndpointAuthMethodsSupported,
		RegistrationEndpoint:                     fmt.Sprintf("%s/register", baseURL),
		RegistrationEndpointAuthMethodsSupported: p.metadata.RegistrationEndpointAuthMethodsSupported,
	}

	JSON(w, http.StatusOK, metadata)
}

func (p *OAuthProxy) protectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata := OAuthProtectedResourceMetadata{
		Resource:              fmt.Sprintf("%s/mcp", p.getBaseURL(r)),
		AuthorizationServers:  []string{p.getBaseURL(r)},
		Scopes:                p.metadata.ScopesSupported,
		ResourceName:          p.resourceName,
		ResourceDocumentation: p.metadata.ServiceDocumentation,
	}

	JSON(w, http.StatusOK, metadata)
}

func (p *OAuthProxy) withTokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Return 401 with proper WWW-Authenticate header
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", p.getBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Missing Authorization header",
			})
			return
		}

		// Parse Authorization header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", p.getBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid Authorization header format, expected 'Bearer TOKEN'", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid Authorization header format, expected 'Bearer TOKEN'",
			})
			return
		}

		token := parts[1]

		tokenInfo, err := p.tokenManager.GetTokenInfo(token)
		if err != nil {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", p.getBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid or expired token", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid or expired token",
			})
			return
		}

		// Decrypt props if needed before storing in context
		if tokenInfo.Props != nil {
			decryptedProps, err := p.decryptPropsIfNeeded(tokenInfo.Props)
			if err != nil {
				resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", p.getBaseURL(r))
				wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Failed to decrypt token data", resource_metadata="%s"`, resourceMetadataUrl)
				w.Header().Set("WWW-Authenticate", wwwAuthValue)
				JSON(w, http.StatusUnauthorized, map[string]string{
					"error":             "invalid_token",
					"error_description": "Failed to decrypt token data",
				})
				return
			}
			tokenInfo.Props = decryptedProps
		}

		next(w, r.WithContext(context.WithValue(r.Context(), tokenInfoKey{}, tokenInfo)))
	}
}

type tokenInfoKey struct{}

func (p *OAuthProxy) mcpProxyHandler(w http.ResponseWriter, r *http.Request) {
	tokenInfo := r.Context().Value(tokenInfoKey{}).(*tokens.TokenInfo)
	path := r.PathValue("path")

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
						JSON(w, http.StatusUnauthorized, map[string]string{
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
						JSON(w, http.StatusInternalServerError, map[string]string{
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
						JSON(w, http.StatusInternalServerError, map[string]string{
							"error":             "server_error",
							"error_description": "OAuth credentials not configured",
						})
						p.lock.Unlock()
						return
					}

					// Refresh the token
					newTokenInfo, err := provider.RefreshToken(r.Context(), refreshToken, clientID, clientSecret)
					if err != nil {
						log.Printf("Failed to refresh token: %v", err)
						JSON(w, http.StatusUnauthorized, map[string]string{
							"error":             "invalid_token",
							"error_description": "Failed to refresh access token",
						})
						p.lock.Unlock()
						return
					}

					// Update the grant with new token information
					if err := p.updateGrant(tokenInfo.GrantID, tokenInfo.UserID, tokenInfo, newTokenInfo); err != nil {
						log.Printf("Failed to update grant: %v", err)
						JSON(w, http.StatusInternalServerError, map[string]string{
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
	log.Printf("Proxying request: %s %s -> %s", r.Method, r.URL.Path, targetURL)

	// Create reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Header.Del("Authorization")
			req.Header.Set("X-Forwarded-Host", req.Host)

			newURL, _ := url.Parse(targetURL)
			req.URL.Scheme = newURL.Scheme
			req.URL.Host = newURL.Host
			req.Host = newURL.Host

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
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			rw.WriteHeader(http.StatusBadGateway)
		},
	}

	// Serve the proxied request
	proxy.ServeHTTP(w, r)
}

func (p *OAuthProxy) tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Check for client ID
	if clientID == "" {
		JSON(w, http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client ID is required",
		})
		return
	}

	// Get client info to determine authentication method
	clientInfo, err := p.db.GetClient(clientID)
	if err != nil || clientInfo == nil {
		JSON(w, http.StatusUnauthorized, OAuthError{
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
			JSON(w, http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client secret is required for confidential clients",
			})
			return
		}

		// Validate client secret for confidential clients
		if clientInfo.ClientSecret != clientSecret {
			JSON(w, http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client secret",
			})
			return
		}
	}

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, clientID)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, clientID)
	default:
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "unsupported_grant_type",
			ErrorDescription: "The grant type is not supported by this authorization server",
		})
	}
}

func (p *OAuthProxy) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	// Validate authorization code
	grantID, userID, err := p.db.ValidateAuthCode(code)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid authorization code",
		})
		return
	}

	// Get the grant
	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Grant not found",
		})
		return
	}

	// Verify client ID matches
	if grant.ClientID != clientID {
		JSON(w, http.StatusBadRequest, OAuthError{
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
			JSON(w, http.StatusBadRequest, OAuthError{
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
			JSON(w, http.StatusBadRequest, OAuthError{
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
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "redirect_uri is required when not using PKCE",
		})
		return
	}

	// Check PKCE if code_verifier is provided
	if codeVerifier != "" {
		if !isPkceEnabled {
			JSON(w, http.StatusBadRequest, OAuthError{
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
			JSON(w, http.StatusBadRequest, OAuthError{
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
	tokenData := &types.TokenData{
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
		JSON(w, http.StatusInternalServerError, OAuthError{
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

	JSON(w, http.StatusOK, response)
}

func (p *OAuthProxy) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	refreshToken := r.FormValue("refresh_token")

	// Validate refresh token from database
	tokenData, err := p.db.GetTokenByRefreshToken(refreshToken)
	if err != nil {
		JSON(w, http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid refresh token",
		})
		return
	}

	// Check if token is revoked
	if tokenData.Revoked {
		JSON(w, http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token has been revoked",
		})
		return
	}

	// Check if refresh token is expired
	if time.Now().After(tokenData.RefreshTokenExpiresAt) {
		JSON(w, http.StatusUnauthorized, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Refresh token has expired",
		})
		return
	}

	// Check if token belongs to the requesting client
	if tokenData.ClientID != clientID {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token does not belong to the requesting client",
		})
		return
	}

	// Get the grant to access props
	_, err = p.db.GetGrant(tokenData.GrantID, tokenData.UserID)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
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
	newTokenData := &types.TokenData{
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
		JSON(w, http.StatusInternalServerError, OAuthError{
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

	JSON(w, http.StatusOK, response)
}

func (p *OAuthProxy) revokeHandler(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint") // RFC 7009: token_type_hint parameter
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client ID
	if clientID == "" {
		JSON(w, http.StatusUnauthorized, OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client ID is required",
		})
		return
	}

	// Get client info to determine authentication method
	clientInfo, err := p.db.GetClient(clientID)
	if err != nil || clientInfo == nil {
		JSON(w, http.StatusUnauthorized, OAuthError{
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
			JSON(w, http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client secret is required for confidential clients",
			})
			return
		}

		// Validate client secret for confidential clients
		if clientInfo.ClientSecret != clientSecret {
			JSON(w, http.StatusUnauthorized, OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client secret",
			})
			return
		}
	}

	// Validate token parameter
	if token == "" {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Token parameter is required",
		})
		return
	}

	// Optional: Validate that the token belongs to the requesting client
	// This is a security best practice but not required by RFC 7009
	var tokenData *types.TokenData
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
	w.WriteHeader(http.StatusOK)
}

func (p *OAuthProxy) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Client registration is always enabled when this endpoint is accessible

	// Only allow POST method
	if r.Method != "POST" {
		JSON(w, http.StatusMethodNotAllowed, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		return
	}

	// Check content length (max 1MB)
	if r.ContentLength > 1024*1024 {
		JSON(w, http.StatusRequestEntityTooLarge, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Request payload too large, must be under 1 MiB",
		})
		return
	}

	// Parse JSON body
	var clientMetadata map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&clientMetadata); err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON payload",
		})
		return
	}

	// Validate and extract client metadata
	clientInfo, err := p.validateClientMetadata(clientMetadata)
	if err != nil {
		JSON(w, http.StatusBadRequest, OAuthError{
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
	dbClientInfo := &types.ClientInfo{
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
		JSON(w, http.StatusInternalServerError, OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to register client",
		})
		return
	}

	// Build response
	baseURL := p.getBaseURL(r)
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

	JSON(w, http.StatusCreated, response)
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

// encryptData encrypts sensitive data using AES-256-GCM
func encryptData(data map[string]interface{}, encryptionKey []byte) (*encryption.EncryptedProps, error) {
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

	return &encryption.EncryptedProps{
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		IV:        base64.StdEncoding.EncodeToString(iv),
		Algorithm: "AES-256-GCM",
	}, nil
}

// decryptData decrypts encrypted data using AES-256-GCM
func decryptData(encryptedProps *encryption.EncryptedProps, encryptionKey []byte) (map[string]interface{}, error) {
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
	encryptedProps := &encryption.EncryptedProps{
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
	db *db.Store
}

func (da *databaseAdapter) GetToken(accessToken string) (interface{}, error) {
	return da.db.GetToken(accessToken)
}

func (da *databaseAdapter) GetGrant(grantID, userID string) (interface{}, error) {
	return da.db.GetGrant(grantID, userID)
}

// OAuthProxy represents the OAuth proxy server
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
