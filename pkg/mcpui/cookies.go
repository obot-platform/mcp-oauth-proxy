package mcpui

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	MCPUICookieName        = "mcp-ui-code"
	MCPUIRefreshCookieName = "mcp-ui-refresh-code"
	DefaultCookieMaxAge    = 3600 // 1 hour
)

// CookieManager handles browser cookies for MCP UI authentication
type CookieManager struct {
	httpOnly bool
	sameSite http.SameSite
}

// NewCookieManager creates a new cookie manager
func NewCookieManager() *CookieManager {
	return &CookieManager{
		httpOnly: true,
		sameSite: http.SameSiteStrictMode,
	}
}

// isSecureRequest determines if the request is over HTTPS
func (c *CookieManager) isSecureRequest(r *http.Request) bool {
	// Check if request is HTTPS
	if r.TLS != nil {
		return true
	}

	// Check forwarded headers from reverse proxies
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}

	if r.Header.Get("X-Forwarded-Ssl") == "on" {
		return true
	}

	return false
}

// getDomain extracts the appropriate domain for cookies
func (c *CookieManager) getDomain(r *http.Request) string {
	host := r.Host

	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// For localhost, don't set domain (allows cookies to work on localhost)
	if host == "localhost" || host == "127.0.0.1" {
		return ""
	}

	return host
}

// SetMCPUICookie sets the MCP UI authentication cookie containing the bearer token
func (c *CookieManager) SetMCPUICookie(w http.ResponseWriter, r *http.Request, bearerToken string) {
	// Encode the bearer token for cookie storage
	cookie := &http.Cookie{
		Name:     MCPUICookieName,
		Value:    bearerToken,
		Path:     "/",
		Domain:   c.getDomain(r),
		MaxAge:   DefaultCookieMaxAge,
		Secure:   c.isSecureRequest(r),
		HttpOnly: c.httpOnly,
		SameSite: c.sameSite,
	}

	http.SetCookie(w, cookie)
}

// SetMCPUIRefreshCookie sets the refresh token cookie
func (c *CookieManager) SetMCPUIRefreshCookie(w http.ResponseWriter, r *http.Request, refreshToken string) {
	// Encode the refresh token for cookie storage
	cookie := &http.Cookie{
		Name:     MCPUIRefreshCookieName,
		Value:    refreshToken,
		Path:     "/",
		Domain:   c.getDomain(r),
		MaxAge:   DefaultCookieMaxAge * 24 * 30, // 30 days for refresh token
		Secure:   c.isSecureRequest(r),
		HttpOnly: c.httpOnly,
		SameSite: c.sameSite,
	}

	http.SetCookie(w, cookie)
}

// GetMCPUICookie retrieves and decodes the MCP UI authentication cookie
func (c *CookieManager) GetMCPUICookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(MCPUICookieName)
	if err != nil {
		return "", fmt.Errorf("MCP UI cookie not found: %w", err)
	}

	return cookie.Value, nil
}

// GetMCPUIRefreshCookie retrieves and decodes the MCP UI refresh cookie
func (c *CookieManager) GetMCPUIRefreshCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(MCPUIRefreshCookieName)
	if err != nil {
		return "", fmt.Errorf("MCP UI refresh cookie not found: %w", err)
	}

	return cookie.Value, nil
}
