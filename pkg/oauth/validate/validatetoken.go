package validate

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
)

type TokenValidator struct {
	tokenManager  *tokens.TokenManager
	encryptionKey []byte
}

func NewTokenValidator(tokenManager *tokens.TokenManager, encryptionKey []byte) *TokenValidator {
	return &TokenValidator{
		tokenManager:  tokenManager,
		encryptionKey: encryptionKey,
	}
}

func (p *TokenValidator) WithTokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Return 401 with proper WWW-Authenticate header
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Missing Authorization header",
			})
			return
		}

		// Parse Authorization header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid Authorization header format, expected 'Bearer TOKEN'", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid Authorization header format, expected 'Bearer TOKEN'",
			})
			return
		}

		token := parts[1]

		tokenInfo, err := p.tokenManager.GetTokenInfo(token)
		if err != nil {
			resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", handlerutils.GetBaseURL(r))
			wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Invalid or expired token", resource_metadata="%s"`, resourceMetadataUrl)
			w.Header().Set("WWW-Authenticate", wwwAuthValue)
			handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Invalid or expired token",
			})
			return
		}

		// Decrypt props if needed before storing in context
		if tokenInfo.Props != nil {
			decryptedProps, err := encryption.DecryptPropsIfNeeded(p.encryptionKey, tokenInfo.Props)
			if err != nil {
				resourceMetadataUrl := fmt.Sprintf("%s/.well-known/oauth-protected-resource/mcp", handlerutils.GetBaseURL(r))
				wwwAuthValue := fmt.Sprintf(`Bearer error="invalid_token", error_description="Failed to decrypt token data", resource_metadata="%s"`, resourceMetadataUrl)
				w.Header().Set("WWW-Authenticate", wwwAuthValue)
				handlerutils.JSON(w, http.StatusUnauthorized, map[string]string{
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

func GetTokenInfo(r *http.Request) *tokens.TokenInfo {
	return r.Context().Value(tokenInfoKey{}).(*tokens.TokenInfo)
}

type tokenInfoKey struct{}
