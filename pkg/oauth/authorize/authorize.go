package authorize

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type AuthorizationStore interface {
	GetClient(clientID string) (*types.ClientInfo, error)
}

type Handler struct {
	db              AuthorizationStore
	provider        providers.Provider
	scopesSupported []string
}

func NewHandler(db AuthorizationStore, provider providers.Provider, scopesSupported []string) http.Handler {
	return &Handler{
		db:              db,
		provider:        provider,
		scopesSupported: scopesSupported,
	}
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get parameters from query or form
	var params url.Values
	if r.Method == "GET" {
		params = r.URL.Query()
	} else {
		if err := r.ParseForm(); err != nil {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "Failed to parse form data",
			})
			return
		}
		params = r.Form
	}

	// Parse authorization request
	authReq := types.AuthRequest{
		ResponseType:        params.Get("response_type"),
		ClientID:            params.Get("client_id"),
		RedirectURI:         params.Get("redirect_uri"),
		Scope:               params.Get("scope"),
		State:               params.Get("state"),
		CodeChallenge:       params.Get("code_challenge"),
		CodeChallengeMethod: params.Get("code_challenge_method"),
	}

	if authReq.Scope == "" {
		authReq.Scope = strings.Join(p.scopesSupported, " ")
	}

	// Validate required parameters
	if authReq.ResponseType == "" || authReq.ClientID == "" || authReq.RedirectURI == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing required parameters",
		})
		return
	}

	// Validate response type
	if authReq.ResponseType != "code" && authReq.ResponseType != "token" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "unsupported_response_type",
			ErrorDescription: "Only 'code' and 'token' response types are supported",
		})
		return
	}

	// Validate client exists
	clientInfo, err := p.db.GetClient(authReq.ClientID)
	if err != nil || clientInfo == nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
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
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect URI",
		})
		return
	}

	// Get the provider's client ID and secret
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")

	// Check if provider is configured
	if clientID == "" || clientSecret == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "OAuth provider not configured",
		})
		return
	}

	stateData, err := json.Marshal(authReq)
	if err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to marshal state data",
		})
		return
	}

	encodedState := base64.URLEncoding.EncodeToString(stateData)
	redirectURI := fmt.Sprintf("%s/callback", handlerutils.GetBaseURL(r))

	// Generate authorization URL with the provider
	authURL := p.provider.GetAuthorizationURL(
		clientID,
		redirectURI,
		authReq.Scope,
		encodedState,
	)

	// Redirect to the provider's authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}
