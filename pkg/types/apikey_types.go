package types

// APIKeyAuthRequest is the request body sent to the API key authentication webhook.
type APIKeyAuthRequest struct {
	MCPServerID         string `json:"mcpServerId,omitempty"`
	MCPServerInstanceID string `json:"mcpServerInstanceId,omitempty"`
}

// APIKeyAuthResponse is the response from the API key authentication webhook.
type APIKeyAuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	Authorized    bool   `json:"authorized"`
	UserID        uint   `json:"userId,omitempty"`
	Username      string `json:"username,omitempty"`
	Error         string `json:"error,omitempty"`
}
