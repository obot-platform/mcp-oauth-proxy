package types

import (
	"time"
)

// TokenData represents stored token data for OAuth 2.1 compliance
type TokenData struct {
	AccessToken           string `gorm:"primaryKey"`
	RefreshToken          string `gorm:"uniqueIndex"`
	ClientID              string `gorm:"not null;index"`
	UserID                string `gorm:"not null"`
	GrantID               string `gorm:"not null"`
	Scope                 string
	ExpiresAt             time.Time `gorm:"not null;index"`
	RefreshTokenExpiresAt time.Time `gorm:"not null"`
	CreatedAt             time.Time `gorm:"autoCreateTime"`
	Revoked               bool      `gorm:"default:false;index"`
	RevokedAt             *time.Time
}

// ClientInfo represents OAuth client registration information
type ClientInfo struct {
	ClientID                string      `gorm:"primaryKey" json:"client_id"`
	ClientSecret            string      `json:"client_secret,omitempty"`
	RedirectUris            StringSlice `gorm:"type:text" json:"redirect_uris"`
	ClientName              string      `json:"client_name,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Contacts                StringSlice `gorm:"type:text" json:"contacts,omitempty"`
	GrantTypes              StringSlice `gorm:"type:text" json:"grant_types,omitempty"`
	ResponseTypes           StringSlice `gorm:"type:text" json:"response_types,omitempty"`
	RegistrationDate        int64       `json:"registration_date,omitempty"`
	TokenEndpointAuthMethod string      `gorm:"default:client_secret_basic" json:"token_endpoint_auth_method"`
	CreatedAt               time.Time   `gorm:"autoCreateTime"`
	UpdatedAt               time.Time   `gorm:"autoUpdateTime"`
}

// Grant represents an authorization grant
type Grant struct {
	ID                  string      `gorm:"primaryKey" json:"id"`
	ClientID            string      `gorm:"not null;index" json:"client_id"`
	UserID              string      `gorm:"not null;index" json:"user_id"`
	Scope               StringSlice `gorm:"type:text" json:"scope"`
	Metadata            JSON        `gorm:"type:text" json:"metadata"`
	Props               JSON        `gorm:"type:text" json:"props"`
	CreatedAt           int64       `gorm:"not null" json:"created_at"`
	ExpiresAt           int64       `gorm:"not null" json:"expires_at"`
	CodeChallenge       string      `json:"code_challenge,omitempty"`
	CodeChallengeMethod string      `json:"code_challenge_method,omitempty"`
}

// AuthorizationCode represents an authorization code
type AuthorizationCode struct {
	Code      string    `gorm:"primaryKey"`
	GrantID   string    `gorm:"not null"`
	UserID    string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}
