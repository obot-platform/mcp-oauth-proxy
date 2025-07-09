package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Database represents the database connection and operations
type Database struct {
	db *sql.DB
}

// TokenData represents stored token data for OAuth 2.1 compliance
type TokenData struct {
	AccessToken  string
	RefreshToken string
	ClientID     string
	UserID       string
	GrantID      string
	Scope        string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	Revoked      bool
	RevokedAt    *time.Time
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

// Grant represents an authorization grant
type Grant struct {
	ID                  string                 `json:"id"`
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id"`
	Scope               []string               `json:"scope"`
	Metadata            map[string]interface{} `json:"metadata"`
	Props               map[string]interface{} `json:"props"`
	CreatedAt           int64                  `json:"created_at"`
	ExpiresAt           int64                  `json:"expires_at"`
	CodeChallenge       string                 `json:"code_challenge,omitempty"`
	CodeChallengeMethod string                 `json:"code_challenge_method,omitempty"`
}

// NewDatabase creates a new database connection and sets up the schema
func NewDatabase(dsn string) (*Database, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{db: db}

	// Setup schema
	if err := database.setupSchema(); err != nil {
		return nil, fmt.Errorf("failed to setup schema: %w", err)
	}

	return database, nil
}

// setupSchema creates the necessary tables
func (d *Database) setupSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			client_id VARCHAR(255) PRIMARY KEY,
			client_secret VARCHAR(255),
			redirect_uris JSONB NOT NULL,
			client_name VARCHAR(255),
			logo_uri VARCHAR(500),
			client_uri VARCHAR(500),
			policy_uri VARCHAR(500),
			tos_uri VARCHAR(500),
			jwks_uri VARCHAR(500),
			contacts JSONB,
			grant_types JSONB,
			response_types JSONB,
			registration_date BIGINT,
			token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic'
		)`,

		`CREATE TABLE IF NOT EXISTS grants (
			id VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			scope JSONB NOT NULL,
			metadata JSONB,
			props JSONB,
			created_at BIGINT NOT NULL,
			expires_at BIGINT NOT NULL,
			code_challenge VARCHAR(255),
			code_challenge_method VARCHAR(10)
		)`,

		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			grant_id VARCHAR(255) NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS access_tokens (
			access_token VARCHAR(255) PRIMARY KEY,
			refresh_token VARCHAR(255) UNIQUE,
			client_id VARCHAR(255) NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			grant_id VARCHAR(255) NOT NULL,
			scope TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMPTZ,
			FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
		)`,

		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_revoked ON access_tokens(revoked)`,
		`CREATE INDEX IF NOT EXISTS idx_grants_user_id ON grants(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_grants_client_id ON grants(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %s: %w", query, err)
		}
	}

	return nil
}

// GetClient retrieves a client by ID
func (d *Database) GetClient(clientID string) (*ClientInfo, error) {
	query := `
		SELECT client_id, client_secret, redirect_uris, client_name, logo_uri, client_uri, 
		       policy_uri, tos_uri, jwks_uri, contacts, grant_types, response_types, 
		       registration_date, token_endpoint_auth_method
		FROM clients WHERE client_id = $1
	`

	var client ClientInfo
	var redirectUris, contacts, grantTypes, responseTypes []byte
	var registrationDate sql.NullInt64

	err := d.db.QueryRow(query, clientID).Scan(
		&client.ClientID,
		&client.ClientSecret,
		&redirectUris,
		&client.ClientName,
		&client.LogoURI,
		&client.ClientURI,
		&client.PolicyURI,
		&client.TosURI,
		&client.JwksURI,
		&contacts,
		&grantTypes,
		&responseTypes,
		&registrationDate,
		&client.TokenEndpointAuthMethod,
	)

	if err != nil {
		return nil, err
	}

	// Parse JSON arrays
	if err := json.Unmarshal(redirectUris, &client.RedirectUris); err != nil {
		return nil, fmt.Errorf("failed to parse redirect_uris: %w", err)
	}
	if contacts != nil {
		if err := json.Unmarshal(contacts, &client.Contacts); err != nil {
			return nil, fmt.Errorf("failed to parse contacts: %w", err)
		}
	}
	if grantTypes != nil {
		if err := json.Unmarshal(grantTypes, &client.GrantTypes); err != nil {
			return nil, fmt.Errorf("failed to parse grant_types: %w", err)
		}
	}
	if responseTypes != nil {
		if err := json.Unmarshal(responseTypes, &client.ResponseTypes); err != nil {
			return nil, fmt.Errorf("failed to parse response_types: %w", err)
		}
	}
	if registrationDate.Valid {
		client.RegistrationDate = registrationDate.Int64
	}

	return &client, nil
}

// StoreClient stores a new client
func (d *Database) StoreClient(client *ClientInfo) error {
	query := `
		INSERT INTO clients (client_id, client_secret, redirect_uris, client_name, logo_uri, 
		                    client_uri, policy_uri, tos_uri, jwks_uri, contacts, grant_types, 
		                    response_types, registration_date, token_endpoint_auth_method)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	redirectUris, _ := json.Marshal(client.RedirectUris)
	contacts, _ := json.Marshal(client.Contacts)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	responseTypes, _ := json.Marshal(client.ResponseTypes)

	_, err := d.db.Exec(query,
		client.ClientID,
		client.ClientSecret,
		redirectUris,
		client.ClientName,
		client.LogoURI,
		client.ClientURI,
		client.PolicyURI,
		client.TosURI,
		client.JwksURI,
		contacts,
		grantTypes,
		responseTypes,
		client.RegistrationDate,
		client.TokenEndpointAuthMethod,
	)

	return err
}

// StoreGrant stores a new grant
func (d *Database) StoreGrant(grant *Grant) error {
	query := `
		INSERT INTO grants (id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	scope, _ := json.Marshal(grant.Scope)
	metadata, _ := json.Marshal(grant.Metadata)
	props, _ := json.Marshal(grant.Props)

	_, err := d.db.Exec(query,
		grant.ID,
		grant.ClientID,
		grant.UserID,
		scope,
		metadata,
		props,
		grant.CreatedAt,
		grant.ExpiresAt,
		grant.CodeChallenge,
		grant.CodeChallengeMethod,
	)

	return err
}

// GetGrant retrieves a grant by ID and user ID
func (d *Database) GetGrant(grantID, userID string) (*Grant, error) {
	query := `
		SELECT id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method
		FROM grants WHERE id = $1 AND user_id = $2
	`

	var grant Grant
	var scope, metadata, props []byte

	err := d.db.QueryRow(query, grantID, userID).Scan(
		&grant.ID,
		&grant.ClientID,
		&grant.UserID,
		&scope,
		&metadata,
		&props,
		&grant.CreatedAt,
		&grant.ExpiresAt,
		&grant.CodeChallenge,
		&grant.CodeChallengeMethod,
	)

	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	if err := json.Unmarshal(scope, &grant.Scope); err != nil {
		return nil, fmt.Errorf("failed to parse scope: %w", err)
	}
	if metadata != nil {
		if err := json.Unmarshal(metadata, &grant.Metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	}
	if props != nil {
		if err := json.Unmarshal(props, &grant.Props); err != nil {
			return nil, fmt.Errorf("failed to parse props: %w", err)
		}
	}

	return &grant, nil
}

// StoreAuthCode stores an authorization code
func (d *Database) StoreAuthCode(code, grantID, userID string) error {
	query := `
		INSERT INTO authorization_codes (code, grant_id, user_id, expires_at)
		VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')
	`

	_, err := d.db.Exec(query, code, grantID, userID)
	return err
}

// ValidateAuthCode validates an authorization code and returns grant info
func (d *Database) ValidateAuthCode(code string) (string, string, error) {
	query := `
		SELECT grant_id, user_id FROM authorization_codes 
		WHERE code = $1 AND expires_at > NOW()
	`

	var grantID, userID string
	err := d.db.QueryRow(query, code).Scan(&grantID, &userID)
	if err != nil {
		return "", "", err
	}

	return grantID, userID, nil
}

// DeleteAuthCode deletes an authorization code (single-use)
func (d *Database) DeleteAuthCode(code string) error {
	query := `DELETE FROM authorization_codes WHERE code = $1`
	_, err := d.db.Exec(query, code)
	return err
}

// hashRefreshToken creates a SHA-256 hash of the refresh token for secure storage
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// StoreToken stores an access token and refresh token
func (d *Database) StoreToken(data *TokenData) error {
	query := `
		INSERT INTO access_tokens (access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	// Hash the refresh token for secure storage
	hashedAccessToken := hashToken(data.AccessToken)
	hashedRefreshToken := hashToken(data.RefreshToken)

	_, err := d.db.Exec(query, hashedAccessToken, hashedRefreshToken, data.ClientID, data.UserID, data.GrantID, data.Scope, data.ExpiresAt)
	return err
}

// GetToken retrieves a token by access token
func (d *Database) GetToken(accessToken string) (*TokenData, error) {
	query := `
		SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, created_at, revoked, revoked_at
		FROM access_tokens WHERE access_token = $1
	`

	hashedAccessToken := hashToken(accessToken)

	var data TokenData
	var revokedAt sql.NullTime
	err := d.db.QueryRow(query, hashedAccessToken).Scan(
		&data.AccessToken,
		&data.RefreshToken,
		&data.ClientID,
		&data.UserID,
		&data.GrantID,
		&data.Scope,
		&data.ExpiresAt,
		&data.CreatedAt,
		&data.Revoked,
		&revokedAt,
	)

	if err != nil {
		return nil, err
	}

	if revokedAt.Valid {
		data.RevokedAt = &revokedAt.Time
	}

	return &data, nil
}

// GetTokenByRefreshToken retrieves a token by refresh token
func (d *Database) GetTokenByRefreshToken(refreshToken string) (*TokenData, error) {
	query := `
		SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, created_at, revoked, revoked_at
		FROM access_tokens WHERE refresh_token = $1
	`

	// Hash the refresh token for lookup
	hashedRefreshToken := hashToken(refreshToken)

	var data TokenData
	var revokedAt sql.NullTime
	err := d.db.QueryRow(query, hashedRefreshToken).Scan(
		&data.AccessToken,
		&data.RefreshToken, // This will be the hashed value from DB
		&data.ClientID,
		&data.UserID,
		&data.GrantID,
		&data.Scope,
		&data.ExpiresAt,
		&data.CreatedAt,
		&data.Revoked,
		&revokedAt,
	)

	if err != nil {
		return nil, err
	}

	if revokedAt.Valid {
		data.RevokedAt = &revokedAt.Time
	}

	// Store the original refresh token in the struct for the caller
	data.RefreshToken = refreshToken

	return &data, nil
}

// RevokeToken revokes an access token
func (d *Database) RevokeToken(token string) error {
	hashedToken := hashToken(token)
	// First try to revoke as access token
	query := `UPDATE access_tokens SET revoked = TRUE, revoked_at = NOW() WHERE access_token = $1`
	result, err := d.db.Exec(query, hashedToken)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		return nil
	}

	// If not found as access token, try as refresh token (hash it first)
	query = `UPDATE access_tokens SET revoked = TRUE, revoked_at = NOW() WHERE refresh_token = $1`
	_, err = d.db.Exec(query, hashedToken)
	return err
}

// UpdateTokenRefreshToken updates the refresh token for an existing token
func (d *Database) UpdateTokenRefreshToken(accessToken, newRefreshToken string) error {
	query := `UPDATE access_tokens SET refresh_token = $1 WHERE access_token = $2`

	hashedAccessToken := hashToken(accessToken)

	hashedNewRefreshToken := hashToken(newRefreshToken)

	_, err := d.db.Exec(query, hashedNewRefreshToken, hashedAccessToken)
	return err
}

// CleanupExpiredTokens removes expired tokens and authorization codes
func (d *Database) CleanupExpiredTokens() error {
	queries := []string{
		`DELETE FROM access_tokens WHERE expires_at < NOW() OR revoked = TRUE`,
		`DELETE FROM authorization_codes WHERE expires_at < NOW()`,
		`DELETE FROM grants WHERE expires_at < EXTRACT(EPOCH FROM NOW())`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to cleanup expired tokens: %w", err)
		}
	}

	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// GenerateCodeChallenge generates a PKCE code challenge from a code verifier
func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
