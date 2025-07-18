package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// Database represents the database connection and operations
type Database struct {
	db     *sql.DB
	dbType string // "postgres" or "sqlite"
}

// TokenData represents stored token data for OAuth 2.1 compliance
type TokenData struct {
	AccessToken           string
	RefreshToken          string
	ClientID              string
	UserID                string
	GrantID               string
	Scope                 string
	ExpiresAt             time.Time
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
	Revoked               bool
	RevokedAt             *time.Time
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
	var db *sql.DB
	var dbType string
	var err error

	// If DSN is empty, use SQLite with local file
	if dsn == "" {
		// Create data directory if it doesn't exist
		dataDir := "data"
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}

		// Use local SQLite database
		sqlitePath := filepath.Join(dataDir, "oauth_proxy.db")
		db, err = sql.Open("sqlite3", sqlitePath)
		dbType = "sqlite"
	} else {
		// Check if it's a PostgreSQL DSN
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			db, err = sql.Open("postgres", dsn)
			dbType = "postgres"
		} else {
			// Assume SQLite file path
			db, err = sql.Open("sqlite3", dsn)
			dbType = "sqlite"
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{db: db, dbType: dbType}

	// Setup schema
	if err := database.setupSchema(); err != nil {
		return nil, fmt.Errorf("failed to setup schema: %w", err)
	}

	return database, nil
}

// setupSchema creates the necessary tables and handles migrations
func (d *Database) setupSchema() error {
	// First, create tables if they don't exist
	if err := d.createTables(); err != nil {
		return err
	}

	// Then run migrations
	if err := d.runMigrations(); err != nil {
		return err
	}

	return nil
}

// createTables creates the base tables
func (d *Database) createTables() error {
	var queries []string

	if d.dbType == "postgres" {
		queries = []string{
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
	} else {
		// SQLite schema
		queries = []string{
			`CREATE TABLE IF NOT EXISTS clients (
				client_id TEXT PRIMARY KEY,
				client_secret TEXT,
				redirect_uris TEXT NOT NULL,
				client_name TEXT,
				logo_uri TEXT,
				client_uri TEXT,
				policy_uri TEXT,
				tos_uri TEXT,
				jwks_uri TEXT,
				contacts TEXT,
				grant_types TEXT,
				response_types TEXT,
				registration_date INTEGER,
				token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic'
			)`,

			`CREATE TABLE IF NOT EXISTS grants (
				id TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				scope TEXT NOT NULL,
				metadata TEXT,
				props TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				code_challenge TEXT,
				code_challenge_method TEXT
			)`,

			`CREATE TABLE IF NOT EXISTS authorization_codes (
				code TEXT PRIMARY KEY,
				grant_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				expires_at DATETIME NOT NULL,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			)`,

			`CREATE TABLE IF NOT EXISTS access_tokens (
				access_token TEXT PRIMARY KEY,
				refresh_token TEXT UNIQUE,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				grant_id TEXT NOT NULL,
				scope TEXT,
				expires_at DATETIME NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				revoked INTEGER DEFAULT 0,
				revoked_at DATETIME,
				FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
			)`,

			`CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id)`,
			`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_access_tokens_revoked ON access_tokens(revoked)`,
			`CREATE INDEX IF NOT EXISTS idx_grants_user_id ON grants(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_grants_client_id ON grants(client_id)`,
			`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,
		}
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %s: %w", query, err)
		}
	}

	return nil
}

// runMigrations handles database schema migrations
func (d *Database) runMigrations() error {
	// Migration 1: Add refresh_token_expires_at column to access_tokens table
	if err := d.migrateAddRefreshTokenExpiration(); err != nil {
		return fmt.Errorf("failed to run migration 1: %w", err)
	}

	return nil
}

// migrateAddRefreshTokenExpiration adds the refresh_token_expires_at column
func (d *Database) migrateAddRefreshTokenExpiration() error {
	// Check if the column already exists
	columnExists, err := d.columnExists("access_tokens", "refresh_token_expires_at")
	if err != nil {
		return fmt.Errorf("failed to check if column exists: %w", err)
	}

	if columnExists {
		return nil // Column already exists, no migration needed
	}

	// Add the column
	var query string
	if d.dbType == "postgres" {
		query = `ALTER TABLE access_tokens ADD COLUMN refresh_token_expires_at TIMESTAMPTZ`
	} else {
		query = `ALTER TABLE access_tokens ADD COLUMN refresh_token_expires_at DATETIME`
	}

	if _, err := d.db.Exec(query); err != nil {
		return fmt.Errorf("failed to add refresh_token_expires_at column: %w", err)
	}

	// Update existing records to have a default expiration (30 days from now)
	updateQuery := `UPDATE access_tokens SET refresh_token_expires_at = ? WHERE refresh_token_expires_at IS NULL`
	if d.dbType == "postgres" {
		updateQuery = `UPDATE access_tokens SET refresh_token_expires_at = $1 WHERE refresh_token_expires_at IS NULL`
	}

	defaultExpiration := time.Now().Add(30 * 24 * time.Hour)
	if _, err := d.db.Exec(updateQuery, defaultExpiration); err != nil {
		return fmt.Errorf("failed to update existing records: %w", err)
	}

	// Make the column NOT NULL (SQLite doesn't support ALTER COLUMN SET NOT NULL directly)
	if d.dbType == "postgres" {
		query = `ALTER TABLE access_tokens ALTER COLUMN refresh_token_expires_at SET NOT NULL`
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to make refresh_token_expires_at NOT NULL: %w", err)
		}
	}

	return nil
}

// columnExists checks if a column exists in a table
func (d *Database) columnExists(tableName, columnName string) (bool, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT COUNT(*) FROM information_schema.columns 
			WHERE table_name = $1 AND column_name = $2
		`
	} else {
		query = `
			SELECT COUNT(*) FROM pragma_table_info(?) 
			WHERE name = ?
		`
	}

	var count int
	err := d.db.QueryRow(query, tableName, columnName).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetClient retrieves a client by ID
func (d *Database) GetClient(clientID string) (*ClientInfo, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT client_id, client_secret, redirect_uris, client_name, logo_uri, client_uri, 
			       policy_uri, tos_uri, jwks_uri, contacts, grant_types, response_types, 
			       registration_date, token_endpoint_auth_method
			FROM clients WHERE client_id = $1
		`
	} else {
		query = `
			SELECT client_id, client_secret, redirect_uris, client_name, logo_uri, client_uri, 
			       policy_uri, tos_uri, jwks_uri, contacts, grant_types, response_types, 
			       registration_date, token_endpoint_auth_method
			FROM clients WHERE client_id = ?
		`
	}

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
	var query string
	if d.dbType == "postgres" {
		query = `
			INSERT INTO clients (client_id, client_secret, redirect_uris, client_name, logo_uri, 
			                    client_uri, policy_uri, tos_uri, jwks_uri, contacts, grant_types, 
			                    response_types, registration_date, token_endpoint_auth_method)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		`
	} else {
		query = `
			INSERT INTO clients (client_id, client_secret, redirect_uris, client_name, logo_uri, 
			                    client_uri, policy_uri, tos_uri, jwks_uri, contacts, grant_types, 
			                    response_types, registration_date, token_endpoint_auth_method)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
	}

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
	var query string
	if d.dbType == "postgres" {
		query = `
			INSERT INTO grants (id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`
	} else {
		query = `
			INSERT INTO grants (id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
	}

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

// UpdateGrant updates an existing grant's properties
func (d *Database) UpdateGrant(grant *Grant) error {
	var query string
	if d.dbType == "postgres" {
		query = `
			UPDATE grants 
			SET scope = $1, metadata = $2, props = $3, expires_at = $4
			WHERE id = $5 AND user_id = $6
		`
	} else {
		query = `
			UPDATE grants 
			SET scope = ?, metadata = ?, props = ?, expires_at = ?
			WHERE id = ? AND user_id = ?
		`
	}

	scope, _ := json.Marshal(grant.Scope)
	metadata, _ := json.Marshal(grant.Metadata)
	props, _ := json.Marshal(grant.Props)

	result, err := d.db.Exec(query,
		scope,
		metadata,
		props,
		grant.ExpiresAt,
		grant.ID,
		grant.UserID,
	)
	if err != nil {
		return err
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("grant not found: id=%s, user_id=%s", grant.ID, grant.UserID)
	}

	return nil
}

// GetGrant retrieves a grant by ID and user ID
func (d *Database) GetGrant(grantID, userID string) (*Grant, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method
			FROM grants WHERE id = $1 AND user_id = $2
		`
	} else {
		query = `
			SELECT id, client_id, user_id, scope, metadata, props, created_at, expires_at, code_challenge, code_challenge_method
			FROM grants WHERE id = ? AND user_id = ?
		`
	}

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
	var query string
	if d.dbType == "postgres" {
		query = `
			INSERT INTO authorization_codes (code, grant_id, user_id, expires_at)
			VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')
		`
	} else {
		query = `
			INSERT INTO authorization_codes (code, grant_id, user_id, expires_at)
			VALUES (?, ?, ?, datetime('now', '+10 minutes'))
		`
	}

	_, err := d.db.Exec(query, code, grantID, userID)
	return err
}

// ValidateAuthCode validates an authorization code and returns grant info
func (d *Database) ValidateAuthCode(code string) (string, string, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT grant_id, user_id FROM authorization_codes 
			WHERE code = $1 AND expires_at > NOW()
		`
	} else {
		query = `
			SELECT grant_id, user_id FROM authorization_codes 
			WHERE code = ? AND expires_at > datetime('now')
		`
	}

	var grantID, userID string
	err := d.db.QueryRow(query, code).Scan(&grantID, &userID)
	if err != nil {
		return "", "", err
	}

	return grantID, userID, nil
}

// DeleteAuthCode deletes an authorization code (single-use)
func (d *Database) DeleteAuthCode(code string) error {
	var query string
	if d.dbType == "postgres" {
		query = `DELETE FROM authorization_codes WHERE code = $1`
	} else {
		query = `DELETE FROM authorization_codes WHERE code = ?`
	}
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
	var query string
	if d.dbType == "postgres" {
		query = `
			INSERT INTO access_tokens (access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`
	} else {
		query = `
			INSERT INTO access_tokens (access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`
	}

	// Hash the refresh token for secure storage
	hashedAccessToken := hashToken(data.AccessToken)
	hashedRefreshToken := hashToken(data.RefreshToken)

	// Set refresh token expiration to 30 days from now if not already set
	if data.RefreshTokenExpiresAt.IsZero() {
		data.RefreshTokenExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	}

	_, err := d.db.Exec(query, hashedAccessToken, hashedRefreshToken, data.ClientID, data.UserID, data.GrantID, data.Scope, data.ExpiresAt, data.RefreshTokenExpiresAt)
	return err
}

// GetToken retrieves a token by access token
func (d *Database) GetToken(accessToken string) (*TokenData, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at, created_at, revoked, revoked_at
			FROM access_tokens WHERE access_token = $1
		`
	} else {
		query = `
			SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at, created_at, revoked, revoked_at
			FROM access_tokens WHERE access_token = ?
		`
	}

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
		&data.RefreshTokenExpiresAt,
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
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at, created_at, revoked, revoked_at
			FROM access_tokens WHERE refresh_token = $1 AND refresh_token_expires_at > NOW()
		`
	} else {
		query = `
			SELECT access_token, refresh_token, client_id, user_id, grant_id, scope, expires_at, refresh_token_expires_at, created_at, revoked, revoked_at
			FROM access_tokens WHERE refresh_token = ? AND refresh_token_expires_at > datetime('now')
		`
	}

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
		&data.RefreshTokenExpiresAt,
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

// IsRefreshTokenExpired checks if a refresh token is expired
func (d *Database) IsRefreshTokenExpired(refreshToken string) (bool, error) {
	var query string
	if d.dbType == "postgres" {
		query = `
			SELECT refresh_token_expires_at FROM access_tokens WHERE refresh_token = $1
		`
	} else {
		query = `
			SELECT refresh_token_expires_at FROM access_tokens WHERE refresh_token = ?
		`
	}

	hashedRefreshToken := hashToken(refreshToken)
	var expiresAt time.Time
	err := d.db.QueryRow(query, hashedRefreshToken).Scan(&expiresAt)
	if err != nil {
		return false, err
	}

	return time.Now().After(expiresAt), nil
}

// RevokeToken revokes an access token
func (d *Database) RevokeToken(token string) error {
	hashedToken := hashToken(token)

	var query string
	if d.dbType == "postgres" {
		// First try to revoke as access token
		query = `UPDATE access_tokens SET revoked = TRUE, revoked_at = NOW() WHERE access_token = $1`
	} else {
		// First try to revoke as access token
		query = `UPDATE access_tokens SET revoked = 1, revoked_at = datetime('now') WHERE access_token = ?`
	}

	result, err := d.db.Exec(query, hashedToken)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		return nil
	}

	// If not found as access token, try as refresh token (hash it first)
	if d.dbType == "postgres" {
		query = `UPDATE access_tokens SET revoked = TRUE, revoked_at = NOW() WHERE refresh_token = $1`
	} else {
		query = `UPDATE access_tokens SET revoked = 1, revoked_at = datetime('now') WHERE refresh_token = ?`
	}
	_, err = d.db.Exec(query, hashedToken)
	return err
}

// UpdateTokenRefreshToken updates the refresh token for an existing token
func (d *Database) UpdateTokenRefreshToken(accessToken, newRefreshToken string) error {
	var query string
	if d.dbType == "postgres" {
		query = `UPDATE access_tokens SET refresh_token = $1 WHERE access_token = $2`
	} else {
		query = `UPDATE access_tokens SET refresh_token = ? WHERE access_token = ?`
	}

	hashedAccessToken := hashToken(accessToken)
	hashedNewRefreshToken := hashToken(newRefreshToken)

	_, err := d.db.Exec(query, hashedNewRefreshToken, hashedAccessToken)
	return err
}

// CleanupExpiredTokens removes expired tokens and authorization codes
func (d *Database) CleanupExpiredTokens() error {
	var queries []string

	if d.dbType == "postgres" {
		queries = []string{
			`DELETE FROM access_tokens WHERE (expires_at < NOW() AND refresh_token_expires_at < NOW()) OR revoked = TRUE`,
			`DELETE FROM authorization_codes WHERE expires_at < NOW()`,
			`DELETE FROM grants WHERE expires_at < EXTRACT(EPOCH FROM NOW())`,
		}
	} else {
		queries = []string{
			`DELETE FROM access_tokens WHERE (expires_at < datetime('now') AND refresh_token_expires_at < datetime('now')) OR revoked = 1`,
			`DELETE FROM authorization_codes WHERE expires_at < datetime('now')`,
			`DELETE FROM grants WHERE expires_at < strftime('%s', 'now')`,
		}
	}

	for _, query := range queries {
		result, err := d.db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired tokens: %w", err)
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			fmt.Printf("Deleted %d expired rows for query %s\n", rowsAffected, query)
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
