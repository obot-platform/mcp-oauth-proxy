package database

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseOperations tests all database operations
func TestDatabaseOperations(t *testing.T) {
	// Skip if no test database is available
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}

	// Create test database
	dsn := "postgres://test:test@localhost:5432/oauth_test?sslmode=disable"
	db, err := NewDatabase(dsn)
	if err != nil {
		t.Skipf("Skipping database tests: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Logf("Error closing database: %v", err)
		}
	}()

	t.Run("TestClientOperations", func(t *testing.T) {
		testClientOperations(t, db)
	})

	t.Run("TestGrantOperations", func(t *testing.T) {
		testGrantOperations(t, db)
	})

	t.Run("TestTokenOperations", func(t *testing.T) {
		testTokenOperations(t, db)
	})

	t.Run("TestAuthCodeOperations", func(t *testing.T) {
		testAuthCodeOperations(t, db)
	})

	t.Run("TestCleanupOperations", func(t *testing.T) {
		testCleanupOperations(t, db)
	})
}

func testClientOperations(t *testing.T, db *Database) {
	// Test storing client
	client := &ClientInfo{
		ClientID:                "test_client_db",
		ClientSecret:            "test_secret",
		RedirectUris:            []string{"https://test.example.com/callback"},
		ClientName:              "Test Client DB",
		LogoURI:                 "https://test.example.com/logo.png",
		ClientURI:               "https://test.example.com",
		PolicyURI:               "https://test.example.com/policy",
		TosURI:                  "https://test.example.com/tos",
		JwksURI:                 "https://test.example.com/jwks",
		Contacts:                []string{"admin@test.example.com"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		RegistrationDate:        time.Now().Unix(),
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	err := db.StoreClient(client)
	require.NoError(t, err)

	// Test retrieving client
	retrievedClient, err := db.GetClient("test_client_db")
	require.NoError(t, err)
	assert.Equal(t, client.ClientID, retrievedClient.ClientID)
	assert.Equal(t, client.ClientSecret, retrievedClient.ClientSecret)
	assert.Equal(t, client.RedirectUris, retrievedClient.RedirectUris)
	assert.Equal(t, client.ClientName, retrievedClient.ClientName)
	assert.Equal(t, client.LogoURI, retrievedClient.LogoURI)
	assert.Equal(t, client.ClientURI, retrievedClient.ClientURI)
	assert.Equal(t, client.PolicyURI, retrievedClient.PolicyURI)
	assert.Equal(t, client.TosURI, retrievedClient.TosURI)
	assert.Equal(t, client.JwksURI, retrievedClient.JwksURI)
	assert.Equal(t, client.Contacts, retrievedClient.Contacts)
	assert.Equal(t, client.GrantTypes, retrievedClient.GrantTypes)
	assert.Equal(t, client.ResponseTypes, retrievedClient.ResponseTypes)
	assert.Equal(t, client.RegistrationDate, retrievedClient.RegistrationDate)
	assert.Equal(t, client.TokenEndpointAuthMethod, retrievedClient.TokenEndpointAuthMethod)

	// Test retrieving non-existent client
	_, err = db.GetClient("non_existent_client")
	assert.Error(t, err)
}

func testGrantOperations(t *testing.T, db *Database) {
	// Test storing grant
	grant := &Grant{
		ID:                  "test_grant_db_123",
		ClientID:            "test_client_db",
		UserID:              "test_user_123",
		Scope:               []string{"read", "write", "admin"},
		Metadata:            map[string]interface{}{"provider": "test", "ip": "127.0.0.1"},
		Props:               map[string]interface{}{"email": "test@example.com", "name": "Test User"},
		CreatedAt:           time.Now().Unix(),
		ExpiresAt:           time.Now().Add(10 * time.Minute).Unix(),
		CodeChallenge:       "test_challenge",
		CodeChallengeMethod: "S256",
	}

	err := db.StoreGrant(grant)
	require.NoError(t, err)

	// Test retrieving grant
	retrievedGrant, err := db.GetGrant("test_grant_db_123", "test_user_123")
	require.NoError(t, err)
	assert.Equal(t, grant.ID, retrievedGrant.ID)
	assert.Equal(t, grant.ClientID, retrievedGrant.ClientID)
	assert.Equal(t, grant.UserID, retrievedGrant.UserID)
	assert.Equal(t, grant.Scope, retrievedGrant.Scope)
	assert.Equal(t, grant.Metadata, retrievedGrant.Metadata)
	assert.Equal(t, grant.Props, retrievedGrant.Props)
	assert.Equal(t, grant.CreatedAt, retrievedGrant.CreatedAt)
	assert.Equal(t, grant.ExpiresAt, retrievedGrant.ExpiresAt)
	assert.Equal(t, grant.CodeChallenge, retrievedGrant.CodeChallenge)
	assert.Equal(t, grant.CodeChallengeMethod, retrievedGrant.CodeChallengeMethod)

	// Test retrieving non-existent grant
	_, err = db.GetGrant("non_existent_grant", "test_user_123")
	assert.Error(t, err)
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
func testTokenOperations(t *testing.T, db *Database) {
	grantID, err := generateRandomString(16)
	require.NoError(t, err)

	refreshTokenData, err := generateRandomString(16)
	require.NoError(t, err)

	accessTokenData, err := generateRandomString(16)
	require.NoError(t, err)

	// Test storing token
	tokenData := &TokenData{
		AccessToken:  accessTokenData,
		RefreshToken: refreshTokenData,
		ClientID:     "test_client_db",
		UserID:       "test_user_123",
		GrantID:      grantID,
		Scope:        "read write admin",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
		Revoked:      false,
	}

	err = db.StoreToken(tokenData)
	require.NoError(t, err)

	// Test retrieving token
	retrievedToken, err := db.GetToken("test_access_token_db_123")
	require.NoError(t, err)
	assert.Equal(t, tokenData.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, tokenData.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, tokenData.ClientID, retrievedToken.ClientID)
	assert.Equal(t, tokenData.UserID, retrievedToken.UserID)
	assert.Equal(t, tokenData.GrantID, retrievedToken.GrantID)
	assert.Equal(t, tokenData.Scope, retrievedToken.Scope)
	assert.False(t, retrievedToken.Revoked)

	// Test retrieving token by refresh token
	refreshToken, err := db.GetTokenByRefreshToken(refreshTokenData)
	require.NoError(t, err)
	assert.Equal(t, tokenData.AccessToken, refreshToken.AccessToken)
	assert.Equal(t, tokenData.RefreshToken, refreshToken.RefreshToken)

	// Test revoking token
	err = db.RevokeToken(accessTokenData)
	require.NoError(t, err)

	revokedToken, err := db.GetToken(accessTokenData)
	require.NoError(t, err)
	assert.True(t, revokedToken.Revoked)
	assert.NotNil(t, revokedToken.RevokedAt)

	// Test updating refresh token
	newRefreshTokenData, err := generateRandomString(16)
	require.NoError(t, err)
	err = db.UpdateTokenRefreshToken(accessTokenData, newRefreshTokenData)
	require.NoError(t, err)

	updatedToken, err := db.GetToken(accessTokenData)
	require.NoError(t, err)
	assert.Equal(t, newRefreshTokenData, updatedToken.RefreshToken)

	// Test retrieving non-existent token
	_, err = db.GetToken("non_existent_token")
	assert.Error(t, err)
}

func testAuthCodeOperations(t *testing.T, db *Database) {
	// Test storing authorization code
	code := "test_auth_code_db_123"
	grantID := "test_grant_db_123"
	userID := "test_user_123"

	err := db.StoreAuthCode(code, grantID, userID)
	require.NoError(t, err)

	// Test validating authorization code
	retrievedGrantID, retrievedUserID, err := db.ValidateAuthCode(code)
	require.NoError(t, err)
	assert.Equal(t, grantID, retrievedGrantID)
	assert.Equal(t, userID, retrievedUserID)

	// Test deleting authorization code
	err = db.DeleteAuthCode(code)
	require.NoError(t, err)

	// Test validating deleted authorization code
	_, _, err = db.ValidateAuthCode(code)
	assert.Error(t, err)
}

func testCleanupOperations(t *testing.T, db *Database) {
	// Create expired tokens
	expiredToken := &TokenData{
		AccessToken:  "expired_token_123",
		RefreshToken: "expired_refresh_123",
		ClientID:     "test_client_db",
		UserID:       "test_user_123",
		GrantID:      "test_grant_db_123",
		Scope:        "read write",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		Revoked:      false,
	}

	err := db.StoreToken(expiredToken)
	require.NoError(t, err)

	// Test cleanup
	err = db.CleanupExpiredTokens()
	require.NoError(t, err)

	// Verify expired token is cleaned up
	_, err = db.GetToken("expired_token_123")
	assert.Error(t, err)
}

// TestCodeChallengeGeneration tests PKCE code challenge generation
func TestCodeChallengeGeneration(t *testing.T) {
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := GenerateCodeChallenge(codeVerifier)
	assert.Equal(t, expectedChallenge, challenge)

	// Test with random code verifier
	randomVerifier := "random_code_verifier_123"
	randomChallenge := GenerateCodeChallenge(randomVerifier)
	assert.NotEmpty(t, randomChallenge)
	assert.NotEqual(t, randomVerifier, randomChallenge)
}

// TestTokenHashing tests token hashing functionality
func TestTokenHashing(t *testing.T) {
	token := "test_token_123"
	hash1 := hashToken(token)
	hash2 := hashToken(token)

	// Same token should produce same hash
	assert.Equal(t, hash1, hash2)

	// Different tokens should produce different hashes
	differentToken := "different_token_456"
	hash3 := hashToken(differentToken)
	assert.NotEqual(t, hash1, hash3)

	// Hash should be consistent
	assert.NotEmpty(t, hash1)
	assert.Len(t, hash1, 44) // Base64 encoded SHA256 hash length
}
