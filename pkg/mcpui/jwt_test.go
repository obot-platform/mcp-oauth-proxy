package mcpui

import (
	"crypto/rand"
	"testing"
)

func TestJWTManagerEncryption(t *testing.T) {
	// Generate a test encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create JWT manager (using same key for signing and encryption)
	jwtManager := NewJWTManager(key, key)

	// Test bearer token
	testBearerToken := "user123:grant456:secret789"
	testRefreshToken := "refresh123"

	// Generate encrypted JWT
	encryptedJWT, err := jwtManager.GenerateMCPUICode(testBearerToken, testRefreshToken)
	if err != nil {
		t.Fatalf("Failed to generate MCP UI code: %v", err)
	}

	// JWT should not be empty
	if encryptedJWT == "" {
		t.Fatal("Generated JWT is empty")
	}

	// JWT should not contain the bearer token in plaintext
	if string(encryptedJWT) == testBearerToken {
		t.Fatal("JWT contains plaintext bearer token")
	}

	// Validate and decrypt the JWT
	extractedBearerToken, extractedRefreshToken, err := jwtManager.ValidateMCPUICode(encryptedJWT)
	if err != nil {
		t.Fatalf("Failed to validate MCP UI code: %v", err)
	}

	// Extracted token should match original
	if extractedBearerToken != testBearerToken {
		t.Fatalf("Extracted bearer token doesn't match: expected %s, got %s", testBearerToken, extractedBearerToken)
	}

	// Extracted refresh token should match original
	if extractedRefreshToken != testRefreshToken {
		t.Fatalf("Extracted refresh token doesn't match: expected %s, got %s", testRefreshToken, extractedRefreshToken)
	}
}

func TestJWTManagerWrongKey(t *testing.T) {
	// Generate two different keys
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("Failed to generate test key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("Failed to generate test key2: %v", err)
	}

	// Create JWT managers with different keys
	jwtManager1 := NewJWTManager(key1, key1)
	jwtManager2 := NewJWTManager(key2, key2)

	// Test bearer token
	testBearerToken := "user123:grant456:secret789"
	testRefreshToken := "refresh123"

	// Generate JWT with first manager
	encryptedJWT, err := jwtManager1.GenerateMCPUICode(testBearerToken, testRefreshToken)
	if err != nil {
		t.Fatalf("Failed to generate MCP UI code: %v", err)
	}

	// Try to validate with second manager (wrong key) - should fail
	_, _, err = jwtManager2.ValidateMCPUICode(encryptedJWT)
	if err == nil {
		t.Fatal("Expected validation to fail with wrong key, but it succeeded")
	}
}
