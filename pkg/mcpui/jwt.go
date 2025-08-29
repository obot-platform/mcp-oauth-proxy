package mcpui

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MCPUICodeClaims represents the JWT claims for MCP UI codes
type MCPUICodeClaims struct {
	BearerToken  string `json:"bearer_token"`
	RefreshToken string `json:"refresh_token"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT operations for MCP UI codes with signing and encryption
type JWTManager struct {
	signingKey    []byte
	encryptionKey []byte
}

// NewJWTManager creates a new JWT manager with the given signing and encryption keys
func NewJWTManager(signingKey []byte, encryptionKey []byte) *JWTManager {
	return &JWTManager{
		signingKey:    signingKey,
		encryptionKey: encryptionKey,
	}
}

// GenerateMCPUICode creates a signed JWT then encrypts it containing the bearer token with 1-minute expiration
func (j *JWTManager) GenerateMCPUICode(bearerToken string, refreshToken string) (string, error) {
	// Create claims with 1-minute expiration
	claims := MCPUICodeClaims{
		BearerToken:  bearerToken,
		RefreshToken: refreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Create and sign the JWT first
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedJWT, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	// Encrypt the signed JWT using AES-GCM
	encryptedJWT, err := j.encrypt([]byte(signedJWT))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt signed JWT: %w", err)
	}

	// Base64 encode the encrypted data for URL safety
	return base64.URLEncoding.EncodeToString(encryptedJWT), nil
}

// ValidateMCPUICode validates and extracts the bearer token from the encrypted and signed JWT
func (j *JWTManager) ValidateMCPUICode(tokenString string) (string, string, error) {
	// Base64 decode the encrypted data
	encryptedJWT, err := base64.URLEncoding.DecodeString(tokenString)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode token: %w", err)
	}

	// Decrypt the JWT
	signedJWT, err := j.decrypt(encryptedJWT)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt JWT: %w", err)
	}

	// Parse and validate the signed JWT
	token, err := jwt.ParseWithClaims(string(signedJWT), &MCPUICodeClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signingKey, nil
	})

	if err != nil {
		return "", "", fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract claims
	if claims, ok := token.Claims.(*MCPUICodeClaims); ok && token.Valid {
		return claims.BearerToken, claims.RefreshToken, nil
	}

	return "", "", fmt.Errorf("invalid token claims")
}

// encrypt encrypts data using AES-GCM
func (j *JWTManager) encrypt(data []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(j.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (j *JWTManager) decrypt(encryptedData []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(j.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce and ciphertext
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncodeKey encodes a key to base64 for storage
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64-encoded key
func DecodeKey(encodedKey string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encodedKey)
}
