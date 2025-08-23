package encryption

// EncryptedProps represents encrypted properties with metadata
type EncryptedProps struct {
	Data      string `json:"data"`      // Base64 encoded encrypted data
	IV        string `json:"iv"`        // Base64 encoded initialization vector
	Algorithm string `json:"algorithm"` // Encryption algorithm used
}
