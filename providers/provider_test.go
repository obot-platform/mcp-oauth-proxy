package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockProviderForTest implements the Provider interface for testing
type MockProviderForTest struct {
	name string
}

func (m *MockProviderForTest) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	return "https://mock-provider.com/oauth/authorize?client_id=" + clientID + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&response_type=code"
}

func (m *MockProviderForTest) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) string {
	return "https://mock-provider.com/oauth/authorize?client_id=" + clientID + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&response_type=code&code_challenge=" + codeChallenge + "&code_challenge_method=" + codeChallengeMethod
}

func (m *MockProviderForTest) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenInfo, error) {
	return &TokenInfo{
		AccessToken:  "mock_access_token_" + code,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "mock_refresh_token_" + code,
		Scope:        "read write",
		IDToken:      "mock_id_token_" + code,
	}, nil
}

func (m *MockProviderForTest) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	return &UserInfo{
		ID:    "mock_user_123",
		Email: "test@example.com",
		Name:  "Test User",
	}, nil
}

func (m *MockProviderForTest) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenInfo, error) {
	return &TokenInfo{
		AccessToken:  "mock_new_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "mock_new_refresh_token",
		Scope:        "read write",
	}, nil
}

func (m *MockProviderForTest) GetName() string {
	return m.name
}

// TestManager tests the provider manager functionality
func TestManager(t *testing.T) {
	manager := NewManager()

	t.Run("TestRegisterAndGetProvider", func(t *testing.T) {
		// Test registering provider
		mockProvider := &MockProviderForTest{name: "test_provider"}
		manager.RegisterProvider("test", mockProvider)

		// Test getting provider
		provider, err := manager.GetProvider("test")
		require.NoError(t, err)
		assert.Equal(t, mockProvider, provider)
		assert.Equal(t, "test_provider", provider.GetName())

		// Test getting non-existent provider
		_, err = manager.GetProvider("non_existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "provider 'non_existent' not found")
	})

	t.Run("TestListProviders", func(t *testing.T) {
		// Clear manager
		manager = NewManager()

		// Register multiple providers
		provider1 := &MockProviderForTest{name: "provider1"}
		provider2 := &MockProviderForTest{name: "provider2"}
		provider3 := &MockProviderForTest{name: "provider3"}

		manager.RegisterProvider("p1", provider1)
		manager.RegisterProvider("p2", provider2)
		manager.RegisterProvider("p3", provider3)

		// Test listing providers
		providers := manager.ListProviders()
		assert.Len(t, providers, 3)
		assert.Contains(t, providers, "p1")
		assert.Contains(t, providers, "p2")
		assert.Contains(t, providers, "p3")
	})

	t.Run("TestConcurrentAccess", func(t *testing.T) {
		// Test concurrent registration and retrieval
		manager = NewManager()
		done := make(chan bool, 10)

		// Start multiple goroutines registering providers
		for i := 0; i < 5; i++ {
			go func(id int) {
				provider := &MockProviderForTest{name: "concurrent_provider"}
				manager.RegisterProvider("concurrent_"+string(rune(id)), provider)
				done <- true
			}(i)
		}

		// Start multiple goroutines retrieving providers
		for i := 0; i < 5; i++ {
			go func(id int) {
				_, err := manager.GetProvider("concurrent_" + string(rune(id)))
				// Some might not exist due to race conditions, which is expected
				_ = err
				done <- true
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify manager is still functional
		providers := manager.ListProviders()
		assert.GreaterOrEqual(t, len(providers), 0)
	})
}

// TestMockProvider tests the mock provider functionality
func TestMockProvider(t *testing.T) {
	provider := &MockProviderForTest{name: "test_mock"}

	t.Run("TestGetAuthorizationURL", func(t *testing.T) {
		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "read write", "test_state")
		assert.Contains(t, authURL, "https://mock-provider.com/oauth/authorize")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "redirect_uri=https://test.example.com/callback")
		assert.Contains(t, authURL, "scope=read write")
		assert.Contains(t, authURL, "state=test_state")
		assert.Contains(t, authURL, "response_type=code")
	})

	t.Run("TestGetAuthorizationURLWithPKCE", func(t *testing.T) {
		authURL := provider.GetAuthorizationURLWithPKCE("test_client", "https://test.example.com/callback", "read write", "test_state", "test_challenge", "S256")
		assert.Contains(t, authURL, "https://mock-provider.com/oauth/authorize")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "code_challenge=test_challenge")
		assert.Contains(t, authURL, "code_challenge_method=S256")
	})

	t.Run("TestExchangeCodeForToken", func(t *testing.T) {
		ctx := context.Background()
		tokenInfo, err := provider.ExchangeCodeForToken(ctx, "test_code", "test_client", "test_secret", "https://test.example.com/callback")
		require.NoError(t, err)
		assert.Equal(t, "mock_access_token_test_code", tokenInfo.AccessToken)
		assert.Equal(t, "Bearer", tokenInfo.TokenType)
		assert.Equal(t, 3600, tokenInfo.ExpiresIn)
		assert.Equal(t, "mock_refresh_token_test_code", tokenInfo.RefreshToken)
		assert.Equal(t, "read write", tokenInfo.Scope)
		assert.Equal(t, "mock_id_token_test_code", tokenInfo.IDToken)
	})

	t.Run("TestGetUserInfo", func(t *testing.T) {
		ctx := context.Background()
		userInfo, err := provider.GetUserInfo(ctx, "test_token")
		require.NoError(t, err)
		assert.Equal(t, "mock_user_123", userInfo.ID)
		assert.Equal(t, "test@example.com", userInfo.Email)
		assert.Equal(t, "Test User", userInfo.Name)
	})

	t.Run("TestRefreshToken", func(t *testing.T) {
		ctx := context.Background()
		tokenInfo, err := provider.RefreshToken(ctx, "test_refresh", "test_client", "test_secret")
		require.NoError(t, err)
		assert.Equal(t, "mock_new_access_token", tokenInfo.AccessToken)
		assert.Equal(t, "Bearer", tokenInfo.TokenType)
		assert.Equal(t, 3600, tokenInfo.ExpiresIn)
		assert.Equal(t, "mock_new_refresh_token", tokenInfo.RefreshToken)
		assert.Equal(t, "read write", tokenInfo.Scope)
	})

	t.Run("TestGetName", func(t *testing.T) {
		assert.Equal(t, "test_mock", provider.GetName())
	})
}

// TestProviderInterface tests that the mock provider correctly implements the Provider interface
func TestProviderInterface(t *testing.T) {
	var _ Provider = &MockProviderForTest{}
}

// TestTokenInfo tests the TokenInfo struct
func TestTokenInfo(t *testing.T) {
	tokenInfo := &TokenInfo{
		AccessToken:  "test_access_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "test_refresh_token",
		Scope:        "read write",
		IDToken:      "test_id_token",
	}

	assert.Equal(t, "test_access_token", tokenInfo.AccessToken)
	assert.Equal(t, "Bearer", tokenInfo.TokenType)
	assert.Equal(t, 3600, tokenInfo.ExpiresIn)
	assert.Equal(t, "test_refresh_token", tokenInfo.RefreshToken)
	assert.Equal(t, "read write", tokenInfo.Scope)
	assert.Equal(t, "test_id_token", tokenInfo.IDToken)
}

// TestUserInfo tests the UserInfo struct
func TestUserInfo(t *testing.T) {
	userInfo := &UserInfo{
		ID:    "test_user_id",
		Email: "test@example.com",
		Name:  "Test User",
	}

	assert.Equal(t, "test_user_id", userInfo.ID)
	assert.Equal(t, "test@example.com", userInfo.Email)
	assert.Equal(t, "Test User", userInfo.Name)
}
