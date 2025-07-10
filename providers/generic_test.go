package providers

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenericProvider_RefreshTokenParams(t *testing.T) {
	t.Run("TestGoogleRefreshTokenParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "openid profile email", "test_state")

		assert.Contains(t, authURL, "access_type=offline")
		assert.Contains(t, authURL, "prompt=consent")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=openid+profile+email")
		assert.Contains(t, authURL, "state=test_state")
	})

	t.Run("TestMicrosoftRefreshTokenParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "openid profile email", "test_state")

		assert.Contains(t, authURL, "response_mode=query")
		assert.Contains(t, authURL, "scope=openid+profile+email+offline_access")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "state=test_state")
	})

	t.Run("TestMicrosoftRefreshTokenParamsWithExistingOfflineAccess", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "openid profile email offline_access", "test_state")

		assert.Contains(t, authURL, "response_mode=query")
		assert.Contains(t, authURL, "scope=openid+profile+email+offline_access")
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "state=test_state")
	})

	t.Run("TestGenericProviderNoSpecialParams", func(t *testing.T) {
		provider := &GenericProvider{
			authorizeURL: "https://github.com/login/oauth/authorize",
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}

		authURL := provider.GetAuthorizationURL("test_client", "https://test.example.com/callback", "read:user user:email", "test_state")

		// Should not contain Google or Microsoft specific parameters
		assert.NotContains(t, authURL, "access_type=offline")
		assert.NotContains(t, authURL, "prompt=consent")
		assert.NotContains(t, authURL, "response_mode=query")
		assert.NotContains(t, authURL, "offline_access")

		// Should contain standard OAuth parameters
		assert.Contains(t, authURL, "client_id=test_client")
		assert.Contains(t, authURL, "scope=read%3Auser+user%3Aemail")
		assert.Contains(t, authURL, "state=test_state")
	})
}

func TestGenericProvider_AddRefreshTokenParams(t *testing.T) {
	provider := &GenericProvider{}

	t.Run("TestGoogleParams", func(t *testing.T) {
		provider.authorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
		q := url.Values{}

		provider.addRefreshTokenParams(q)

		assert.Equal(t, "offline", q.Get("access_type"))
		assert.Equal(t, "consent", q.Get("prompt"))
		assert.Equal(t, "", q.Get("response_mode"))
	})

	t.Run("TestMicrosoftParams", func(t *testing.T) {
		provider.authorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		q := url.Values{}
		q.Set("scope", "openid profile email")

		provider.addRefreshTokenParams(q)

		assert.Equal(t, "query", q.Get("response_mode"))
		assert.Equal(t, "openid profile email offline_access", q.Get("scope"))
		assert.Equal(t, "", q.Get("access_type"))
		assert.Equal(t, "", q.Get("prompt"))
	})

	t.Run("TestMicrosoftParamsWithExistingOfflineAccess", func(t *testing.T) {
		provider.authorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		q := url.Values{}
		q.Set("scope", "openid profile email offline_access")

		provider.addRefreshTokenParams(q)

		assert.Equal(t, "query", q.Get("response_mode"))
		assert.Equal(t, "openid profile email offline_access", q.Get("scope"))
	})

	t.Run("TestGenericProviderParams", func(t *testing.T) {
		provider.authorizeURL = "https://github.com/login/oauth/authorize"
		q := url.Values{}
		q.Set("scope", "read:user user:email")

		provider.addRefreshTokenParams(q)

		// Should not add any special parameters
		assert.Equal(t, "", q.Get("access_type"))
		assert.Equal(t, "", q.Get("prompt"))
		assert.Equal(t, "", q.Get("response_mode"))
		assert.Equal(t, "read:user user:email", q.Get("scope"))
	})
}
