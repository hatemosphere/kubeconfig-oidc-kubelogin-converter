package main

import (
	"testing"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
)

func TestBuildCacheKey_IncludesExtraScopes(t *testing.T) {
	scopes := []string{"profile", "email", "offline_access", "groups"}
	key := buildCacheKey("https://dex.example.com", "client", "secret", scopes)
	if len(key.Provider.ExtraScopes) != 4 {
		t.Fatalf("ExtraScopes length = %d, want 4", len(key.Provider.ExtraScopes))
	}

	// Verify key without scopes produces a different hash
	keyNoScopes := buildCacheKey("https://dex.example.com", "client", "secret", nil)
	if cacheChecksum(key) == cacheChecksum(keyNoScopes) {
		t.Error("cache key with and without ExtraScopes must produce different checksums")
	}
}

func TestCacheChecksum_MatchesKubelogin(t *testing.T) {
	tests := []struct {
		name     string
		key      tokencache.Key
		expected string
	}{
		{
			name: "base key with extra scopes and CA cert",
			key: tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL:    "YOUR_ISSUER",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					ExtraScopes:  []string{"openid", "email"},
				},
				TLSClientConfig: tlsclientconfig.Config{
					CACertFilename: []string{"/path/to/cert"},
				},
			},
			expected: "14254ac10e5bcfbfc2f54a2b34184495d27826ecb181a08751740e2fd3e46ba0",
		},
		{
			name: "minimal key",
			key: tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL: "https://example.com",
					ClientID:  "client-id",
				},
			},
			expected: "6c65998233293c518451f3abc44a7d6518239bd257592df90ba4e944fbe0b98b",
		},
		{
			name: "base key with auth request extra params",
			key: tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL:    "YOUR_ISSUER",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					ExtraScopes:  []string{"openid", "email"},
				},
				TLSClientConfig: tlsclientconfig.Config{
					CACertFilename: []string{"/path/to/cert"},
				},
				AuthRequestExtraParams: map[string]string{"audience": "api1"},
			},
			expected: "57c80323197c7046beb5cad37b83c81804b343ccf1d4edef2a4ae79af702a588",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheChecksum(tt.key)
			if got != tt.expected {
				t.Errorf("cacheChecksum() = %s, want %s", got, tt.expected)
			}
		})
	}
}
