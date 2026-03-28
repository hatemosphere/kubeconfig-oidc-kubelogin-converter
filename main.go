package main

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/zalando/go-keyring"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

type cacheEntity struct {
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func tokenCacheDir() string {
	if dir, ok := os.LookupEnv("KUBECACHEDIR"); ok {
		return filepath.Join(dir, "oidc-login")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	return filepath.Join(home, ".kube", "cache", "oidc-login")
}

func cacheChecksum(key tokencache.Key) string {
	s := sha256.New()
	if err := gob.NewEncoder(s).Encode(&key); err != nil {
		log.Fatalf("Failed to compute cache key checksum: %v", err)
	}
	return hex.EncodeToString(s.Sum(nil))
}

var extraScopes = []string{"profile", "email", "offline_access", "groups"}

func buildCacheKey(issuer, clientID, clientSecret string) tokencache.Key {
	return tokencache.Key{
		Provider: oidc.Provider{
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			ExtraScopes:  extraScopes,
		},
	}
}

const keyringService = "kubelogin"
const keyringItemPrefix = "kubelogin/tokencache/"

func injectTokenCache(issuer, clientID, clientSecret, idToken, refreshToken string, useKeyring bool) {
	if idToken == "" && refreshToken == "" {
		return
	}
	key := buildCacheKey(issuer, clientID, clientSecret)
	checksum := cacheChecksum(key)
	data, err := json.Marshal(cacheEntity{IDToken: idToken, RefreshToken: refreshToken})
	if err != nil {
		log.Fatalf("Failed to marshal token cache: %v", err)
	}
	if useKeyring {
		if err := keyring.Set(keyringService, keyringItemPrefix+checksum, string(data)); err != nil {
			log.Fatalf("Failed to write token to keyring: %v", err)
		}
	} else {
		dir := tokenCacheDir()
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("Failed to create token cache dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, checksum), data, 0600); err != nil {
			log.Fatalf("Failed to write token cache: %v", err)
		}
	}
}

func removeTokenCache(issuer, clientID, clientSecret string, useKeyring bool) {
	key := buildCacheKey(issuer, clientID, clientSecret)
	checksum := cacheChecksum(key)
	if useKeyring {
		keyring.Delete(keyringService, keyringItemPrefix+checksum) // best-effort
	} else {
		os.Remove(filepath.Join(tokenCacheDir(), checksum)) // best-effort
	}
}

var validGrantTypes = map[string]bool{
	"authcode":           true,
	"authcode-keyboard":  true,
	"device-code":        true,
	"password":           true,
	"client-credentials": true,
}

func main() {
	reverse := flag.Bool("reverse", false, "Convert kubelogin exec entries back to auth-provider oidc")
	noBackup := flag.Bool("no-backup", false, "Skip creating a backup of the kubeconfig before conversion")
	grantType := flag.String("grant-type", "device-code", "OAuth2 grant type for kubelogin (authcode, authcode-keyboard, device-code, password, client-credentials)")
	tokenCacheStorage := flag.String("token-cache-storage", "keyring", "Token cache storage for kubelogin (keyring, disk)")
	flag.Parse()

	if !validGrantTypes[*grantType] {
		log.Fatalf("Invalid grant type %q. Supported: authcode, authcode-keyboard, device-code, password, client-credentials", *grantType)
	}
	if *tokenCacheStorage != "keyring" && *tokenCacheStorage != "disk" {
		log.Fatalf("Invalid token cache storage %q. Supported: keyring, disk", *tokenCacheStorage)
	}
	useKeyring := *tokenCacheStorage == "keyring"

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeconfigPath := loadingRules.GetDefaultFilename()

	config, err := loadingRules.Load()
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %v", err)
	}

	if *reverse {
		runReverse(config, kubeconfigPath, *noBackup, useKeyring)
	} else {
		runConvert(config, kubeconfigPath, *noBackup, *grantType, *tokenCacheStorage, useKeyring)
	}
}

func backup(kubeconfigPath string) {
	ts := time.Now().Format("20060102-150405")
	backupPath := kubeconfigPath + ".bak-" + ts
	src, err := os.Open(kubeconfigPath)
	if err != nil {
		log.Fatalf("Failed to open kubeconfig for backup: %v", err)
	}
	defer src.Close()
	dst, err := os.Create(backupPath)
	if err != nil {
		log.Fatalf("Failed to create backup file: %v", err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		log.Fatalf("Failed to write backup: %v", err)
	}
	fmt.Printf("Backup saved to %s\n\n", backupPath)
}

func writeConfig(config *api.Config, path string) {
	if err := clientcmd.WriteToFile(*config, path); err != nil {
		log.Fatalf("Failed to write kubeconfig: %v", err)
	}
	fmt.Printf("\nWritten to %s\n", path)
}

func runConvert(config *api.Config, kubeconfigPath string, noBackup bool, grantType, tokenCacheStorage string, useKeyring bool) {
	var converted []string
	for name, authInfo := range config.AuthInfos {
		if authInfo.AuthProvider == nil || authInfo.AuthProvider.Name != "oidc" {
			continue
		}
		cfg := authInfo.AuthProvider.Config

		issuer := cfg["idp-issuer-url"]
		clientID := cfg["client-id"]
		clientSecret := cfg["client-secret"]
		idToken := cfg["id-token"]
		refreshToken := cfg["refresh-token"]

		injectTokenCache(issuer, clientID, clientSecret, idToken, refreshToken, useKeyring)

		authInfo.AuthProvider = nil
		authInfo.Exec = &api.ExecConfig{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Command:    "kubectl",
			Args: []string{
				"oidc-login",
				"get-token",
				"--oidc-issuer-url=" + issuer,
				"--oidc-client-id=" + clientID,
				"--oidc-client-secret=" + clientSecret,
				"--grant-type=" + grantType,
				"--oidc-extra-scope=profile",
				"--oidc-extra-scope=email",
				"--oidc-extra-scope=offline_access",
				"--oidc-extra-scope=groups",
				"--token-cache-storage=" + tokenCacheStorage,
			},
		}
		converted = append(converted, name)
	}

	if len(converted) == 0 {
		fmt.Println("No OIDC auth-provider entries found to convert.")
		os.Exit(0)
	}

	if !noBackup {
		backup(kubeconfigPath)
	}

	sort.Strings(converted)
	fmt.Printf("Converting %d context(s) to kubelogin exec plugin:\n", len(converted))
	for _, name := range converted {
		fmt.Printf("  - %s\n", name)
	}

	writeConfig(config, kubeconfigPath)
	fmt.Println("\nMake sure kubelogin is installed: kubectl krew install oidc-login")
}

func runReverse(config *api.Config, kubeconfigPath string, noBackup bool, useKeyring bool) {
	var converted []string
	for name, authInfo := range config.AuthInfos {
		if authInfo.Exec == nil || authInfo.Exec.Command != "kubectl" {
			continue
		}
		args := authInfo.Exec.Args
		if len(args) < 2 || args[0] != "oidc-login" || args[1] != "get-token" {
			continue
		}

		params := map[string]string{}
		for _, arg := range args[2:] {
			if k, v, ok := strings.Cut(arg, "="); ok {
				params[k] = v
			}
		}

		clientID := params["--oidc-client-id"]

		removeTokenCache(params["--oidc-issuer-url"], clientID, params["--oidc-client-secret"], useKeyring)

		authInfo.Exec = nil
		authInfo.AuthProvider = &api.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      clientID,
				"client-secret":  params["--oidc-client-secret"],
				"idp-issuer-url": params["--oidc-issuer-url"],
				"id-token":       "",
				"refresh-token":  "",
			},
		}
		converted = append(converted, name)
	}

	if len(converted) == 0 {
		fmt.Println("No kubelogin exec entries found to revert.")

		// Check for backup files to suggest restoring
		dir := filepath.Dir(kubeconfigPath)
		base := filepath.Base(kubeconfigPath)
		matches, _ := filepath.Glob(filepath.Join(dir, base+".bak-*"))
		if len(matches) > 0 {
			sort.Strings(matches)
			latest := matches[len(matches)-1]
			fmt.Printf("\nFound backup: %s\n", latest)
			fmt.Printf("To restore: cp %s %s\n", latest, kubeconfigPath)
		}
		os.Exit(0)
	}

	if !noBackup {
		backup(kubeconfigPath)
	}

	sort.Strings(converted)
	fmt.Printf("Reverting %d context(s) to auth-provider oidc:\n", len(converted))
	for _, name := range converted {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println("\nNote: id-token and refresh-token are cleared — you'll need to re-authenticate.")

	writeConfig(config, kubeconfigPath)
}
