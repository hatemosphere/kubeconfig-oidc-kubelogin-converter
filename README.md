# kubeconfig-oidc-kubelogin-converter

Converts kubeconfig OIDC `auth-provider` entries to [kubelogin](https://github.com/int128/kubelogin) `exec` plugin format, and back.

During conversion, existing `id-token` and `refresh-token` are injected into kubelogin's token cache so the first `kubectl` call after conversion works silently — no interactive login required. OIDC scopes are automatically detected from the existing token claims. Tokens are stored in the OS keychain by default (macOS Keychain, Windows Credential Manager, Linux secret service) for security.

Reverse conversion (`-reverse`) reads tokens back from kubelogin's cache into the kubeconfig, making the round-trip lossless.

## Why

kubectl's built-in OIDC auth-provider (`auth-provider: name: oidc` in kubeconfig) has a token refresh implementation that is broken in practice with many providers — it strips scopes from refresh requests, has no retries or timeouts, and silently fails, causing `kubectl` commands to stall or get 401 errors. With Dex setups, token refresh effectively never works, requiring users to re-authenticate through the web UI whenever the 24h id-token expires.

The in-tree auth-provider plugins were deprecated in Kubernetes v1.22 in favor of exec credential plugins ([KEP-541](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/541-external-credential-providers)). The vendor-specific plugins (Azure, GCP) were removed in v1.26. The generic OIDC auth-provider still ships in v1.35 but is considered legacy and receives no fixes.

[kubelogin](https://github.com/int128/kubelogin) is the recommended replacement — it handles token refresh with retries and backoff, supports multiple login flows (browser, device code, keyboard), and manages its own token cache.

This tool automates the migration for any OIDC provider setup, converting all matching kubeconfig `auth-provider: oidc` entries in one shot and preserving existing tokens to avoid unnecessary re-authentication.

## Usage

```bash
# Convert (default: device-code grant, OS keychain storage)
./kubeconfig-oidc-kubelogin-converter

# Use filesystem storage instead of OS keychain
./kubeconfig-oidc-kubelogin-converter -token-cache-storage=disk

# Use a specific grant type
./kubeconfig-oidc-kubelogin-converter -grant-type=authcode

# Revert back to auth-provider oidc
./kubeconfig-oidc-kubelogin-converter -reverse

# Skip backup creation
./kubeconfig-oidc-kubelogin-converter -no-backup
```

A timestamped backup of the kubeconfig is created before any modification (unless `-no-backup` is set).

### Flags

| Flag | Default | Description |
|---|---|---|
| `-grant-type` | `device-code` | OAuth2 grant type for kubelogin (`authcode`, `authcode-keyboard`, `device-code`, `password`, `client-credentials`) |
| `-token-cache-storage` | `keyring` | Token cache storage (`keyring` for OS keychain, `disk` for `~/.kube/cache/oidc-login/`) |
| `-reverse` | `false` | Convert kubelogin exec entries back to auth-provider oidc |
| `-no-backup` | `false` | Skip creating a backup of the kubeconfig |

## Prerequisites

```bash
kubectl krew install oidc-login
```

## Token storage

By default, tokens are stored in the OS keychain (`-token-cache-storage=keyring`):

- **macOS** — Keychain (encrypted at rest, locked with screen lock)
- **Windows** — Credential Manager
- **Linux** — Secret Service (GNOME Keyring / KWallet)

This avoids plaintext token files on disk. Use `-token-cache-storage=disk` to fall back to filesystem storage at `~/.kube/cache/oidc-login/` (or `$KUBECACHEDIR/oidc-login/`).

## Token lifecycle

After conversion, kubelogin manages tokens independently:

1. **Cached token valid** — returned directly, no network call.
2. **Cached token expired, refresh token valid** — silently refreshed and saved (including rotated refresh token if the provider issues one).
3. **Refresh token expired/invalid** — falls back to the configured grant type for interactive re-authentication.

## OIDC provider configuration

kubelogin is OIDC-only. Each grant type has different requirements on the provider side.

### `device-code` (default)

The user gets a one-time code and a verification URL to visit on any device. Works in headless/SSH environments and doesn't require localhost redirect URIs.

**Provider requirements:**
- Must support the [Device Authorization Grant (RFC 8628)](https://datatracker.ietf.org/doc/html/rfc8628)

**Dex configuration:**

Enable device code flow and add `/device/callback` to redirect URIs (Dex uses this path internally during the authorization flow):
```yaml
oauth2:
  responseTypes: ["code", "token", "id_token"]
  skipApprovalScreen: true
  deviceRequests:
    enabled: true

staticClients:
  - id: my-client
    secret: <secret>
    redirectURIs:
      - https://login.example.com/callback   # existing web UI callback
      - /device/callback                      # required for device code flow
```

> **Note:** Dex requires `client_secret` during device code flow, which is non-compliant with RFC 8628 for public clients ([dexidp/dex#3983](https://github.com/dexidp/dex/issues/3983)). This is fine since kubelogin always passes `client-secret`.

### `authcode`

Opens a browser for the standard Authorization Code flow. kubelogin starts a local HTTP server to receive the callback.

**Provider requirements:**
- Redirect URIs: `http://localhost:8000/callback` and `http://localhost:18000/callback` (fallback port)
- Custom addresses via `--listen-address` — each must be registered

### `authcode-keyboard`

Prints the URL to the terminal. The user opens a browser manually, authenticates, and pastes the authorization code back.

**Provider requirements:**
- Redirect URI: `http://localhost` (default, configurable via `--oidc-redirect-url`)

### `password`

Direct username/password exchange (ROPC). No browser involved.

**Provider requirements:**
- The connector must support password grants

### `client-credentials`

Service-to-service flow, no user interaction. Typically not useful for interactive kubectl usage.
