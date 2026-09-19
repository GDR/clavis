# 🔑 Clavis

**Clavis** is a native macOS Swift / SwiftUI application that securely manages Ed25519 private keys in macOS Keychain with Touch ID protection, acts as an SSH Agent daemon (`SSH_AUTH_SOCK`), signs Git commits (`gpg.format = ssh`), interfaces with `sops-nix` via `age-plugin-clavis`, and provides a Menu Bar status item + Key Management Window UI.

---

## ✨ Features

- **Native macOS SwiftUI & AppKit**: Built directly using `CryptoKit`, `Security`, and `LocalAuthentication` frameworks.
- **Unencrypted Public Key Listing**: `ssh-add -l` and `SSH2_AGENTC_REQUEST_IDENTITIES` respond instantly **without triggering Touch ID prompts**.
- **Touch ID Gated Signing**: Biometric prompts trigger strictly when signature challenges are received (`SSH2_AGENTC_SIGN_REQUEST` or `age` decryption).
- **Clamshell & Lid-Closed Fallback**: Supports Apple Watch double-click and macOS User Password fallback (`.deviceOwnerAuthentication`).
- **In-Memory Session Cache & Auto-Lock**: Configurable cache TTL (Off, 5 min, 15 min, 1 hour). Automatically purges keys from memory when the screen locks, workspace sleeps, or upon clicking "Lock Now".
- **`age-plugin-clavis` Integration**: CLI tool that translates Ed25519 keys to X25519 Montgomery keys for `age` and `sops-nix` secret decryption.
- **Flake Integration**: Ready for Nix Flakes on macOS (`nix build`, `nix develop`).

---

## 🚀 Quick Start

### 1. Build and sign using Swift Package Manager
```bash
./build.sh
```

The build script signs every release executable with the hardened runtime and
the required entitlements, then verifies each signature. It uses an available
development certificate or falls back to an ad-hoc signature for local use.

### 2. Build using Nix
```bash
nix build
```

### 3. Usage with SSH & Git

Set your `SSH_AUTH_SOCK` environment variable:
```bash
export SSH_AUTH_SOCK=~/.ssh/clavis.sock
```

List identities (no Touch ID prompt):
```bash
ssh-add -l
```

Authenticate to Git / SSH (triggers Touch ID prompt):
```bash
ssh -T git@github.com
```

Configure Git commit signing:
```bash
git config --global gpg.format ssh
git config --global user.signingkey "ssh-ed25519 ..."
git commit -S -m "signed commit"
```

---

## 🛠 Project Structure

- `Sources/ClavisCore`: Shared engine containing `KeychainManager`, `SSHAgentServer`, `SessionCacheManager`, and `Ed25519AgeConverter`.
- `Sources/Clavis`: Menu Bar status item (`MenuBarExtra`) and SwiftUI Key Management dashboard.
- `Sources/AgePluginClavis`: CLI executable `age-plugin-clavis` adhering to `age-plugin` v1 specification.
- `Tests/ClavisTests`: Unit test suite.
