# 🔑 Clavis

**Clavis** is a native macOS Swift / SwiftUI application that securely manages Ed25519 private keys in macOS Keychain with Touch ID protection, acts as an SSH Agent daemon (`SSH_AUTH_SOCK`), signs Git commits (`gpg.format = ssh`), interfaces with `sops-nix` via `age-plugin-clavis`, and provides a Menu Bar status item + Key Management Window UI.

Clavis requires a Mac with Secure Enclave support (Apple silicon, an Intel Mac
with a T2 chip, or a 2016–2017 MacBook Pro with Touch Bar and T1). It exits on
unsupported Macs. Ed25519 keys remain software keys in Keychain; Secure Enclave
protects the recovery vault master key and can directly hold P-256 signing keys.

---

## ✨ Features

- **Native macOS SwiftUI & AppKit**: Built directly using `CryptoKit`, `Security`, and `LocalAuthentication` frameworks.
- **Unencrypted Public Key Listing**: `ssh-add -l` and `SSH2_AGENTC_REQUEST_IDENTITIES` respond instantly **without triggering Touch ID prompts**.
- **Touch ID Gated Signing**: Every SSH-agent signature request requires fresh user authentication, and the prompt names the requesting process (executable name and PID). Prompts are shown one at a time, and repeated denials trigger a short cooldown. Note that with `ssh -A` the requesting process is the local `ssh` client relaying a remote request. Age decryption can reuse the configured session cache.
- **Clamshell & Lid-Closed Fallback**: Supports Apple Watch double-click and macOS User Password fallback (`.deviceOwnerAuthentication`).
- **In-Memory Session Cache & Auto-Lock**: Configurable cache TTL (Off, 5 min, 15 min, 1 hour) for scoped application and age operations. SSH-agent signing deliberately bypasses this cache. Cached material is purged when the screen locks, workspace sleeps, or upon clicking "Lock Now".
- **Git Signing Sessions**: After repeated commits (rebase, cherry-pick) Clavis can offer a 5-minute / 200-signature session bound to the requesting `ssh-keygen` process, its parent `git` process and process group. This is a convenience, not an isolation boundary: code that runs under the same `git` process (for example repository hooks) can present the same identity while a session is active. Choose "Sign Once" when working in repositories you do not trust.
- **`age-plugin-clavis` Integration**: CLI tool that translates Ed25519 keys to X25519 Montgomery keys for `age` and `sops-nix` secret decryption.
- **Logs**: `~/.config/clavis/clavis.log` (3 x 1 MiB) holds general activity; security-relevant events (alerts, signing, locks, deletions, Git sessions) are also written to `clavis.security.log` (10 x 1 MiB) so routine activity cannot rotate them away. Per-request protocol chatter (`SSH_AGENT_REQ`, identity listings, key listings) is off by default; set `CLAVIS_VERBOSE_LOG=1` for troubleshooting. Logs contain key labels and requesting executable paths and are `0600` in a `0700` directory.
- **Flake Integration**: Ready for Nix Flakes on macOS (`nix build`, `nix develop`).

---

## 🚀 Quick Start

### 1. Build and sign using Just / Swift Package Manager
```bash
just
# or ./build.sh (or make)
```

The `justfile` (invoked via `just`, `./build.sh`, or `make`) assembles a complete `Clavis.app`, including the
SwiftPM localization bundle and command-line helpers, then signs the standalone
executables, nested helpers, and final application bundle with the hardened
runtime. It fails closed when no development certificate is available. A
specific certificate can be selected with `CLAVIS_SIGN_IDENTITY`.

For local development and relaunching:
```bash
just run debug
# or ./build.sh run debug
```

Private records use the Login Keychain with `SecAccessControl` authentication.
The recovery vault never creates or opens a file-backed software master key in
normal builds. If an older `master.key` uses that format, Clavis preserves the
vault files and refuses new key creation or import until the vault is replaced
with a Secure Enclave backed vault. Automatic migration is not yet provided.
Existing Keychain records remain available for signing. Do not delete the old
vault files as a migration shortcut: they may be the only recovery copy of a key.
The build script gives every certificate-signed Clavis executable the original
GUI Code Signing Identifier (`Clavis`), so existing GUI-created records and all
shipped clients have the same designated requirement without restricted
entitlements or a provisioning profile. Independently signed or plain
`swift run` executables are not equivalent Keychain clients. Records created by
older signatures are copied once, after an authenticated read, to a versioned
service owned by the current signed client. The old record is retained as a
recovery fallback and is no longer consulted after the copy succeeds.

For an explicitly local, non-distributable build without a certificate, opt in
to ad-hoc signing with `CLAVIS_ALLOW_ADHOC_SIGNING=1 just`. The Nix package
downloads the pinned GitHub release archive and preserves its existing code
signatures; it does not rebuild or re-sign the binaries.

`just package` (or `make package`) also creates `clavis-macos-arm64.dmg` for graphical installation.
Open the disk image and drag `Clavis.app` to the Applications shortcut. The DMG
and Nix archive are published together with SHA-256 checksum files.

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
