# 🔑 Clavis

**Clavis** is a native macOS Swift / SwiftUI application that securely manages Secure Enclave ECDSA P-256 private keys with Touch ID protection, acts as an SSH Agent daemon (`SSH_AUTH_SOCK`), signs Git commits (`gpg.format = ssh`), and provides a Menu Bar status item + Key Management Window UI.

Clavis requires a Mac with Secure Enclave support (Apple silicon, an Intel Mac
with a T2 chip, or a 2016–2017 MacBook Pro with Touch Bar and T1). It exits on
unsupported Macs. All signing keys are hardware-backed Secure Enclave ECDSA P-256
keys; Secure Enclave also protects the recovery vault master key.

---

## ✨ Features

- **Native macOS SwiftUI & AppKit**: Built directly using `CryptoKit`, `Security`, and `LocalAuthentication` frameworks.
- **Unencrypted Public Key Listing**: `ssh-add -l` and `SSH2_AGENTC_REQUEST_IDENTITIES` respond instantly **without triggering Touch ID prompts**.
- **Touch ID & User Presence Gated Signing**: Direct SSH authentication requests on the personal socket (`~/.ssh/clavis.sock`), single-shot Git signatures, and agent sessions configured in `ask` mode require fresh user authentication for every signature, with a prompt naming the requesting process (executable path and PID). Prompts are serialized one at a time, and repeated denials trigger a short cooldown. By contrast, **5-minute Git signing sessions** (up to 300 seconds / 200 operations) and **Agent sessions** in `none` or `notify` mode intentionally reuse an evaluated `LAContext` for the duration of the approved lease; session and grant scoping (process-tree binding, operation caps, rate limits, and screen-lock/sleep invalidation) is enforced by Clavis application logic on top of the Secure Enclave's `LAContext` requirement.
- **Configurable Hardware Access Control**: Keys support two hardware `SecAccessControl` policies at creation time:
  - `.userPresence` (`deviceOwnerAuthentication`): accepts Touch ID, Apple Watch double-click, or the macOS account password (including in clamshell / lid-closed mode).
  - `.biometryCurrentSet` (`deviceOwnerAuthenticationWithBiometrics`): strictly requires Touch ID matching the current biometric enrollment set, enforced by the Secure Enclave.
- **Git Signing Sessions**: After repeated commits (rebase, cherry-pick) Clavis can offer a 5-minute / 200-signature session bound to the requesting `ssh-keygen` process, its parent `git` process and process group. This is a convenience, not an isolation boundary: code that runs under the same `git` process (for example repository hooks) can present the same identity while a session is active. Choose "Sign Once" when working in repositories you do not trust.
- **SSH Agent Forwarding Detection**: Clavis inspects OpenSSH's `session-bind@openssh.com` extension on client connections. When a connection reports forwarding (`ssh -A`), the personal socket (`~/.ssh/clavis.sock`) displays a forwarded-agent warning in the authentication prompt (note that the local `ssh` client is the peer process relaying the remote request), while the dedicated agent socket (`~/.ssh/clavis-agent.sock`) refuses forwarded signing requests outright. Clients that do not send `session-bind@openssh.com` cannot be verified as non-forwarded via protocol extension.
- **Logs**: `~/.config/clavis/clavis.log` (3 x 1 MiB) holds general activity. Security-relevant events are recorded in the History window. Per-request protocol chatter (`SSH_AGENT_REQ`, identity listings, key listings) is off by default; set `CLAVIS_VERBOSE_LOG=1` for troubleshooting. Logs contain key labels and requesting executable paths and are `0600` in a `0700` directory.
- **Flake Integration**: Ready for Nix Flakes on macOS (`nix build`, `nix develop`).

---

## 🚀 Quick Start

### 1. Build and sign using Just / Swift Package Manager
```bash
just
# or ./build.sh (or make)
```

The `justfile` (invoked via `just`) assembles a complete `Clavis.app`, including the
SwiftPM localization bundle (`Clavis_ClavisCore.bundle`), nested `Clavis Agent.app`, and
command-line helpers, then re-signs every bundle and standalone executable inside-out with
the hardened runtime. It fails closed when no development certificate is available and
resolves an unambiguous SHA-1 identity, preferring `CLAVIS_TEAM_ID` (default `4G6X3KNZUS`)
when multiple matching certificates exist. A specific certificate (CN prefix or SHA-1) can
be selected with `CLAVIS_SIGN_IDENTITY`; run `just signing-status` to inspect installed
certificates and the active selection.

For local development and relaunching:
```bash
just run debug
```

P-256 private keys are generated inside and never leave the Secure Enclave. The opaque Secure Enclave key reference (`dataRepresentation`) is stored in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and backed up in the encrypted recovery vault (`~/.config/clavis/vault`), whose master key is itself a Secure Enclave key. Hardware access control (`.userPresence` or `.biometryCurrentSet`) is enforced by the Secure Enclave itself; key purpose separation (`general`, `gitSigningOnly`, `agent`), rate limits, and prompt attribution are enforced by Clavis, and key deletion strictly requires user authentication before modifying stores.

- **Data Protection Keychain (provisioned builds)**: When matching macOS provisioning profiles for `com.clavis.app` and `com.clavis.agent` (granting `<TEAM_ID>.com.clavis.shared` or `<TEAM_ID>.*`) are available—passed via `CLAVIS_APP_PROVISION_PROFILE` and `CLAVIS_AGENT_PROVISION_PROFILE` or auto-discovered in `packaging/macos/`, `~/Library/Developer/Xcode/UserData/Provisioning Profiles`, or `~/Library/MobileDevice/Provisioning Profiles`—`just sign` embeds `Contents/embedded.provisionprofile` and signs `Clavis.app` and `Clavis Agent.app` with `keychain-access-groups` = `["<TEAM_ID>.com.clavis.shared"]` (pass `CLAVIS_REQUIRE_PROVISIONING=1` to fail closed if missing). At runtime `KeychainScope.processDefault` inspects the process entitlements and stores Clavis items in the macOS Data Protection Keychain (`kSecUseDataProtectionKeychain` + `<TEAM_ID>.com.clavis.shared`), sharing them between `Clavis.app` and `Clavis Agent.app` without legacy `SecAccess` ACL prompts. Legacy Login Keychain private key items are migrated once on authenticated read and removed from the legacy partition after the Data Protection copy succeeds.
- **Login Keychain fallback (unprovisioned builds)**: When the provisioning profile pair is absent, `just sign` omits provisioning entitlements (`Entitlements.plist`) and signs `Apple Development` / `Developer ID Application` binaries with a Team-OU designated requirement (`identifier "Clavis"` anchored to Apple with `certificate leaf[subject.OU] = "<TEAM_ID>"`). At runtime `KeychainScope.processDefault` automatically falls back to the Login Keychain, where items rely on the shared `Clavis` identifier and Team-OU designated requirement. Independently signed or plain `swift run` executables are not equivalent Keychain clients.
- **Socket-only `clavis-cli`**: Standalone binaries (`Clavis`, `clavis-agent`, and `Contents/Helpers/clavis-cli`) are always signed without provisioning entitlements. `clavis-cli` does not access Keychain or the recovery vault directly: all key and vault commands (`list`, `export-pub`, `generate`, `kind`, `delete`, `lock`, `vault repair`, `run`) are routed over the `LOCAL_PEERTOKEN`-authenticated personal daemon control socket (`~/.ssh/clavis.sock`), auto-starting `Clavis Agent.app` if needed. Both client and daemon mutually verify peer code identity (`ClavisCodeTrust`, requiring the shared `Clavis` identifier and Team ID in release builds), validate peer process continuity, and serialize mutating/interactive requests through `SigningPromptGate`; the dedicated agent socket (`~/.ssh/clavis-agent.sock`) rejects all control requests.

For an explicitly local, non-distributable build without a certificate, opt in
to ad-hoc signing with `CLAVIS_ALLOW_ADHOC_SIGNING=1 just`. Helper launch is
pinned to the signing team of the running app, so an ad-hoc **release**
build has no team to pin and will not auto-launch the bundled agent; use a
debug build (`just run debug`) or start `clavis-agent --daemon` yourself. The Nix package
downloads the pinned GitHub release archive and preserves its existing code
signatures; it does not rebuild or re-sign the binaries.

`just package` also creates `clavis-macos-arm64.dmg` for graphical installation.
Open the disk image and drag `Clavis.app` to the Applications shortcut. The DMG
and Nix archive are published together with SHA-256 checksum files.

#### Release signing and notarization

Releases are built by `.github/workflows/release.yml`. While local builds default to an
`Apple Development` certificate (which is not distributable: Gatekeeper cannot verify it and
the signature has no secure timestamp), release CI builds strictly require a `Developer ID Application`
certificate, an explicit Team ID, and Apple notarization:

- Configure the `release` GitHub environment with `CLAVIS_SIGN_IDENTITY=Developer ID Application`,
  `CLAVIS_EXPECTED_TEAM_ID=4G6X3KNZUS` (your 10-character Apple Developer Team ID), and
  `CLAVIS_NOTARIZE=1`, along with the secrets `MACOS_CERTIFICATE_BASE64`, `MACOS_CERTIFICATE_PWD`,
  `NOTARY_KEY_BASE64` (App Store Connect API key `.p8`, base64), `NOTARY_KEY_ID`, and
  `NOTARY_ISSUER_ID`. To enable Data Protection Keychain in release artifacts, also provide the
  atomic provisioning profile pair `MACOS_APP_PROVISION_PROFILE_BASE64` (`com.clavis.app`) and
  `MACOS_AGENT_PROVISION_PROFILE_BASE64` (`com.clavis.agent`). You can inspect or populate all of
  these in one step with:
  ```bash
  MACOS_CERTIFICATE_PWD='<p12-password>' just ci-signing-setup \
    <DeveloperID.p12> <AuthKey.p8> <KEY_ID> <ISSUER_ID> \
    [owner/repo] [<Clavis.provisionprofile> <ClavisAgent.provisionprofile>]
  ```
- When both `MACOS_APP_PROVISION_PROFILE_BASE64` and `MACOS_AGENT_PROVISION_PROFILE_BASE64` are set,
  CI stages them, sets `CLAVIS_REQUIRE_PROVISIONING=1`, and embeds them into `Clavis.app` and
  `Clavis Agent.app` (CI fails closed if only one of the pair is set; if neither is set, CI
  continues with an unprovisioned release build).
- CI imports Apple's WWDR G3/G6 and `DeveloperIDG2CA` intermediate certificates into an ephemeral
  keychain, verifies the `Developer ID Application` identity matches `CLAVIS_EXPECTED_TEAM_ID`,
  and signs every binary, resource bundle, helper app, `Clavis.app`, and `.dmg` with secure
  Apple timestamps (`CLAVIS_TIMESTAMP=secure`).
- `just package` with `CLAVIS_NOTARIZE=1` notarizes and staples both `clavis-macos-arm64.dmg` and
  `Clavis.app`, validates them with `stapler` and `spctl`, and also submits the standalone
  `Clavis`, `clavis-agent`, and `clavis-cli` binaries for notarization before packing
  `clavis-macos-arm64.tar.gz`. Locally, use
  `CLAVIS_NOTARIZE=1 CLAVIS_NOTARY_PROFILE=<notarytool keychain profile> just package`.
- Each release publishes a GitHub build-provenance attestation for the DMG and archive
  (`gh attestation verify clavis-macos-arm64.dmg --repo <owner>/clavis`). Set the repository
  variable `CLAVIS_ATTEST=0` to opt out (for example on a plan without attestations).

Changing the signing certificate changes the Keychain designated requirement of the app. Records
written by an `Apple Development` build are migrated by the existing authenticated-copy flow, but
test the upgrade with a throwaway key on a spare account before shipping the first Developer ID
build, and keep the recovery vault until it has been verified.

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
git config --global user.signingkey "ecdsa-sha2-nistp256 ..."
git commit -S -m "signed commit"
```

---

## 🛠 Project Structure

- `Sources/ClavisCore`: Shared engine containing `KeychainManager`, `KeychainScope`, `EncryptedVaultStore`, `CLIService`, and `SSHAgentServer`.
- `Sources/Clavis`: Menu Bar status item (`MenuBarExtra`) and SwiftUI Key Management dashboard.
- `Sources/ClavisAgent`: Background SSH agent daemon (`Clavis Agent.app`).
- `Sources/ClavisCLI`: Socket-only `clavis-cli` executable delegating key and vault operations over `~/.ssh/clavis.sock`.
- `Tests/ClavisCoreTests`, `Tests/ClavisAppTests`, `Tests/ClavisTestSupport`: Swift Testing unit and integration suites.
