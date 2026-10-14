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

P-256 private keys are generated inside and never leave the Secure Enclave. The opaque Secure Enclave key reference (`dataRepresentation`) is stored in a Keychain record protected by `.userPresence` `SecAccessControl` (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and backed up in the encrypted recovery vault (`~/.config/clavis/vault`), whose master key is itself a Secure Enclave key. Secure Enclave key blobs are hardware-bound to the Mac and protected by their hardware `SecAccessControl` policy (`.userPresence` or `.biometryCurrentSet`), while key purpose separation (`general`, `gitSigningOnly`, `agent`), rate limits, and prompt attribution are enforced by Clavis. Key deletion strictly requires user authentication before modifying stores.
Release builds signed with Developer ID or Apple Development certificates include the Data Protection Keychain access group entitlement (`keychain-access-groups` matching `$(AppIdentifierPrefix)com.clavis.app`) for unified access across the app, agent daemon, and CLI helpers. Unprovisioned local development builds (`CLAVIS_ALLOW_ADHOC_SIGNING=1`) sign without restricted entitlements so `just build` and `swift test` continue functioning without requiring an Apple Developer provisioning profile.
The build script gives every certificate-signed Clavis executable the original
GUI Code Signing Identifier (`Clavis`), so existing GUI-created records and all
shipped clients have the same designated requirement. Independently signed or plain
`swift run` executables are not equivalent Keychain clients. Records created by
older signatures are copied once, after an authenticated read, to a versioned
service owned by the current signed client. The old record is retained as a
recovery fallback and is no longer consulted after the copy succeeds.

For an explicitly local, non-distributable build without a certificate, opt in
to ad-hoc signing with `CLAVIS_ALLOW_ADHOC_SIGNING=1 just`. Helper launch is
pinned to the signing team of the running app, so an ad-hoc **release**
build has no team to pin and will not auto-launch the bundled agent; use a
debug build (`just run debug`) or start `clavis-agent --daemon` yourself. The Nix package
downloads the pinned GitHub release archive and preserves its existing code
signatures; it does not rebuild or re-sign the binaries.

`just package` (or `make package`) also creates `clavis-macos-arm64.dmg` for graphical installation.
Open the disk image and drag `Clavis.app` to the Applications shortcut. The DMG
and Nix archive are published together with SHA-256 checksum files.

#### Release signing and notarization

Releases are built by `.github/workflows/release.yml`. While local builds default to an
`Apple Development` certificate (which is not distributable: Gatekeeper cannot verify it and
the signature has no secure timestamp), release CI builds strictly require a `Developer ID Application`
certificate and fail if one is not configured. For release builds:

- Set the repository variable `CLAVIS_SIGN_IDENTITY` to `Developer ID Application` (and
  `CLAVIS_EXPECTED_TEAM_ID` to your 10-character team ID; the release workflow requires both and fails
  if the identity does not start with `Developer ID Application` or if the team ID is missing).
  Developer ID builds automatically use secure timestamps (`CLAVIS_TIMESTAMP=auto`).
- Until a Developer ID certificate is available, set the variable `CLAVIS_ALLOW_NON_DEVID_RELEASE=1`
  to explicitly publish a release signed with `Apple Development` (`CLAVIS_SIGN_IDENTITY` empty or
  starting with `Apple Development`; `CLAVIS_EXPECTED_TEAM_ID` is still required). Such releases are
  not notarized, have no secure timestamp, are rejected by Gatekeeper, and are marked with a warning
  in the workflow log and release notes. Notarization cannot be combined with this flag.
- Set `CLAVIS_NOTARIZE=1` (repository variable) with the secrets `NOTARY_KEY_BASE64`,
  `NOTARY_KEY_ID` and `NOTARY_ISSUER_ID` to submit the DMG to Apple, staple the ticket and
  validate it with `spctl` before the checksum is computed. Locally, use
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

- `Sources/ClavisCore`: Shared engine containing `KeychainManager` and `SSHAgentServer`.
- `Sources/Clavis`: Menu Bar status item (`MenuBarExtra`) and SwiftUI Key Management dashboard.
- `Tests/ClavisTests`: Unit test suite.
