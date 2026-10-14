# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/GDR/clavis/security/advisories/new)
instead of opening a public issue. Include the Clavis version, macOS version, and the
smallest reproduction you can. You can expect an acknowledgement, and a fix or mitigation plan
for confirmed issues, as soon as practical; please allow time for a fix before disclosing.

## Supported versions

Only the latest release receives security fixes.

## What Clavis protects

- Private keys are generated inside and never leave the Secure Enclave:
  - Hardware ECDSA P-256 keys (`.secureEnclave`) are generated inside the Apple Secure Enclave with one of two hardware `SecAccessControl` policies (`[.privateKeyUsage, .userPresence]` or `[.privateKeyUsage, .biometryCurrentSet]`).
    - `.userPresence` (`deviceOwnerAuthentication`) accepts Touch ID, Apple Watch, or the macOS account password.
    - `.biometryCurrentSet` (`deviceOwnerAuthenticationWithBiometrics`) strictly requires Touch ID matching the current biometric enrollment set, enforced by the Secure Enclave.
  - Only the opaque Secure Enclave key reference (`dataRepresentation`) is stored in the local Keychain—protected by `.userPresence` `SecAccessControl` (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`)—and backed up in the encrypted recovery vault (`~/.config/clavis/vault`).
  - Secure Enclave key blobs are hardware-bound to the Mac and protected by their `SecAccessControl` policy, while key purpose separation (`general`, `gitSigningOnly`, `agent`), rate limits, and prompt attribution are enforced by Clavis application logic.
  - Key generation fails closed if Keychain access control protection is unavailable (`errSecMissingEntitlement` / `-34018`), refusing to persist keys without proper entitlements.
  - The recovery vault master key requires hardware Secure Enclave support; software master keys are never created or loaded.
  - Key deletion strictly requires user-presence authentication before private or public key records are removed.
- Authentication per signature vs. approved sessions:
  - Direct SSH authentication requests on the personal socket (`~/.ssh/clavis.sock`), single-shot Git signatures, and agent sessions configured in `ask` mode require fresh user authentication for every signature and display the requesting process attribution.
  - **5-minute Git signing sessions** (up to 300 seconds / 200 operations) and **Agent sessions** in `none` or `notify` mode intentionally reuse an evaluated `LAContext` for the duration of the approved lease. Session and grant scoping (process-tree binding, operation caps, rate limits, and screen-lock/sleep invalidation) is enforced by Clavis application logic on top of the Secure Enclave's `LAContext` requirement.
  - Git signing sessions are an opt-in convenience bound to the requesting process identity (`ssh-keygen`, its parent `git` process, and process group). They are not an isolation boundary against code running under the same `git` process, such as repository hooks.
- SSH agent forwarding detection (`session-bind@openssh.com`):
  - Forwarding detection relies on OpenSSH's `session-bind@openssh.com` protocol extension.
  - When a client connection reports forwarding (`ssh -A`), the personal socket (`~/.ssh/clavis.sock`) surfaces a forwarded-agent warning in the authentication prompt, whereas the dedicated agent socket (`~/.ssh/clavis-agent.sock`) refuses forwarded signing requests outright.

## Known Limitations

- `com.clavis.openKeyManager`: The Clavis CLI posts an unauthenticated Darwin distributed notification (`com.clavis.openKeyManager`) to request that the running GUI application display the key management window.
- Because macOS distributed notifications cannot authenticate the sender, any local process running under the same user account can post this notification to trigger the window.
- Impact: This is a UI nuisance only. The notification carries no payload, cannot request signatures, and cannot extract or modify private keys or settings.

## Out of scope

- A fully compromised user account or an attacker who can already run code as you, change your
  shell or Git configuration, or approve authentication prompts on your behalf.
- Forwarded personal agents (`ssh -A` on `~/.ssh/clavis.sock`) and SSH clients that do not send `session-bind@openssh.com`: a remote host you forward your personal agent to can request signatures, which you must approve (and clients omitting `session-bind@openssh.com` cannot be distinguished from local requests by protocol extension). Prefer `ProxyJump` over agent forwarding for untrusted hosts.
- Ad-hoc or development-signed builds. Only official release builds are intended for
  distribution; builds you sign yourself are your responsibility.

## Verifying a download

Each release publishes SHA-256 checksum files. Releases that include a GitHub build-provenance
attestation can be checked with
`gh attestation verify clavis-macos-arm64.dmg --repo GDR/clavis`.
