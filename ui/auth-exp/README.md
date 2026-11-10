# Clavis auth lab

Three standalone macOS prototypes comparing authentication UX **and** whether the Secure Enclave
key actually enforces authorization. All share `Shared/` (SEP P-256 key, challenge, log, test harness).

| App | Run | Mechanism |
| --- | --- | --- |
| `AuthSystemPrompt` | `just auth-exp system` | `LAContext` + `.userPresence` system dialog (baseline) |
| `AuthEmbedded` | `just auth-exp embedded` | `LocalAuthenticationView` bound to an explicit `LAContext` (`evaluateAccessControl` / `evaluatePolicy`) |
| `AuthApplicationPassword` | `just auth-exp password` | `.applicationPassword` on the SEP key |

`just auth-exp-build [system|embedded|password|all]` only builds ad-hoc-signed bundles into `.build/apps/`.

## Harness (same in every app)

1. Generate SEP P-256 key (the `toid` token blob is persisted to `~/Library/Application Support/ClavisAuthLab/<profile>-sep-key.json`; it holds no private scalar, so keys survive restarts).
2. Show a signing request. 3. Authenticate via the app's mechanism. 4. `SecKeyCreateSignature`, then verify with the public key.
5. Scenario buttons: sign twice, reuse last context (`interactionNotAllowed`, so success = real reuse), 3 concurrent requests, agent process with its own auth, agent process with handed-off `externalizedContext` (GUI → agent, as in Clavis).
6. **Bypass buttons** (success criterion): signing without authentication, in-process and from a separate process, must FAIL (`SECURITY_PASS` in the log).

Manual: Touch ID off/unavailable, wrong password, cancel, restart app, lock/unlock Mac (lock events are logged). "Copy report" puts a Markdown table of the run on the clipboard.

## Notes from the pre-build probes (macOS 27 SDK, unprovisioned binary)

- `kSecAttrIsPermanent: true` for SEP keys and `LARightStore` fail with `-34018` without provisioning; keys here are non-permanent and referenced via `toid`.
- Unauthenticated signing against a `.userPresence`/`.applicationPassword` key fails inside SEP (`-1004` / AKS error); a wrong application password fails with `AKSError`; correct one signs.
- `LAContext.externalizedContext` (private selector) let a second context sign — validate in the real two-process test before relying on it.
- `LocalAuthenticationView` explicit-context init supports biometrics/companion policies; `.deviceOwnerAuthentication` only works there if biometry/Watch is available (no password UI).
