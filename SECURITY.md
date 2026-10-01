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

- Private keys are stored in the Login Keychain or Secure Enclave and are not written to disk in
  plaintext.
- Every SSH-agent signature asks for fresh user authentication (Touch ID / Apple Watch /
  password) and shows the requesting program.
- Git signing sessions (5 minutes / 200 signatures) are an opt-in convenience bound to the
  requesting process identity. They are not an isolation boundary against code running under the
  same `git` process, such as repository hooks.

## Out of scope

- A fully compromised user account or an attacker who can already run code as you, change your
  shell or Git configuration, or approve authentication prompts on your behalf.
- Forwarded agents (`ssh -A`): a remote host you forward to can request signatures, which you
  must approve. Prefer `ProxyJump` over agent forwarding for untrusted hosts.
- Ad-hoc or development-signed builds. Only official release builds are intended for
  distribution; builds you sign yourself are your responsibility.

## Verifying a download

Each release publishes SHA-256 checksum files. Releases that include a GitHub build-provenance
attestation can be checked with
`gh attestation verify clavis-macos-arm64.dmg --repo GDR/clavis`.
