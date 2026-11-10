# macOS authentication validation gates

Status: planned, 2026-10-28. **No new validation has been executed.** Existing lab observations in `ui/auth-exp/README.md` do not establish support for daily, session-long or unattended signing.

## Capability contract

A Clavis TTL is an upper bound on permitted reuse. macOS can reject a context sooner. On rejection, invalidate the cached context and reauthenticate or fail; do not retry through weaker hardware controls or storage. Session-long and daily reuse remain experimental until their relevant validation cases pass on supported macOS versions and hardware. Even passing tests cannot promise that macOS will never request earlier authentication.

Hardware-policy changes must be handled according to what the actual key supports. If replacement is needed, create a distinct key only through an explicit user action and explain that existing remote public-key registration will not update itself. No private API dependency should silently become a shipping requirement.

## Test matrix and evidence

Execute using production-equivalent signed/entitled app and daemon builds on the supported OS/hardware matrix, with throwaway keys. Record exact macOS/build, hardware, signing/entitlement setup, key access-control flags, private-record protection, process that owns the context, process that signs, timestamps and result/error codes. Never log private material or externalized authentication blobs.

| Experiment | Required observation |
| --- | --- |
| Fresh context and direct signing | Authentication succeeds and the signature verifies; cancel/failure produces no signature response. |
| Unauthenticated signing | Protected key refuses in both signing process and alternate process. |
| Immediate and delayed reuse | Observe whether the real key accepts the context without prompting; app-side session flags are not evidence of reuse. |
| Session-long / daily window | Test intended duration, early rejection and expiry; record supported behavior rather than inferring duration from a short probe. |
| Screen lock, sleep, explicit revoke, daemon restart | Cached proof is invalidated at each configured event; no stale pending response is released. |
| Lid closed while Mac stays awake | Verify actual event behavior; do not equate lid closure to sleep. Define product policy before testing acceptance. |
| Clock/time-zone change | No accidental lifetime extension. Choose rolling monotonic duration versus calendar semantics explicitly. |
| Context owner versus signing daemon | Verify supported cross-process architecture and actual enforcement. A GUI authentication success alone is insufficient. |
| Concurrent requests and policy edits | Authentication scope is preserved; cancellation/revocation cannot release a stale response. |
| Backend/hardware-policy change | Determine edit versus replacement behavior and preserve key identity truthfully. |
| Proposed unattended key | Test creation, protected-record loading and actual signature verification after restarts without prior interactive proof; record locked-state behavior. |
| Biometry unavailable/enrollment changed | Document failure/fallback according to hardware policy; no silent weakening. |

Reuse scope remains a decision: initially preserve constrained key/principal/process reuse, rather than sharing one cached proof across every application with a grant. Supported policy documentation must specify required invalidation events, maximum duration and early reauthentication behavior.

## Release gates

1. Review authorization contracts, operation classifier and migration semantics.
2. Validate ancestry discovery, signing verification, complete-chain boundaries and revocation ordering on real client chains.
3. Complete the relevant authentication matrix before implementing/promoting the corresponding production policy. Unvalidated daily/unattended modes stay gated.
4. Attach reproducible results and failures to a separate evidence report; retain experimental status for unsupported combinations.

An HTML interaction prototype may proceed using fixtures. Runtime redesign implementation must wait for the relevant contracts and platform constraints to be validated.
