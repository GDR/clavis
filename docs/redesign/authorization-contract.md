# Authorization contract

Status: normative draft for review, 2026-10-28. Not implemented or validated. Operation-level grants are recommended pending a product decision.

## Data and terminology

```text
Key { id, purpose, authenticationPolicy, allowedOperations }
Application { id, verifiedSigningRequirement, name }
ApplicationProfile { id, name, applicationIds[] }
AccessGrant { id, principal: applicationId | profileId, keyId, allowedOperations }
Restriction { id, applicationId, keyId: specific | all, deniedOperations }
Request { id, peerInstance, keyId, operation, evidence, policyRevision }
```

`AccessGrant` is allow-only. `Restriction` models explicit deny, including a global application block as all keys/all supported operations. No implicit deny record is created merely because an application lacks a grant. Keys have no separate owner entity. Purpose describes intended use; key operations are the enforceable ceiling. Any purpose/operation combination the product supports must have an explicit validation rule.

Operations initially distinguish `sshAuthentication` and `gitSigning`. No “all future operations” wildcard is stored in grants. Empty grants are invalid; absent or unrecognized operation fields require migration/review, never unrestricted access. Disabling a key operation does not silently rewrite grants: the UI shows their configured and effective operations separately. Re-enabling it can restore previously granted access and therefore requires explicit impact review.

An application is a **principal** and a live process is a **process instance**. A key is a standalone cryptographic object. These identifiers are not interchangeable. Removing owner entities does not remove verification of application/process code identity.

## AC-AUTHZ-01: evidence contract

1. Obtain peer identity from the local connection using a supported, validated OS mechanism; never trust a client-supplied PID/path/environment label.
2. Capture the peer instance and ancestry toward a defined OS session/root boundary. Record process-instance identity, parent linkage and running-code signing evidence. Reused PIDs must not match old instances. The exact OS APIs and instance representation are an implementation-validation gate.
3. Require verified code-signing evidence for rule matching and for selecting a principal. A process name, executable path, display icon, Team ID alone, or static file hash is insufficient. Verify a configured signing requirement against the running code; define update compatibility through that requirement.
4. Traverse the entire required chain before deciding. Do not stop at the first allow. A loop, missing process/link, changed instance, failed verification, cross-session ambiguity, or traversal limit produces `uncertainAncestry`. A traversal limit must never count as a successfully reached boundary.
5. A root/session boundary is an explicit verified stopping condition, not an arbitrary application whose grant happens to match. OS-boundary and transparent-helper recognition must be pinned rules; their implementation needs validation before runtime work.
6. A chain containing an unverifiable process is uncertain under this conservative draft. This can reject unsigned CLI tools or scripts; it must be measured on actual supported launch chains. Do not silently make such nodes transparent to improve compatibility.

Uncertain ancestry never permits persistent authorization or cached authentication reuse. This draft denies the request. An authenticated, nonpersistent one-shot exception remains an open decision and is not enabled by this contract or prototype.

## AC-AUTHZ-02: principal selection and precedence

Take one consistent policy snapshot containing keys, applications, memberships, grants and restrictions. For one request, let `C` be its complete verified ancestry, ordered direct peer to root.

1. Paused requests, unavailable/corrupt policy, unknown key or unsupported/malformed operation deny without an approval dialog that could bypass the failure.
2. If evidence is uncertain, deny as above.
3. Evaluate **every applicable restriction** against every verified process in `C`. A restriction applies only when identity, key scope and operation scope match. If any applies, deny. No allow, first-use action, existing authentication context or descendant process can override it.
4. Select the nearest eligible application principal in `C`, starting at the peer. Eligible means a verified application explicitly registered for access, or a verified first-use candidate presented to the user. Recognized OS transports are not automatically eligible; signature validity alone never makes an arbitrary ancestor a trusted principal. Candidate discovery must be validated with real app and CLI launch chains before implementation.
5. Do not fall through to a more distant allowed application if the selected nearer principal lacks access. Do not combine allows belonging to different ancestor principals. For example, a configured Codex principal inside Terminal remains Codex even if Terminal has broader grants.
6. Compute operations for that principal using the formula below. If the requested operation is disabled on the key, deny. If it is enabled but not granted, return `approvalRequired` for the verified candidate. A lack of grant is not an explicit deny.
7. If granted, evaluate the key's authentication policy. Permission and authentication must both pass before signing.

For selected principal `p` and key `k`:

```text
G(p,k) = direct grants to p for k
         ∪ grants to each profile containing p for k
AllowOps(p,k) = union(g.allowedOperations for g in G(p,k))
DenyOps(C,k) = union(r.deniedOperations for restrictions matching any node in C and k)
EffectiveOps(p,k,C) = k.allowedOperations ∩ AllowOps(p,k) − DenyOps(C,k)
```

Explicit key/operation restrictions anywhere in the chain apply even if their process is not selected as principal. Union applies to grants for **one principal**, not to all ancestors. Grant revocation is a removal from this union; removing one grant need not remove rights supplied by another.

## AC-AUTHZ-03: per-request and revocation contract

Each signing request repeats evidence collection, restriction checks, principal selection and operation authorization. Opening a connection or listing identities does not authorize later signatures. Enumeration rules require their own review; a key being listed is never a permission to sign.

Bind pending approval and authentication reuse to the key, principal/process scope, operation and captured revisions. Recheck process evidence, key generation, policy revision, pause/block state and context validity before signature release. All grant/profile/restriction/key-policy changes increment the relevant revision and invalidate stale pending approvals. A remove-and-readd cycle never revives old approvals.

Implementation must define one serialized decision point between the final policy check and committing the signature response. Revocation ordered before that point prevents release; revocation ordered after a committed response cannot recall it. A check followed by an uncoordinated write is insufficient to claim race-safe revocation. This is a required concurrency validation case.

Audit the selected principal, evidence outcome, key, operation, access source/revision and result. Avoid raw signed payloads in logs. Signing failure, cancellation, timeout and policy invalidation are not success.

## AC-SCOPE-01: first-use confirmation

For an individual-key approval, show the selected application, child-process scope, exact key and selected operations before confirmation. Default to the requested operation only. Persistent changes require the authenticated control path. Disabled key operations cannot be enabled by granting application permission.

For profile membership, show **every key and effective operation supplied by that profile**, including keys outside the initiating request. Show newly added permissions separately from already effective access, after key ceilings and configured restrictions; chain-dependent restrictions still apply at request time. Explain that future grants to that profile include this member. Do not describe the change as access only to the requesting key.

The confirmation binds the reviewed membership/grant/key-policy revision. Any change that alters its scope requires a refreshed review and confirmation. An accessible scrollable complete list is acceptable; collapsed summaries or “and more” cannot substitute for disclosure of the full scope.

“Allow once” binds exactly one request, key, principal/process evidence and operation, expires on cancellation/timeout/disconnection, and creates no persistent grant. Concurrent requests do not share it.

A persistent grant is committed as an authenticated policy change, separately from signing. If persistence fails, no signature is released through that new grant. If persistence succeeds but subsequent signing fails, the grant remains and the UI/audit reports both outcomes. User cancellation before the policy commit creates no grant.

## Decision examples / required validation cases

| Evidence and policy | Required outcome |
| --- | --- |
| Allowed descendant; ancestor denies requested operation/key | Deny; no approval bypass. |
| Allowed ancestor; descendant denies requested operation/key | Deny. |
| Ancestor denies Git only; SSH request otherwise granted | SSH can proceed; denial is scoped. |
| Selected Codex has no grant; Terminal ancestor does | Approval required for Codex; no fallback. |
| Key permits SSH + Git; selected app grant permits Git | Git eligible; SSH requires a separate approval. |
| Direct SSH grant + profile Git grant; key permits both | Both eligible for this principal. |
| Remove direct grant while equivalent profile grant remains | Profile-supplied access remains, visibly explained. |
| Missing ancestor / signature failure / PID reuse | Deny; persistent authorization unavailable. |
| Valid grant + system rejects cached context early | Reauthenticate or refuse; never bypass hardware controls. |
| Grant removed/profile changed while prompt is open | Old confirmation stale; no old-response release. |
| Key operation disabled then restored during pending request | Old request invalidated; new request required. |
| Two pending requests; user chooses Allow once for one | Only that request can proceed. |

## Remaining gates

Approve operation-level grants; validate real principal discovery, complete-chain coverage, signing identity matching and boundary rules; resolve migration of existing hash/classification records; validate revocation serialization and hardware authentication behavior. Until then this is a reviewable contract, not a claim of enforced security.
