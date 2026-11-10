# Clavis: application and domain model assessment

Date: 2026-10-28  
Status: Key-first revision; contracts pending validation; no runtime behavior changed  
Branch: `codex/key-access-redesign`

## 1. What Clavis is

Clavis is a local macOS key store and signing broker for people and automation. It keeps private keys on the Mac and lets other applications request signatures under rules controlled by the user.

Its initial integrations are SSH authentication and Git commit/tag signing using SSHSIG. A client requests a signature from a particular key; Clavis decides whether that application may use that key and whether the user must authenticate. A successful request returns a signature, not the private key.

The redesign should make three questions easy to answer:

1. **Which key is this?** A separately named cryptographic key with explicit settings.
2. **What may it do?** SSH authentication, Git signing, or an explicitly supported combination.
3. **Who may use it, and when must I authenticate?** Application access and the key's authentication policy.

Clavis should let applications run normally. Users should not need a Clavis launcher for each bot, or a separate socket for each key. Integrating an agent socket and selecting public keys still requires configuration by the user or their existing tools; this is not a promise of zero setup.

## 2. Basis and decision status

This assessment combines the supplied conversation, `ChatGPT-Описание User Stories-20261028-1530.md`, with a source review of the current working tree. The exported conversation is background material: its assistant suggestions are proposals, not automatically approved requirements.

The current branch starts from `ui/refactor`, commit `6fc9a48`. Existing uncommitted changes were present before this assessment and remain untouched. Findings describe the inspected working tree, not necessarily a released build. No build, runtime authentication experiment, or security audit was performed for this document.

### Explicit direction from the user

| Direction | Product consequence |
| --- | --- |
| People and bots should have independent keys. | A bot receives its own cryptographic identity rather than implicitly borrowing a person's signature. |
| Separate Git signing through SSHSIG from SSH authentication. | Key naming and permitted operations must be independent concepts. |
| Clavis should focus on storing keys rather than maintaining SSH configuration. | Host definitions and SSH routing stay outside the core product. |
| Authentication policy belongs on the key. | Profiles and applications cannot weaken a key's authentication requirement. |
| Support different authentication reuse periods, including until lid closure or once a day. | Define explicit session and expiry semantics; validate what the storage backend can support. |
| Identify trusted applications through the requesting process's ancestry. | Evaluate a stable application identity rather than saving a PID as permanent trust. |
| An access request should offer adding the requesting application to the key. | Access can be configured at first use, with explicit scope. |

### Architecture revisions supplied by the user

- Keys are standalone objects. The latest UX revision removes named owner entities, ownership selectors and grouping.
- An **Application Profile** groups trusted applications and can be granted access to selected keys.
- A **Direct Grant** gives one application access to one key.
- One primary SSH-agent socket is the default integration point.
- Separate physical keys for SSH and Git signing are the recommended creation path, while existing combined-use keys remain supported.

The latest UX revision supersedes the earlier named-owner proposal. Navigation contains Keys, Application Profiles and Activity; there is no Requests/requesters view or global authentication screen. Authentication is edited inside the selected key's settings. Activity follows the supplied token-history reference, including app icons, removable key scope, date/sort controls and sticky date groups.

The revisions require deny precedence across verified ancestry, code-signing verification, per-request evaluation, experimental long-lived authentication reuse, and mandatory first-use scope disclosure. Operation-level grants remain an open product question; this draft recommends them and specifies their semantics for review. None of these new entities or contracts should be read as implemented runtime behavior.

## 3. What the app does today

Clavis has four Swift package targets: a native SwiftUI/AppKit app, a background agent, a command-line utility, and the shared `ClavisCore` library. The app provides key management, authentication/session controls, application settings, history, and a menu-bar surface. The daemon handles agent requests and authoritative policy checks.

### Existing domain concepts

| Area | Inspected implementation | Assessment |
| --- | --- | --- |
| Keys | `SSHKeyInfo`, `StoredPrivateKeyRecord`, `KeyAlgorithm`, `KeyStorageType` | Currently ECDSA P-256 and Secure Enclave only. Alternative storage and algorithms are not implemented choices. |
| Ownership | `KeyType.personal` / `.bot` in `KeyAccessProfile` | Ownership is a key classification; there is no separate person/bot Identity aggregate. |
| Operations | Independent `ssh` and `signature` capabilities | A foundation for separating ownership from use already exists. Legacy `KeyPurpose` restrictions remain relevant. |
| Application access | `ApplicationRegistry`, `ApplicationClassification` | Global Personal/Bot/Block classification, rather than explicit application-to-key grants. |
| Attribution | `ApplicationCallerResolver`, `ApplicationIdentityVerifier` | Process-chain inspection and verification already exist. The implementation is more conservative than unrestricted ancestor matching. |
| Authentication | `BiometricPolicy`, `KeyGracePeriod`, Git grants, agent sessions | Hardware access controls and several application-managed reuse mechanisms exist. They are not yet one coherent policy model. |
| Transport | `AgentSocketRole` and agent server | Primary `clavis.sock`; restricted compatibility endpoint `clavis-agent.sock`. A socket does not establish caller identity. |
| Revocation | Registry revisions and `KeyPolicyGenerations` | Requests capture policy state and validate it again before returning signatures. Preserve this behavior. |
| History | Audit events, recorder/store and History UI | Existing infrastructure can explain signing and policy decisions; new grant concepts need corresponding audit semantics. |

Today, a verified Personal-classified application is eligible for Personal and Bot keys, while a Bot-classified application is eligible only for Bot keys. Key operation restrictions still apply. Unknown or uncertain callers are eligible only for authenticated one-shot access; this does not create remembered trust.

The caller resolver checks up to 32 processes and revalidates sampled process identities. Personal attribution crosses only recognized, verified transport helpers; an arbitrary shell or interpreter breaks that attribution. Block and Bot classifications can constrain access across interpreters. Consequently, “find any trusted ancestor and allow it” would change the current trust model, not merely simplify its implementation.

The current hardware policies are user presence or the current biometric set. A Bot label, an agent session with no per-operation prompt, and a truly unattended key are different things. Existing sessions can reuse previously authenticated contexts; that does not establish support for signing after a restart without user authentication.

## 4. Proposed domain model

### Key: the cryptographic object and its policy

A key has a stable identifier, descriptive purpose, public key/fingerprint, private-key reference, algorithm/storage metadata, `allowedOperations`, and `authenticationPolicy`. Purpose describes intended use; `allowedOperations` is the authoritative operation ceiling and must remain consistent with purpose. Its display name can change without changing its identity or its grants.

Purpose, operations and authentication are independent. A key used for automation can still require authentication. A key name or purpose does not grant application permission.

The public index is a display aid. Security decisions must use authoritative policy and private records, retaining the current validation against mismatched metadata.

### Application: the verified client identity

An Application represents code that may initiate a request. Its display name, icon, executable path, and observed PID help explain a decision; they do not independently establish trust. Persisted trust in the revised model requires verified running-code signing identity. Names, paths, raw PIDs, or a file hash alone cannot establish it. The current code has designated-requirement and executable-hash identity forms. Legacy hash-based entries need explicit migration/reverification and do not automatically satisfy the new signing-identity contract.

A request can have both a direct peer (`ssh`) and an attributed initiating application (`Antigravity`). The UI should show both when useful.

### Application Profile: reusable application membership

A profile such as “Coding Agents” contains verified application identities. Granting that profile access to a key lets its members use that key, subject to the key's operations and authentication requirements.

A profile has no private key, authentication cache, or implicit socket. It also does not own the keys it can access. Adding an application to a profile expands access to keys and operations granted to that profile; future profile-to-key grants would include that member too. Listing every affected key and its effective operations before confirmation is a mandatory acceptance criterion, including when the change starts from a single-key request.

The new term is **Application Profile**. The existing Swift `KeyAccessProfile` means key ownership plus capabilities and should not be confused with this new entity.

### Access Grant: who may use which key

A persistent grant links either an Application or an Application Profile to one Key. Recommended addition: each grant contains an explicit, nonempty `allowedOperations` set. For the selected application principal, effective access is the intersection of key operations and the union of its applicable direct/profile grant operations, minus applicable denials. Missing operation fields never mean “all.” A profile grant cannot make an SSH-only key sign Git data or make an interactive key unattended.

The formal draft contract is in [authorization-contract.md](authorization-contract.md). An applicable explicit deny anywhere in verified ancestry wins over all allows. A descendant allow cannot bypass an ancestor restriction, and an ancestor allow cannot bypass a descendant restriction. Select one deterministic initiating principal; do not merge allows from unrelated ancestors. Re-evaluate every signature and revalidate before releasing its response. Incomplete/unverifiable ancestry cannot create persistent authorization; this draft refuses such requests pending a decision on one-shot fallback.

Removing a direct grant does not remove access still provided by a profile. The app must show every source of effective access and explain what remains after removal. Explicit restrictions are separate from allow-only Access Grants; they have defined key/operation scope in the contract. Nested profiles remain outside the first version.

### Authentication Session: temporary proof, separate from access

An authentication session records temporary authorization to use a key under its authentication policy. It is not an Access Grant. Removing application access prevents further use even while an authentication session is active.

The scope of authentication reuse needs an explicit decision: key-wide reuse across authorized applications versus reuse bound to a key and initiating application/process context. Keeping policy on a key does not require making its cached proof available to every application. The initial recommendation is to preserve the current constrained reuse until broader sharing is deliberately approved.

### Signing Request and Audit Event

A request binds the selected key, observed caller chain, verified identity evidence, classified operation, and policy revisions. Its outcome is allowed, denied, cancelled, or failed, with an auditable reason. An approval for one request must not authorize another pending request accidentally.

An Audit Event explains the decision, including the key, caller, operation, applicable access source, and authentication result where available. Missing attribution must be presented as missing evidence, not replaced by a confident application label.

### Relationships

```text
Application ── member of ──> Application Profile
Application ── direct Access Grant ──> Key
Application Profile ── Access Grant ──> Key

Key ── defines ──> allowed operations + authentication policy
Signing Request ── evaluated against ──> caller evidence + grants + key policy
Authentication Session ── temporarily satisfies ──> authentication requirement
Signing Request / policy change ── produces ──> Audit Event
```

## 5. Authentication model

These are proposed product behaviors, not claims that every option is currently supported by macOS or Clavis.

| Policy | Intended behavior | Decision or validation needed |
| --- | --- | --- |
| Every request | Require fresh authentication for each signing operation. | Preserve hardware-policy enforcement and cancellation behavior. |
| Until lock or sleep | Reuse authentication until screen lock, sleep, explicit revocation, or agent restart. | Decide whether literal lid closure while awake must also end the session. |
| For a duration | Reuse for a bounded interval after authentication. | Define supported intervals, reuse scope, and invalidation events. |
| Once a day | Reuse within a defined daily window. | Decide rolling 24 hours versus calendar day, and whether lock/sleep ends reuse. |
| Unattended | Authorized applications can sign without interactive authentication. | Validate key creation, private-record access, and signing across restart; existing protected keys cannot be promised this through a UI toggle. |

The user's “context retention” refers to reuse of macOS authentication, not AI memory or key lifetime. A daily policy does not imply daily key rotation or deletion.

Daily and session-long reuse are experimental capabilities until signed end-to-end validation on supported macOS versions succeeds. A configured policy is a maximum reuse window, not a promise of uninterrupted signing. Clavis-managed expiry and the operating system's willingness to accept a context are separate constraints. The product must tolerate earlier system rejection by asking again or refusing the operation. Long reuse windows require experiments on supported, signed builds before becoming guaranteed UI behavior.

Changing hardware access controls may require replacement key material and public-key registration elsewhere. The UI must distinguish a policy edit that preserves a key from an operation that creates a new key. Never silently replace the key requested by an SSH or Git client.

## 6. Request lifecycle and first-use approval

Example: Antigravity launches a shell, which runs Git and then an SSH client requesting the Development Bot SSH key.

1. The agent observes the connecting peer and gathers process identity/ancestry evidence. PID is a live reference, not a saved permission.
2. It resolves an initiating application using explicit attribution rules. A generic signed `ssh`, `git`, or Terminal ancestor must not silently confer broad access.
3. It checks paused/blocked state, requested key, operation, and applicable grants. Application permission is evaluated for each signature, including requests that skip key enumeration.
4. With no applicable grant, a verified candidate can be offered for approval. The dialog shows the key, operation, selected application, process chain, and the scope of child-process trust.
5. The user may deny, allow this request once, always allow this application for this key, or add the application to an existing profile. Individual-key approval lists the key and exact permitted operations. Profile expansion lists every affected key and effective operation before confirmation; the review is invalidated by intervening policy changes. Selecting another process changes the proposed trust target and requires its own valid identity evidence.
6. The key's authentication requirement still applies. Approving application access does not satisfy or weaken that requirement. Persistent access changes must use the authenticated control path.
7. Before returning a signature, the agent rechecks caller and policy state. Revocation during a prompt or signing operation invalidates the stale decision.
8. The outcome is recorded. Cancellation, timeout, a vanished process, or stale evidence must not produce a successful signature response.

The persistence transaction and retry behavior still need specification: for example, whether an explicitly confirmed grant remains if the subsequent signature fails. The UI must report these as distinct outcomes.

For incomplete or unverified ancestry, the proposed conservative default is refusal. Retaining the current explicitly authenticated one-shot fallback is an open product decision; either way, uncertain evidence must never create remembered access. Prompt serialization, deduplication, bounded queues, and cooldown behavior should prevent an unknown caller from flooding the user with dialogs.

## 7. SSH, Git, and the product boundary

One primary agent socket remains the recommended default. Separate public keys identify the requested cryptographic material; separate sockets are not required for separate keys. Keep the existing restricted endpoint compatible until migration is deliberately specified. Additional sockets could later expose narrower views, but do not themselves prove which application is calling.

Git uses SSHSIG for signatures; that is a distinct intended operation from SSH authentication. The repository already validates the structure of Git-namespace SSHSIG payloads for the Git-only path. However, an agent receives bytes to sign, not independently verified user intent. The product must distinguish “Git-format signing request” from a proven statement about a particular repository or commit. Likewise, unmatched bytes are not automatically proven SSH authentication.

The exact operation classifier is a security contract to specify before implementation: malformed SSHSIG, other namespaces, generic signing requests, and missing destination information need explicit outcomes. A dedicated Git adapter is an optional future design, not a requirement already decided in the discussion and not proof of intent by itself.

Clavis should provide public-key copying/export and clear connection guidance. It should not automatically manage hosts, rewrite `~/.ssh/config`, change global Git configuration, or select a different identity than the client requested.

JWT/JWS, mTLS, passkeys, generic artifact signing, SSH certificate issuance, remote key services, additional algorithms, and software-backed keys are potential extensions. They are outside this redesign's initial scope. The existence of a P-256 key does not make those integrations available.

## 8. Trust boundary and migration assessment

The model controls access to signing operations and makes their origin understandable. It does not provide strong isolation from hostile code executing as the same user or inside a trusted application's child processes. Trusting an application's descendants includes scripts and tools it launches; the first-use dialog must say this plainly.

Process chains can change or disappear. Code identity and sampled process instances need revalidation; uncertainty cannot be resolved by falling back to a display name or a convenient trusted ancestor. A “responsible process” integration or Endpoint Security dependency was discussed as a possibility, not established as available or necessary.

The largest migration is from global application classification to explicit key grants. Translating a Personal application into grants to every existing and future key would preserve the broadness the redesign is meant to make visible. Recommended approach: show existing effective access for review, create explicit grants only through a deliberate migration decision, and keep an unmigrated state distinguishable from an empty grant list. Do not let missing new fields silently broaden access.

Preserve key material, fingerprints, disabled operations, hardware controls, and compatibility restrictions. Name changes must not break grant identity. Revisions must cover profile membership, grants, blocks, and key policy, so stale requests cannot survive a remove-and-readd cycle. Authentication caches end on restart and must not be reconstructed from persistent access grants.

Revocation affects future signing and pending responses. It does not close an SSH connection that already authenticated or invalidate a signature already returned. Local key deletion also does not remove its public key from remote services.

## 9. Implications for the later interface

The main object should be the key. Its detail view should answer purpose, authentication policy/status, and effective application access without mixing those into one “type” setting.

Application Profiles need a separate management view with members and affected keys. Applications need inspectable verification details and a way to block or remove access. History should explain both successful and denied requests. The menu-bar surface should expose agent state, active authentication sessions, revocation, and pause/resume.

Use purpose labels such as “SSH” and “Git signing” in primary navigation; algorithm and storage belong in key details. “Authentication expires” and “Application access removed” must remain visibly different outcomes. Empty, unavailable, paused, unverified, and expired states must have distinct meanings.

The current HTML studies use Library, Key Table, Key Settings, Split View and Menu Bar directions. Key lists remain on the left or in the main table; none sits to the right of its inspector. Access prompts are transient dialogs. Authentication belongs to key settings. Activity reuses the supplied token-filter history study with app icons.

## 10. Decisions needed before detailed specifications

| Decision | Recommended starting position |
| --- | --- |
| Standalone keys | Named-owner entities and selectors are removed. Applications still require verified code identity. |
| Operation-level grants? | Recommended: explicit operation sets intersected with the key ceiling; still awaiting product decision. |
| Direct grants plus Application Profiles? | Support both, with all sources of effective access visible. |
| Ancestor selection and conflicting matches | Draft contract: ancestry-wide deny precedence; nearest eligible configured principal; no cross-principal allow union. Validate before implementation. |
| Unverified caller behavior? | Default to refusal; decide explicitly whether authenticated one-shot access remains. |
| Authentication reuse scope? | Preserve constrained reuse initially; do not assume key-wide sharing. |
| Meaning of daily and lid closure? | Define exact expiry/invalidation rules before showing those policy labels. |
| Unattended Secure Enclave keys? | Treat as a gated capability pending signed end-to-end experiments. |
| Existing classification migration? | Review effective permissions and preserve cryptographic restrictions; no silent expansion. |
| Existing combined SSH/Git keys? | Preserve them; recommend separate keys for new setup. |

Companion drafts: [user-stories.md](user-stories.md), [authorization-contract.md](authorization-contract.md), and [authentication-validation.md](authentication-validation.md). The [interactive HTML prototype](../../ui/redesign/index.html) uses simulated data only. Runtime redesign implementation is gated on review of the relevant contracts and validation of the macOS constraints; a prototype is not evidence that those constraints have passed.

## Source map

Paths below are repository-relative. These are the principal sources inspected for this assessment, not evidence of fresh runtime verification.

- `Package.swift` — current executable/library targets and macOS deployment baseline.
- `README.md`, `SECURITY.md` — existing positioning and documented security behavior; some terminology predates the current routing model.
- `docs/personal-bot-routing.md` — primary/compatibility sockets, classifications, uncertainty, pause and revocation behavior.
- `Sources/ClavisCore/Models/KeyModels.swift` — key metadata, hardware policies, current grace-period options and supported algorithm/storage.
- `Sources/ClavisCore/Models/KeyAccessProfile.swift` — ownership and independent operation capabilities.
- `Sources/ClavisCore/Models/PrivateKeyRecord.swift` — authoritative private record and legacy mapping.
- `Sources/ClavisCore/Models/ApplicationRegistry.swift` — application identities, classification eligibility and authenticated updates.
- `Sources/ClavisCore/Protocol/ApplicationCallerResolver.swift` — ancestry matching, transport-helper limits and revalidation.
- `Sources/ClavisCore/Protocol/ApplicationRequestAuthorization.swift` — request leases and revision/generation validation.
- `Sources/ClavisCore/Protocol/SigningPolicyEvaluator.swift`, `SSHSIGPayload.swift`, `AgentSocketRole.swift` — signing decisions, Git payload validation and endpoint restrictions.
- `Sources/ClavisCore/Crypto/KeychainManager.swift`, `UserAuthenticator.swift`, `GitSigningGraceManager.swift` — signing/authentication integration and existing reuse mechanisms.
- `Sources/ClavisCore/Services/SystemEventMonitor.swift` — existing lock/sleep monitoring.
- `Sources/ClavisCore/Audit/AuditEvent.swift` — existing audit event vocabulary.
- `Sources/Clavis/Views/KeyListView.swift`, `Sheets/SettingsNavigation.swift` — current key-oriented UI and application settings.
- `ui/auth-exp/README.md` — existing authentication experiments; their notes are experimental evidence, not a released unattended-key guarantee.
