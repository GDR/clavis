# Redesign user stories and acceptance criteria

Status: draft, 2026-10-28. References: [assessment](assessment.md), [authorization contract](authorization-contract.md), [authentication validation](authentication-validation.md). All “Given / When / Then” clauses below are mandatory acceptance criteria for their story, not evidence of implementation.

## Key management

### US-KEY-01: Manage independent keys

As a user, I want a simple list of separately named keys so that I can manage personal and automation use without a separate owner hierarchy.

- Given key creation, when I save a key, then it receives a stable ID, independent cryptographic material, explicit purpose/operations and per-key authentication settings.
- Given any key view, when I browse or create a key, then there is no named-owner selector or grouping.
- Given a renamed key, when access is evaluated, then grants continue to use its stable reference rather than a display name.
- Given a key with no grants, when an application requests signing, then its name/purpose does not establish permission.
- Given the app navigation, when I browse, then only Keys, Application Profiles and Activity are primary destinations. Access approval remains a transient dialog.
- Given authentication editing, when I change policy, then I do so inside that key's settings, with no global policy screen.

### US-KEY-02: Separate purpose from permission

As a user, I want SSH and Git signing keys and operation controls so that access to one operation does not imply access to the other.

- Given a combined-use key, when an application has only a Git grant, then SSH is not authorized by that grant (subject to the operation-level-grant decision).
- Given a disabled key operation, when a request or first-use approval asks for it, then it is refused without silently changing key policy.
- Given a purpose selection, when the key is saved, then purpose and allowed operations pass an explicit compatibility rule; contradictory settings cannot be saved.
- Given a key-operation change, when it commits, then pending decisions are invalidated and restored operations' existing grant effects are shown before confirmation.
- Given a requested key, when another key seems more appropriate, then Clavis never substitutes it.

### US-KEY-03: Review and revoke effective access

As a user, I want to see all routes to a key so that I can revoke the intended permissions.

- Given direct and profile grants, when I inspect a key, then the UI lists every source and its effective operations.
- Given overlapping grants, when I remove one, then the UI explains any remaining access before confirmation and recomputes it afterward.
- Given a policy change ordered before a pending response's commit point, when authorization is rechecked, then the old response is not released; already returned signatures are not described as recalled.

## Application access

### US-ACCESS-01: Approve one verified application at first use

As a user, I want to review the initiating application and requested key so that I can authorize a deliberate scope.

- Given complete verified ancestry and no grant/deny for an enabled operation, when approval opens, then it shows selected application, direct peer, process chain, exact key and operation.
- Given individual-key approval, when the user confirms, then the dialog has explicitly listed that key and selected operations. The default selection is only the requested operation. This is mandatory.
- Given an eligible candidate change, when I select another process, then identity verification and the impact preview are refreshed; a name/path-only candidate cannot be saved.
- Given an explicit deny anywhere in ancestry, when the request is evaluated, then no allow choice bypasses it.
- Given incomplete/unverified ancestry, when approval would persist access, then persistence is unavailable. The conservative draft refuses the request; one-shot fallback remains undecided.
- Given Allow once and several pending requests, when one is confirmed, then only its bound request may proceed and no grant is saved.
- Given a persistent grant commit followed by a signing failure, when results appear, then the app separately reports that access was saved and signing failed.

### US-ACCESS-02: Reuse application profiles safely

As a user, I want a profile of trusted applications so that I can grant a consistent set of permissions without repeating membership setup for each key.

- Given a profile, when I inspect it, then its members, connected keys, configured operations and effective operations are visible.
- Given a membership addition, whether from settings or first use, when confirmation is requested, then **all affected keys and their effective operations** are listed, with new access distinguished from existing access. This is mandatory.
- Given membership confirmation, when the reviewed scope changes concurrently, then confirmation is invalidated and a fresh complete preview is required.
- Given an authenticated membership edit, when it commits, then revisions change and pending approvals cannot use the older membership.
- Given future grants to the profile, when membership is approved, then that future-inclusion behavior has been disclosed.
- Given profile removal, when it commits, then direct grants remain independently visible; authentication policy is never weakened.

### US-ACCESS-03: Enforce restrictions across ancestry

As a user, I want explicit restrictions to win so that an allowed helper or ancestor cannot bypass them.

- Given conflicting rules on verified nodes, when a signature is requested, then applicable deny wins regardless of ancestor distance.
- Given multiple allows on different ancestors, when a principal is selected, then only that principal's direct/profile grants are combined.
- Given a configured nearer application without access and a more distant allowed ancestor, when evaluated, then the request does not inherit the distant application's grant.
- Given a persistent socket connection, when a new signing request arrives, then ancestry, rules and operation permission are re-evaluated.
- Given a burst of requests, when prompting is considered, then bounded serialization/deduplication/cooldown behavior prevents an unbounded dialog queue; numerical limits must be specified and tested before release.

## Authentication policies

### US-AUTH-01: Keep application permission and authentication distinct

As a user, I want each key to retain its authentication requirement regardless of which application has access.

- Given a permitted application and a key requiring fresh authentication, when it requests signing, then a persistent grant does not skip authentication.
- Given failed or cancelled authentication, when signing completes, then no success response is returned.
- Given an automation key, when its policy is inspected, then its name/purpose alone does not imply unattended signing.
- Given an attempted hardware-policy change, when replacement is required, then the app explains the new fingerprint and external registration implications before any replacement; a UI toggle never silently replaces key material.

### US-AUTH-02: Reuse authentication within validated limits

As a user, I want bounded reuse where supported so that repeated authorized work can proceed with fewer prompts.

- Given session-long/daily reuse without a passed validation matrix, when the setting is shown, then it is labeled experimental and not offered as a guaranteed supported policy.
- Given a configured reuse window, when macOS rejects the context early, then Clavis asks again or refuses; the TTL never bypasses hardware enforcement.
- Given expiry, a configured invalidation event, explicit revocation or daemon restart, when another request arrives, then the old session cannot be reused.
- Given a surviving Access Grant after authentication expiry, when signing is requested, then the permission may still exist but fresh authentication is required.
- Given pending decisions during lock/sleep/revocation, when invalidation occurs, then no stale session response is released under the old authorization.
- Given a daily or lid-related policy, when promoted from experimental, then rolling/calendar-day behavior, lock/sleep behavior, clamshell behavior and reuse scope have explicit validated definitions.

### US-AUTH-03: Use unattended keys only when actually supported

As an automation owner, I want truthful unattended capability so that a job does not unexpectedly wait for user interaction.

- Given an existing user-presence-protected key, when unattended mode is selected, then the app cannot claim it removed hardware authentication through an application setting.
- Given a proposed unattended backend, when release support is considered, then creation, protected-record loading, signing after daemon/Mac restart and defined locked-state behavior must pass signed end-to-end validation.
- Given missing capability evidence, when a bot is configured, then the app offers validated interactive behavior rather than silently falling back to unprotected storage.

## Prototype boundary

The [HTML prototype](../../ui/redesign/index.html) demonstrates standalone keys, operation-limited grants, scope previews and simulated decisions. It does not inspect real processes, authenticate, store keys or enforce these contracts. Prototype interaction checks are not security or macOS capability validation.

### US-ACTIVITY-01: Filter signing history

- Given Activity, when opened, then the key source list sits on the left and event rows show application icons, operation, result and timestamp grouped by sticky date headings.
- Given a selected key or a key-specific Show activity action, when history opens, then one removable Key token represents that scope.
- Given other filter tokens, when the Key token is removed, then all keys are shown while other filters remain.
- Given Filter + or typed Host/Process/Key/Result prefixes, when suggestions are chosen, then removable tokens are added and results update. Values of one field combine with OR; different fields combine with AND.
- Given date and sort controls, when changed, then the displayed date groups and results reflect their values.
