import Foundation
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

/// Regression coverage for the single authenticated, presenter-driven profile mutation.
@Suite(.serialized) struct AsyncPolicyMutationTests {
    @MainActor
    private final class StubAuthenticator: AsyncUserAuthenticating {
        var count = 0
        var lastPolicy: LAPolicy?
        var error: Error?
        /// Runs after a successful evaluation, before the context is returned.
        var afterEvaluation: (() -> Void)?

        func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
            count += 1
            lastPolicy = policy
            if let error { throw error }
            afterEvaluation?()
            return LAContext()
        }
    }

    @Test @MainActor func mutatesExactlyOnceWithOneFreshEvaluation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "async-once")
            let auth = StubAuthenticator()
            let target: KeyType = key.effectiveAccessProfile.type == .bot ? .personal : .bot
            try await manager.changeAccessProfile(
                label: key.label, type: target,
                expectedCurrent: key.effectiveAccessProfile, authenticator: auth
            )
            #expect(auth.count == 1)
            #expect(auth.lastPolicy == .deviceOwnerAuthentication)
            #expect(try manager.fetchKeyInfo(label: key.label)?.effectiveAccessProfile.type == target)
        }
    }

    @Test @MainActor func cancelledAuthenticationLeavesPolicyUnchanged() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let key = try manager.generateKey(label: "async-cancel")
            let raw = try store.load(label: key.label, context: LAContext(), prompt: "")
            let auth = StubAuthenticator()
            auth.error = LAError(.userCancel)
            await #expect(throws: (any Error).self) {
                try await manager.changeAccessProfile(
                    label: key.label, type: .bot,
                    expectedCurrent: key.effectiveAccessProfile, authenticator: auth
                )
            }
            #expect(try store.load(label: key.label, context: LAContext(), prompt: "") == raw)
            #expect(try manager.fetchKeyInfo(label: key.label) == key)
        }
    }

    @Test @MainActor func cancellationAfterEvaluationNeverPersists() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let key = try manager.generateKey(label: "async-late")
            let raw = try store.load(label: key.label, context: LAContext(), prompt: "")
            let auth = StubAuthenticator()
            let task = Task { @MainActor in
                try await manager.changeAccessProfile(
                    label: key.label, type: .bot,
                    expectedCurrent: key.effectiveAccessProfile, authenticator: auth
                )
            }
            // Cancel the request while "authentication" is completing (late completion).
            auth.afterEvaluation = { task.cancel() }
            await #expect(throws: (any Error).self) { try await task.value }
            #expect(try store.load(label: key.label, context: LAContext(), prompt: "") == raw)
            #expect(try manager.fetchKeyInfo(label: key.label) == key)
        }
    }

    @Test @MainActor func staleStagedRequestIsRejectedBeforeAuthentication() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "async-stale")
            let stale = KeyAccessProfile(type: .bot, capabilities: .init(ssh: false, signature: true))
            #expect(stale != key.effectiveAccessProfile)
            let auth = StubAuthenticator()
            await #expect(throws: PolicyMutationError.staleRequest) {
                try await manager.changeAccessProfile(
                    label: key.label, type: .bot,
                    expectedCurrent: stale, authenticator: auth
                )
            }
            #expect(auth.count == 0)
            #expect(try manager.fetchKeyInfo(label: key.label) == key)
        }
    }

    @Test @MainActor func noOpChangeDoesNotAuthenticate() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "async-noop")
            let auth = StubAuthenticator()
            try await manager.changeAccessProfile(
                label: key.label, type: key.effectiveAccessProfile.type,
                expectedCurrent: key.effectiveAccessProfile, authenticator: auth
            )
            #expect(auth.count == 0)
        }
    }

    @Test @MainActor func unlockedTimeoutChangeAuthenticatesPersistsAndRevokesAllGrants() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            var revokedLabels: [String] = []
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                agentGrantRevoker: { revokedLabels.append($0) },
                gitSigningGraceManager: grants
            )
            let key = try manager.generateKey(label: "timeout-mutate", unlockedTimeout: .session)
            let pid = getpid()
            let anchor = GitApprovedProcess(pid: pid, startTime: ProcessInspector.processStartTime(pid: pid) ?? 0, path: "/caller")
            _ = try manager.authorizeGitSigningGrant(
                key: key, prompt: "Git", clientIdentity: "id", duration: 300, approvedProcess: anchor
            )
            _ = try manager.authorizePersonalSSHGrant(
                key: key, prompt: "SSH", approvalIdentity: "app:A", duration: 300
            )
            #expect(grants.getValidGrant(for: key.label) != nil)
            #expect(!grants.allActivePersonalGrants().isEmpty)

            // Tightening 8 hours -> 15 min must authenticate, persist v4 timeout, and lock active sessions.
            let auth = StubAuthenticator()
            try await manager.changeAccessProfile(
                label: key.label,
                unlockedTimeout: .fifteenMinutes,
                expectedCurrent: key.effectiveAccessProfile,
                expectedTimeout: .session,
                authenticator: auth
            )
            #expect(auth.count == 1)
            #expect(auth.lastPolicy == .deviceOwnerAuthentication)
            let updated = try #require(try manager.fetchKeyInfo(label: key.label))
            #expect(updated.unlockedTimeout == .fifteenMinutes)
            #expect(revokedLabels == [key.label])
            #expect(grants.getValidGrant(for: key.label) == nil)
            #expect(grants.allActivePersonalGrants().isEmpty)

            let raw = try #require(try store.load(label: key.label, context: LAContext(), prompt: ""))
            let record = try StoredPrivateKeyRecord.decode(from: raw)
            #expect(record.version == 4)
            #expect(record.unlockedTimeout == .fifteenMinutes)

            // Cancelled change to Once must leave stored 15 min untouched.
            let cancelAuth = StubAuthenticator()
            cancelAuth.error = LAError(.userCancel)
            await #expect(throws: (any Error).self) {
                try await manager.changeAccessProfile(
                    label: key.label,
                    unlockedTimeout: .always,
                    expectedCurrent: updated.effectiveAccessProfile,
                    expectedTimeout: .fifteenMinutes,
                    authenticator: cancelAuth
                )
            }
            #expect(try manager.fetchKeyInfo(label: key.label)?.unlockedTimeout == .fifteenMinutes)

            // Stale expectedTimeout is rejected before prompting.
            let staleAuth = StubAuthenticator()
            await #expect(throws: PolicyMutationError.staleRequest) {
                try await manager.changeAccessProfile(
                    label: key.label,
                    unlockedTimeout: .always,
                    expectedCurrent: updated.effectiveAccessProfile,
                    expectedTimeout: .session,
                    authenticator: staleAuth
                )
            }
            #expect(staleAuth.count == 0)

            // Valid change 15 min -> Once succeeds and revokes any newly granted session.
            _ = try manager.authorizePersonalSSHGrant(
                key: updated, prompt: "SSH2", approvalIdentity: "app:A", duration: 300
            )
            try await manager.changeAccessProfile(
                label: key.label,
                unlockedTimeout: .always,
                expectedCurrent: updated.effectiveAccessProfile,
                expectedTimeout: .fifteenMinutes,
                authenticator: auth
            )
            #expect(auth.count == 2)
            #expect(try manager.fetchKeyInfo(label: key.label)?.unlockedTimeout == .always)
            #expect(grants.allActivePersonalGrants().isEmpty)
        }
    }
}
