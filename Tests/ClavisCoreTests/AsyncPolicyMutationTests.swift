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
}
