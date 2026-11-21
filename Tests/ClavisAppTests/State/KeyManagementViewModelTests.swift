import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport
@testable import Clavis

@Suite
final class KeyManagementViewModelTests {
    private let mockAgent = MockAgentController()

    @MainActor
    private func withTestEnv(_ body: (KeyManagementViewModel, KeychainManager) throws -> Void) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let km = fixture.makeKeyManager()
            let vm = KeyManagementViewModel(keyManager: km, agentLifecycle: mockAgent)
            try body(vm, km)
        }
    }

    @Test @MainActor
    func testListKeysRefreshesPublishedKeys() async throws {
        try await withTestEnv { viewModel, keyManager in
            #expect(viewModel.keys.count == 0)

            _ = try keyManager.generateKey(label: "key-1")
            viewModel.refresh()
            #expect(viewModel.keys.count == 1)
            #expect(viewModel.keys.first?.label == "key-1")
        }
    }

    @Test @MainActor
    func testGenerateKeyCreatesAndRefreshes() async throws {
        try await withTestEnv { viewModel, _ in
            let created = try viewModel.generateKey(
                label: "generated-key",
                algorithm: "ECDSA P-256",
                keyPurpose: .general
            )

            #expect(created.label == "generated-key")
            #expect(viewModel.keys.count == 1)
            #expect(viewModel.keys.first?.label == "generated-key")
            #expect(viewModel.errorMessage == nil)
        }
    }

    @Test @MainActor
    func testDeleteKeyRemovesAndRefreshes() async throws {
        try await withTestEnv { viewModel, _ in
            _ = try viewModel.generateKey(label: "to-delete")
            #expect(viewModel.keys.count == 1)

            try viewModel.deleteKey(label: "to-delete")
            #expect(viewModel.keys.count == 0)
        }
    }

    @Test @MainActor
    func testChangeKeyKindUpdatesKind() async throws {
        try await withTestEnv { viewModel, _ in
            _ = try viewModel.generateKey(label: "kind-key", keyPurpose: .general)
            #expect(viewModel.keys.first?.purpose == .general)

            try viewModel.changeKeyKind(label: "kind-key", to: .agent)
            #expect(viewModel.keys.first?.purpose == .agent)

            try viewModel.changeKind(label: "kind-key", to: .general)
            #expect(viewModel.keys.first?.purpose == .general)
        }
    }

    @Test @MainActor
    func testLockKeyLocksKeyAndRefreshes() async throws {
        try await withTestEnv { viewModel, _ in
            _ = try viewModel.generateKey(label: "lock-key")

            #expect(throws: Never.self) {
                try viewModel.lockKey(label: "lock-key")
            }
            #expect(viewModel.keys.count == 1)
            #expect(viewModel.errorMessage == nil)
        }
    }

    @Test @MainActor
    func testPolicyRoundTripViaAgentControlling() async throws {
        try await withTestEnv { viewModel, _ in
            let keyPolicy = AgentKeyPolicy(
                mode: .notify,
                leaseMinutes: 60,
                allowedHosts: [],
                burst: 10,
                refillPerMinute: 6
            )

            try viewModel.setAgentPolicy(keyPolicy, fingerprint: "SHA256:abc123")
            #expect(mockAgent.setAgentPolicyCallCount == 1)
            #expect(mockAgent.recordedSetPolicies.first?.target == "SHA256:abc123")

            let retrieved = viewModel.getAgentPolicy(fingerprint: "SHA256:abc123")
            #expect(retrieved != nil)
            #expect(retrieved?.mode == .notify)
            #expect(retrieved?.leaseMinutes == 60)
            #expect(retrieved?.burst == 10)
            #expect(retrieved?.refillPerMinute == 6)

            let globalPolicy = AgentGlobalPolicy(
                version: 1,
                maxLeaseMinutes: 120
            )
            try viewModel.setGlobalPolicy(globalPolicy)
            #expect(mockAgent.setAgentPolicyCallCount == 2)
            #expect(mockAgent.recordedSetPolicies.last?.target == "global")

            let retrievedGlobal = viewModel.getGlobalPolicy()
            #expect(retrievedGlobal != nil)
            #expect(retrievedGlobal?.version == 1)
            #expect(retrievedGlobal?.maxLeaseMinutes == 120)
        }
    }

    @Test @MainActor
    func testPolicyValidationFailureThrows() async throws {
        try await withTestEnv { viewModel, _ in
            let invalidPolicy = AgentKeyPolicy(
                mode: .ask,
                leaseMinutes: -5,
                allowedHosts: [],
                burst: 10,
                refillPerMinute: 6
            )

            #expect(throws: (any Error).self) {
                try viewModel.setAgentPolicy(invalidPolicy, fingerprint: "SHA256:invalid")
            }
            #expect(mockAgent.setAgentPolicyCallCount == 0)
        }
    }

    @Test @MainActor
    func testClearError() async throws {
        try await withTestEnv { viewModel, _ in
            viewModel.errorMessage = "Sample error"
            #expect(viewModel.errorMessage == "Sample error")

            viewModel.clearError()
            #expect(viewModel.errorMessage == nil)
        }
    }

    @Test @MainActor
    func testRenameKeyUpdatesLabelAndPreservesFingerprint() async throws {
        try await withTestEnv { viewModel, keyManager in
            let original = try viewModel.generateKey(label: "old-name", keyPurpose: .general)
            let renamed = try viewModel.renameKey(from: "old-name", to: "new-name")

            #expect(renamed.label == "new-name")
            #expect(renamed.fingerprint == original.fingerprint)
            #expect(renamed.publicKeyOpenSSH.hasSuffix("new-name"))
            #expect(viewModel.keys.count == 1)
            #expect(viewModel.keys.first?.label == "new-name")
            #expect((try keyManager.fetchKeyInfo(label: "old-name")) == nil)
            #expect((try keyManager.fetchKeyInfo(label: "new-name"))?.fingerprint == original.fingerprint)

            // Reject empty / whitespace-only rename
            #expect(throws: KeychainManagerError.invalidLabel) {
                try viewModel.renameKey(from: "new-name", to: "   ")
            }
        }
    }

    @Test @MainActor
    func testGracePeriodDefaultAndPersistenceAcrossRename() async throws {
        try await withTestEnv { viewModel, _ in
            let key = try viewModel.generateKey(label: "grace-key", keyPurpose: .general)
            #expect(viewModel.gracePeriod(for: key) == .fifteenMinutes)

            viewModel.setGracePeriod(.fiveMinutes, for: key)
            #expect(viewModel.gracePeriod(for: key) == .fiveMinutes)

            let renamed = try viewModel.renameKey(from: "grace-key", to: "grace-key-renamed")
            #expect(viewModel.gracePeriod(for: renamed) == .fiveMinutes)
        }
    }

    @Test @MainActor
    func testAuthoritativeUnlockedTimeoutOverridesDefaultsSurvivesRenameAndLocksOnAnyChange() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let suite = "clavis.kmvm.timeout.\(UUID().uuidString)"
            let defaults = try #require(UserDefaults(suiteName: suite))
            defer { defaults.removePersistentDomain(forName: suite) }

            let grants = GitSigningGraceManager(observeSystemEvents: false)
            var revokedLabels: [String] = []
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                agentGrantRevoker: { revokedLabels.append($0) },
                gitSigningGraceManager: grants
            )
            let vm = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent, defaults: defaults)

            let key = try vm.generateKey(label: "auth-timeout", keyPurpose: .general, unlockedTimeout: .session)
            defaults.set(KeyGracePeriod.oneMinute.rawValue, forKey: "keyGracePeriod.\(key.fingerprint)")
            #expect(vm.gracePeriod(for: key) == .session, "Authoritative key record must win over stale UserDefaults")

            let renamed = try vm.renameKey(from: "auth-timeout", to: "auth-timeout-renamed")
            #expect(vm.gracePeriod(for: renamed) == .session)

            _ = try keyManager.authorizePersonalSSHGrant(
                key: renamed, prompt: "SSH", approvalIdentity: "app:A", duration: 300
            )
            #expect(!grants.allActivePersonalGrants().isEmpty)
            vm.setGracePeriod(.fifteenMinutes, for: renamed)
            #expect(grants.allActivePersonalGrants().isEmpty, "Changing timeout to non-.always must still revoke active grants")
            #expect(revokedLabels.contains(renamed.label))
        }
    }
}
