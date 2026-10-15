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
}
