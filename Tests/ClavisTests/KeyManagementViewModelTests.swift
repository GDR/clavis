import XCTest
import Foundation
@testable import ClavisCore
@testable import Clavis

final class KeyManagementViewModelTests: ClavisBaseTestCase {
    private var keyManager: KeychainManager!
    private var mockAgent: MockAgentController!

    override func setUpWithError() throws {
        try super.setUpWithError()
        keyManager = makeKeyManager()
        mockAgent = MockAgentController()
    }

    override func tearDownWithError() throws {
        mockAgent = nil
        keyManager = nil
        try super.tearDownWithError()
    }

    @MainActor
    func testListKeysRefreshesPublishedKeys() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        XCTAssertEqual(viewModel.keys.count, 0)

        _ = try keyManager.generateKey(label: "key-1")
        viewModel.refresh()
        XCTAssertEqual(viewModel.keys.count, 1)
        XCTAssertEqual(viewModel.keys.first?.label, "key-1")
    }

    @MainActor
    func testGenerateKeyCreatesAndRefreshes() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        let created = try viewModel.generateKey(
            label: "generated-key",
            algorithm: "ECDSA P-256",
            keyPurpose: .general
        )

        XCTAssertEqual(created.label, "generated-key")
        XCTAssertEqual(viewModel.keys.count, 1)
        XCTAssertEqual(viewModel.keys.first?.label, "generated-key")
        XCTAssertNil(viewModel.errorMessage)
    }

    @MainActor
    func testDeleteKeyRemovesAndRefreshes() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        _ = try viewModel.generateKey(label: "to-delete")
        XCTAssertEqual(viewModel.keys.count, 1)

        try viewModel.deleteKey(label: "to-delete")
        XCTAssertEqual(viewModel.keys.count, 0)
    }

    @MainActor
    func testChangeKeyKindUpdatesKind() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        _ = try viewModel.generateKey(label: "kind-key", keyPurpose: .general)
        XCTAssertEqual(viewModel.keys.first?.purpose, .general)

        try viewModel.changeKeyKind(label: "kind-key", to: .agent)
        XCTAssertEqual(viewModel.keys.first?.purpose, .agent)

        try viewModel.changeKind(label: "kind-key", to: .general)
        XCTAssertEqual(viewModel.keys.first?.purpose, .general)
    }

    @MainActor
    func testLockKeyLocksKeyAndRefreshes() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        _ = try viewModel.generateKey(label: "lock-key")

        XCTAssertNoThrow(try viewModel.lockKey(label: "lock-key"))
        XCTAssertEqual(viewModel.keys.count, 1)
        XCTAssertNil(viewModel.errorMessage)
    }

    @MainActor
    func testPolicyRoundTripViaAgentControlling() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        let keyPolicy = AgentKeyPolicy(
            mode: .notify,
            leaseMinutes: 60,
            allowedHosts: [],
            burst: 10,
            refillPerMinute: 6
        )

        try viewModel.setAgentPolicy(keyPolicy, fingerprint: "SHA256:abc123")
        XCTAssertEqual(mockAgent.setAgentPolicyCallCount, 1)
        XCTAssertEqual(mockAgent.recordedSetPolicies.first?.target, "SHA256:abc123")

        let retrieved = viewModel.getAgentPolicy(fingerprint: "SHA256:abc123")
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.mode, .notify)
        XCTAssertEqual(retrieved?.leaseMinutes, 60)
        XCTAssertEqual(retrieved?.burst, 10)
        XCTAssertEqual(retrieved?.refillPerMinute, 6)

        let globalPolicy = AgentGlobalPolicy(
            version: 1,
            maxLeaseMinutes: 120
        )
        try viewModel.setGlobalPolicy(globalPolicy)
        XCTAssertEqual(mockAgent.setAgentPolicyCallCount, 2)
        XCTAssertEqual(mockAgent.recordedSetPolicies.last?.target, "global")

        let retrievedGlobal = viewModel.getGlobalPolicy()
        XCTAssertNotNil(retrievedGlobal)
        XCTAssertEqual(retrievedGlobal?.version, 1)
        XCTAssertEqual(retrievedGlobal?.maxLeaseMinutes, 120)
    }

    @MainActor
    func testPolicyValidationFailureThrows() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        let invalidPolicy = AgentKeyPolicy(
            mode: .ask,
            leaseMinutes: -5,
            allowedHosts: [],
            burst: 10,
            refillPerMinute: 6
        )

        XCTAssertThrowsError(try viewModel.setAgentPolicy(invalidPolicy, fingerprint: "SHA256:invalid"))
        XCTAssertEqual(mockAgent.setAgentPolicyCallCount, 0)
    }

    @MainActor
    func testClearError() throws {
        let viewModel = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockAgent)
        viewModel.errorMessage = "Sample error"
        XCTAssertEqual(viewModel.errorMessage, "Sample error")

        viewModel.clearError()
        XCTAssertNil(viewModel.errorMessage)
    }
}
