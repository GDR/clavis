import XCTest
import LocalAuthentication
@testable import ClavisCore

final class AgentApprovalModeTests: ClavisBaseTestCase {
    private var auditRecorder: InMemoryAuditRecorder!
    private var manager: KeychainManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auditRecorder = InMemoryAuditRecorder()
        manager = makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
    }

    private func makeRegisterPayload(keyLabel: String, toolName: String, leaseMinutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(leaseMinutes)
        return payload
    }

    private func makeSignPayload(publicKeyBlob: Data, dataToSign: Data) -> Data {
        var payload = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        payload.appendWireData(publicKeyBlob)
        payload.appendWireData(dataToSign)
        payload.appendWireUInt32(0) // flags = 0
        return payload
    }

    func test_006_AC1_notifyModeSignsAndPosts() throws {
        let key = try manager.generateKey(label: "agent-notify-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let policyStore = InMemoryAgentPolicyStore()
        try policyStore.save(AgentKeyPolicy(mode: .notify), forFingerprint: key.fingerprint)

        var postedNotifications: [(name: String, userInfo: [String: String])] = []
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore,
            notificationPoster: { name, userInfo in
                postedNotifications.append((name, userInfo))
            }
        )

        // Register session on control server (or directly register with server)
        let regServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
        let regResp = regServer.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Now sign on agent socket
        let dataToSign = Data("test-ssh-data".utf8)
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)
        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000
        )

        XCTAssertEqual(signResp.first, 14) // SSH2_AGENT_SIGN_RESPONSE
        XCTAssertEqual(postedNotifications.count, 1)
        XCTAssertEqual(postedNotifications.first?.name, "com.clavis.agentSigned")
        XCTAssertEqual(postedNotifications.first?.userInfo["fingerprint"], key.fingerprint)

        let signAudit = auditRecorder.events.first { $0.type == .signature && $0.result == .allowed }
        XCTAssertNotNil(signAudit)
        XCTAssertEqual(signAudit?.reason, .viaAgentSession)
    }

    func test_006_AC2_askModePromptsEverySignature() throws {
        let countingAuthenticator = CountingAuthenticator()
        let customManager = makeKeyManager(authenticator: countingAuthenticator, auditRecorder: auditRecorder)
        let key = try customManager.generateKey(label: "agent-ask-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)

        let policyStore = InMemoryAgentPolicyStore()
        try policyStore.save(AgentKeyPolicy(mode: .ask), forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let regServer = SSHAgentServer(
            role: .personal,
            keyManager: customManager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
        let regResp = regServer.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        let initialAuthCount = countingAuthenticator.authenticationCount

        let server = SSHAgentServer(
            role: .agent,
            keyManager: customManager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        // Sign 1
        let signPayload1 = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: Data("payload-1".utf8))
        let signResp1 = server.processAgentRequest(payload: signPayload1, clientPid: getpid(), clientStartTime: 1000)
        XCTAssertEqual(signResp1.first, 14)
        XCTAssertEqual(countingAuthenticator.authenticationCount, initialAuthCount + 1)

        // Sign 2
        let signPayload2 = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: Data("payload-2".utf8))
        let signResp2 = server.processAgentRequest(payload: signPayload2, clientPid: getpid(), clientStartTime: 1000)
        XCTAssertEqual(signResp2.first, 14)
        XCTAssertEqual(countingAuthenticator.authenticationCount, initialAuthCount + 2)

        let signAudits = auditRecorder.events.filter { $0.type == .signature && $0.result == .allowed }
        XCTAssertEqual(signAudits.count, 2)
        XCTAssertEqual(signAudits[0].reason, .viaPrompt)
        XCTAssertEqual(signAudits[1].reason, .viaPrompt)
    }

    struct CancellingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw LAError(.userCancel)
        }
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw LAError(.userCancel)
        }
    }

    func test_006_AC2_askModeCancelDenies() throws {
        let customManager = makeKeyManager(authenticator: CancellingAuthenticator(), auditRecorder: auditRecorder)
        let key = try customManager.generateKey(label: "agent-ask-cancel-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)

        let policyStore = InMemoryAgentPolicyStore()
        try policyStore.save(AgentKeyPolicy(mode: .ask), forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        // Create session directly with frozen policy
        let session = AgentSession(
            id: "session-ask-cancel",
            keyLabel: key.label,
            keyFingerprint: key.fingerprint,
            toolName: "test-tool",
            root: AgentSessionRoot(pid: getpid(), startTime: 1000),
            startedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600),
            maxExpiresAt: Date().addingTimeInterval(1440 * 60),
            policy: AgentKeyPolicy(mode: .ask),
            grant: AgentSessionGrant()
        )
        registry.add(session)

        let server = SSHAgentServer(
            role: .agent,
            keyManager: customManager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: Data("payload-cancel".utf8))
        let signResp = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)

        XCTAssertEqual(signResp, Data([5]))

        let cancelAudit = auditRecorder.events.first { $0.type == .signature && $0.result == .cancelled }
        XCTAssertNotNil(cancelAudit)
        XCTAssertEqual(cancelAudit?.reason, .userCancelled)
    }

    func test_006_D2_policyChangeDoesNotAffectLiveSession() throws {
        let countingAuthenticator = CountingAuthenticator()
        let customManager = makeKeyManager(authenticator: countingAuthenticator, auditRecorder: auditRecorder)
        let key = try customManager.generateKey(label: "agent-freeze-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)

        let policyStore = InMemoryAgentPolicyStore()
        // Policy starts as .none
        try policyStore.save(AgentKeyPolicy(mode: .none), forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let regServer = SSHAgentServer(
            role: .personal,
            keyManager: customManager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        // Start session 1 -> snapshots .none
        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
        let regResp = regServer.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        let server = SSHAgentServer(
            role: .agent,
            keyManager: customManager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        // Now edit policy in store to .ask
        try policyStore.save(AgentKeyPolicy(mode: .ask), forFingerprint: key.fingerprint)

        let initialAuthCount = countingAuthenticator.authenticationCount

        // Sign using the existing live session -> should still use .none (frozen!)
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: Data("payload-live".utf8))
        let signResp = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)

        XCTAssertEqual(signResp.first, 14)
        // No extra auth prompt because the live session policy mode was frozen as .none
        XCTAssertEqual(countingAuthenticator.authenticationCount, initialAuthCount)
    }
}
