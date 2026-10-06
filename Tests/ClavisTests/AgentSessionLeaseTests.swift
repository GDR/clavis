import XCTest
@testable import ClavisCore

final class AgentSessionLeaseTests: ClavisBaseTestCase {
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

    private func makeExtendPayload(sessionId: String, minutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.extendAgentSessionRequest])
        payload.appendWireString(sessionId)
        payload.appendWireUInt32(minutes)
        return payload
    }

    func test_006_AC3_sessionEndsAfterLease() throws {
        var currentTime = Date()
        let registry = AgentSessionRegistry(
            now: { currentTime },
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let session = AgentSession(
            id: "session-lease-test-1",
            keyLabel: "test-agent-key",
            keyFingerprint: "SHA256:fingerprint-lease",
            toolName: "test-tool",
            root: AgentSessionRoot(pid: 100, startTime: 1000),
            startedAt: currentTime,
            expiresAt: currentTime.addingTimeInterval(60),
            maxExpiresAt: currentTime.addingTimeInterval(1440 * 60),
            grant: AgentSessionGrant()
        )
        registry.add(session)

        // Still active
        let lookupActive = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        XCTAssertEqual(lookupActive, .found(session))

        // Advance time past lease
        currentTime = currentTime.addingTimeInterval(61)

        let lookupExpired = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        XCTAssertEqual(lookupExpired, .expired(session))

        let leaseEvent = auditRecorder.events.first { $0.reason == .leaseExpired }
        XCTAssertNotNil(leaseEvent)
        XCTAssertEqual(leaseEvent?.type, .sessionEnd)
        XCTAssertEqual(leaseEvent?.sessionID, session.id)
    }

    func test_006_AC4_extendRequiresUserPresenceAndMovesExpiry() throws {
        let key = try manager.generateKey(label: "agent-extend-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let authenticator = CountingAuthenticator()
        let policyStore = InMemoryAgentPolicyStore()
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let server = SSHAgentServer(
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore,
            authenticator: authenticator
        )

        // Register session with 60 min lease
        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
        let regResp = server.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)
        var reader = DataReader(data: Data(regResp.dropFirst()))
        guard let sessionId = reader.readWireString() else {
            XCTFail("Missing session id")
            return
        }

        let initialExpiry = registry.summaries().first?.expiresAt

        // Extend by 30 minutes
        let extPayload = makeExtendPayload(sessionId: sessionId, minutes: 30)
        let extResp = server.processAgentRequest(
            payload: extPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(extResp.first, 6)
        XCTAssertEqual(authenticator.authenticationCount, 1)

        var extReader = DataReader(data: Data(extResp.dropFirst()))
        guard let newExpirySeconds = extReader.readUInt32() else {
            XCTFail("Missing new expiry")
            return
        }
        let newExpiryDate = Date(timeIntervalSince1970: TimeInterval(newExpirySeconds))
        let currentRegistryExpiry = registry.summaries().first?.expiresAt
        if let current = currentRegistryExpiry {
            XCTAssertEqual(UInt32(current.timeIntervalSince1970), newExpirySeconds)
        }
        if let initial = initialExpiry {
            XCTAssertGreaterThan(newExpiryDate.timeIntervalSince(initial), 25 * 60)
        }

        let extendEvent = auditRecorder.events.first { $0.type == .sessionExtend }
        XCTAssertNotNil(extendEvent)
        XCTAssertEqual(extendEvent?.result, .allowed)
        XCTAssertEqual(extendEvent?.sessionID, sessionId)
    }

    func test_006_C1_extendCannotExceedGlobalMax() throws {
        let currentTime = Date()
        let globalMaxMinutes = 120
        let registry = AgentSessionRegistry(
            now: { currentTime },
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let session = AgentSession(
            id: "session-max-cap-test",
            keyLabel: "test-agent-key",
            keyFingerprint: "SHA256:fingerprint-max",
            toolName: "test-tool",
            root: AgentSessionRoot(pid: 100, startTime: 1000),
            startedAt: currentTime,
            expiresAt: currentTime.addingTimeInterval(60 * 60),
            maxExpiresAt: currentTime.addingTimeInterval(Double(globalMaxMinutes * 60)),
            grant: AgentSessionGrant()
        )
        registry.add(session)

        // Try to extend by 1000 minutes (should cap at maxExpiresAt)
        let extendedExpiry = registry.extend(id: session.id, by: 1000)
        XCTAssertNotNil(extendedExpiry)
        XCTAssertEqual(extendedExpiry, session.maxExpiresAt)
        XCTAssertEqual(session.expiresAt, session.maxExpiresAt)
    }

    func test_006_C1_requestedLeaseIsCapped() throws {
        let key = try manager.generateKey(label: "agent-cap-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let policyStore = InMemoryAgentPolicyStore(
            global: AgentGlobalPolicy(version: 1, maxLeaseMinutes: 300)
        )
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let server = SSHAgentServer(
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        // Request 1000 minutes, but global max is 300
        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 1000)
        let regResp = server.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)
        var reader = DataReader(data: Data(regResp.dropFirst()))
        _ = reader.readWireString()
        guard let leaseSeconds = reader.readUInt32() else {
            XCTFail("Missing leaseSeconds")
            return
        }
        XCTAssertEqual(leaseSeconds, 300 * 60)
    }

    func test_006_T2_policyLeaseIsDefault() throws {
        let key = try manager.generateKey(label: "agent-default-lease-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let policyStore = InMemoryAgentPolicyStore()
        let customPolicy = AgentKeyPolicy(leaseMinutes: 180)
        try policyStore.save(customPolicy, forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )

        let server = SSHAgentServer(
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        // Request 0 minutes -> should use policy default (180 min)
        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 0)
        let regResp = server.processAgentRequest(
            payload: regPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)
        var reader = DataReader(data: Data(regResp.dropFirst()))
        _ = reader.readWireString()
        guard let leaseSeconds = reader.readUInt32() else {
            XCTFail("Missing leaseSeconds")
            return
        }
        XCTAssertEqual(leaseSeconds, 180 * 60)
    }
}
