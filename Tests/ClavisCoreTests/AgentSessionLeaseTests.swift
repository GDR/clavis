import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("AgentSessionLeaseTests")
struct AgentSessionLeaseTests {
    private let fixture: ClavisTestFixture
    private let auditRecorder: InMemoryAuditRecorder
    private let manager: KeychainManager

    init() throws {
        let fixture = try ClavisTestFixture()
        let audit = InMemoryAuditRecorder()
        let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: audit)
        self.fixture = fixture
        self.auditRecorder = audit
        self.manager = manager
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

    @Test
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
        #expect(lookupActive == .found(session))

        // Advance time past lease
        currentTime = currentTime.addingTimeInterval(61)

        let lookupExpired = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        #expect(lookupExpired == .expired(session))

        let leaseEvent = auditRecorder.events.first { $0.reason == .leaseExpired }
        #expect(leaseEvent != nil)
        #expect(leaseEvent?.type == .sessionEnd)
        #expect(leaseEvent?.sessionID == session.id)
    }

    @Test
    func test_006_AC4_extendRequiresUserPresenceAndMovesExpiry() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-extend-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let authenticator = CountingAuthenticator()
            let policyStore = InMemoryAgentPolicyStore()
            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: auditRecorder,
                watchRootExit: false
            )

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
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
            #expect(regResp.first == 6)
            var reader = DataReader(data: Data(regResp.dropFirst()))
            let sid = reader.readWireString()
            let sessionId = try #require(sid, "Missing session id")

            let initialExpiry = registry.summaries().first?.expiresAt

            // Extend by 30 minutes
            let extPayload = makeExtendPayload(sessionId: sessionId, minutes: 30)
            let extResp = server.processAgentRequest(
                payload: extPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(extResp.first == 6)
            #expect(authenticator.authenticationCount == 1)

            var extReader = DataReader(data: Data(extResp.dropFirst()))
            let newExp = extReader.readUInt32()
            let newExpirySeconds = try #require(newExp, "Missing new expiry")
            let newExpiryDate = Date(timeIntervalSince1970: TimeInterval(newExpirySeconds))
            let currentRegistryExpiry = registry.summaries().first?.expiresAt
            if let current = currentRegistryExpiry {
                #expect(UInt32(current.timeIntervalSince1970) == newExpirySeconds)
            }
            if let initial = initialExpiry {
                #expect(newExpiryDate.timeIntervalSince(initial) > 25 * 60)
            }

            let extendEvent = auditRecorder.events.first { $0.type == .sessionExtend }
            #expect(extendEvent != nil)
            #expect(extendEvent?.result == .allowed)
            #expect(extendEvent?.sessionID == sessionId)
        }
    }

    @Test
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
        #expect(extendedExpiry != nil)
        #expect(extendedExpiry == session.maxExpiresAt)
        #expect(session.expiresAt == session.maxExpiresAt)
    }

    @Test
    func test_006_C1_requestedLeaseIsCapped() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-cap-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let policyStore = InMemoryAgentPolicyStore(
                global: AgentGlobalPolicy(version: 1, maxLeaseMinutes: 300)
            )
            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: auditRecorder,
                watchRootExit: false
            )

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
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
            #expect(regResp.first == 6)
            var reader = DataReader(data: Data(regResp.dropFirst()))
            _ = reader.readWireString()
            let rawLease = reader.readUInt32()
            let leaseSeconds = try #require(rawLease, "Missing leaseSeconds")
            #expect(leaseSeconds == 300 * 60)
        }
    }

    @Test
    func test_006_T2_policyLeaseIsDefault() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-default-lease-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let policyStore = InMemoryAgentPolicyStore()
            let customPolicy = AgentKeyPolicy(leaseMinutes: 180)
            try policyStore.save(customPolicy, forFingerprint: key.fingerprint)

            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: auditRecorder,
                watchRootExit: false
            )

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
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
            #expect(regResp.first == 6)
            var reader = DataReader(data: Data(regResp.dropFirst()))
            _ = reader.readWireString()
            let rawLease = reader.readUInt32()
            let leaseSeconds = try #require(rawLease, "Missing leaseSeconds")
            #expect(leaseSeconds == 180 * 60)
        }
    }
}
