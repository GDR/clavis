import Testing
import Darwin
import CryptoKit
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("AgentSessionProtocolTests")
struct AgentSessionProtocolTests {
    private let fixture: ClavisTestFixture
    private let auditRecorder: InMemoryAuditRecorder
    private let registry: AgentSessionRegistry
    private let manager: KeychainManager
    private let testPid: Int32
    private let startTime: UInt64

    init() throws {
        self.fixture = try ClavisTestFixture()
        let recorder = InMemoryAuditRecorder()
        self.auditRecorder = recorder
        let pid = getpid()
        self.testPid = pid
        let snap = SSHAgentServer.processParentSnapshot(pid: pid)
        let st = snap?.startTime ?? 1000
        self.startTime = st

        self.registry = AgentSessionRegistry(
            processInfo: { p in
                if p == pid {
                    return (startTime: st, parentPid: 1)
                }
                return SSHAgentServer.processParentSnapshot(pid: p).map { ($0.startTime, $0.parentPid) }
            },
            auditRecorder: recorder,
            watchRootExit: false
        )
        self.manager = fixture.makeKeyManager(auditRecorder: recorder)
    }

    private func makeServer(controlPeerValidator: @escaping (Int32) -> Bool = { _ in true }) -> SSHAgentServer {
        SSHAgentServer(
            keyManager: manager,
            controlPeerValidator: controlPeerValidator,
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry
        )
    }

    private func makeRegisterPayload(keyLabel: String, toolName: String, leaseMinutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(leaseMinutes)
        return payload
    }

    private func makeSignPayload(keyBlob: Data, data: Data) -> Data {
        var p = Data([13])
        p.appendWireData(keyBlob)
        p.appendWireData(data)
        p.appendWireUInt32(0)
        return p
    }

    @Test
    func test_001_T3_registerRefusesUntrustedPeer() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-key-1", biometricPolicy: .userPresence, keyPurpose: .agent)
            let server = makeServer()
            let payload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)

            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { false }
            )
            #expect(response == Data([5]))
        }
    }

    @Test
    func test_001_T3_registerRefusesPersonalKey() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let personalKey = try manager.generateKey(label: "personal-key-1", biometricPolicy: .userPresence, keyPurpose: .general)
            let server = makeServer()
            let payload = makeRegisterPayload(keyLabel: personalKey.label, toolName: "agent-tool", leaseMinutes: 60)

            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(response == Data([5]))

            #expect(auditRecorder.events.contains { event in
                event.type == .sessionStart && event.result == .denied && event.reason == .wrongKeyKind
            })
        }
    }

    @Test
    func test_001_T3_leaseIsCapped() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-cap-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let server = makeServer()
            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let payload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 5000)
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: currentPid,
                clientStartTime: currentStartTime,
                isTrustedControlPeer: { true }
            )

            #expect(!response.isEmpty)
            #expect(response[0] == 6)
            var reader = DataReader(data: Data(response.dropFirst()))
            let sessionID = reader.readWireString()
            #expect(sessionID != nil)
            let leaseSeconds = reader.readUInt32()
            #expect(leaseSeconds == UInt32(1440 * 60)) // Capped at 1440 minutes = 86400 seconds
        }
    }

    @Test
    func test_001_T3_listAndEndRoundTrip() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-roundtrip-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let server = makeServer()
            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            // 1. Register session 1
            let p1 = makeRegisterPayload(keyLabel: key.label, toolName: "tool1", leaseMinutes: 10)
            let r1 = server.processAgentRequest(payload: p1, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(r1[0] == 6)
            var reader1 = DataReader(data: Data(r1.dropFirst()))
            let rawId1 = reader1.readWireString()
            let id1 = try #require(rawId1, "Missing id1")

            // 2. Register session 2
            let p2 = makeRegisterPayload(keyLabel: key.label, toolName: "tool2", leaseMinutes: 20)
            let r2 = server.processAgentRequest(payload: p2, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(r2[0] == 6)
            var reader2 = DataReader(data: Data(r2.dropFirst()))
            let rawId2 = reader2.readWireString()
            let id2 = try #require(rawId2, "Missing id2")

            // 3. List sessions
            let listReq = Data([SSHAgentServer.listAgentSessionsRequest])
            let listResp = server.processAgentRequest(payload: listReq, isTrustedControlPeer: { true })
            #expect(listResp[0] == 6)
            var listReader = DataReader(data: Data(listResp.dropFirst()))
            let count = listReader.readUInt32()
            #expect(count == 2)

            // 4. End session 1
            var endReq1 = Data([SSHAgentServer.endAgentSessionRequest])
            endReq1.appendWireString(id1)
            let endResp1 = server.processAgentRequest(payload: endReq1, isTrustedControlPeer: { true })
            #expect(endResp1 == Data([6]))

            // 5. End session 1 again -> fails (unknown id)
            let endResp1Again = server.processAgentRequest(payload: endReq1, isTrustedControlPeer: { true })
            #expect(endResp1Again == Data([5]))

            // 6. List sessions -> 1 session left
            let listRespAfter = server.processAgentRequest(payload: listReq, isTrustedControlPeer: { true })
            var listReaderAfter = DataReader(data: Data(listRespAfter.dropFirst()))
            #expect(listReaderAfter.readUInt32() == 1)
            let remainingId = listReaderAfter.readWireString()
            #expect(remainingId == id2)

            // 7. Revoke all -> returns 1
            let revokeReq = Data([SSHAgentServer.revokeAllAgentSessionsRequest])
            let revokeResp = server.processAgentRequest(payload: revokeReq, isTrustedControlPeer: { true })
            #expect(revokeResp[0] == 6)
            var revokeReader = DataReader(data: Data(revokeResp.dropFirst()))
            #expect(revokeReader.readUInt32() == 1)
        }
    }

    @Test
    func test_001_T3_malformedPayloadsFail() async {
        defer { fixture.cleanup() }
        await fixture.run {
            let server = makeServer()

            // Empty payload
            #expect(server.processAgentRequest(payload: Data(), isTrustedControlPeer: { true }) == Data([5]))

            // Truncated payload for register (opcode only)
            #expect(
                server.processAgentRequest(payload: Data([SSHAgentServer.registerAgentSessionRequest]), isTrustedControlPeer: { true }) == Data([5])
            )

            // Trailing bytes in register
            var malformedRegister = makeRegisterPayload(keyLabel: "k", toolName: "t", leaseMinutes: 10)
            malformedRegister.append(Data([0xFF]))
            #expect(
                server.processAgentRequest(payload: malformedRegister, isTrustedControlPeer: { true }) == Data([5])
            )

            // ToolName empty
            let emptyTool = makeRegisterPayload(keyLabel: "k", toolName: "", leaseMinutes: 10)
            #expect(
                server.processAgentRequest(payload: emptyTool, isTrustedControlPeer: { true }) == Data([5])
            )

            // ToolName > 256 bytes
            let longTool = makeRegisterPayload(keyLabel: "k", toolName: String(repeating: "a", count: 257), leaseMinutes: 10)
            #expect(
                server.processAgentRequest(payload: longTool, isTrustedControlPeer: { true }) == Data([5])
            )

            // Trailing bytes in list
            var malformedList = Data([SSHAgentServer.listAgentSessionsRequest])
            malformedList.append(Data([0x01]))
            #expect(server.processAgentRequest(payload: malformedList, isTrustedControlPeer: { true }) == Data([5]))

            // Trailing bytes in revoke all
            var malformedRevoke = Data([SSHAgentServer.revokeAllAgentSessionsRequest])
            malformedRevoke.append(Data([0x01]))
            #expect(server.processAgentRequest(payload: malformedRevoke, isTrustedControlPeer: { true }) == Data([5]))
        }
    }

    @Test
    func test_001_AC1_registeredSessionSignsWithoutPrompt() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = CountingAuthenticator()
            let countingManager = fixture.makeKeyManager(authenticator: authenticator, auditRecorder: auditRecorder)
            let key = try countingManager.generateKey(label: "agent-ac1-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: countingManager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )
            let agentServer = SSHAgentServer(
                role: .agent,
                keyManager: countingManager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            // 1. Register session: 1 prompt
            let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            let regResp = personalServer.processAgentRequest(payload: regPayload, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(regResp[0] == 6)
            var reader = DataReader(data: Data(regResp.dropFirst()))
            let rawSessionID = reader.readWireString()
            let sessionID = try #require(rawSessionID, "Missing sessionID")
            #expect(authenticator.authenticationCount == 1)

            // 2. Sign 3 times via agent socket: 0 prompts
            for i in 1...3 {
                let dataToSign = Data("agent-commit-\(i)".utf8)
                let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: dataToSign)
                let signResp = agentServer.processAgentRequest(
                    payload: signReq,
                    clientPid: currentPid,
                    clientStartTime: currentStartTime
                )
                #expect(signResp[0] == 14)
                var respReader = DataReader(data: Data(signResp.dropFirst()))
                let rawSigWire = respReader.readWireData()
                let sigWire = try #require(rawSigWire, "Missing wire sig")
                var wireReader = DataReader(data: sigWire)
                #expect(wireReader.readWireString() == "ecdsa-sha2-nistp256")
                let rawSigData = wireReader.readWireData()
                let rawSig = try #require(rawSigData, "Missing raw sig")
                #expect(rawSig.count > 64)
            }

            // Authenticator count is STILL 1
            #expect(authenticator.authenticationCount == 1)

            // Audit events recorded with viaAgentSession and sessionID
            let signEvents = auditRecorder.events.filter { $0.type == .signature && $0.result == .allowed }
            #expect(signEvents.count == 3)
            for ev in signEvents {
                #expect(ev.reason == .viaAgentSession)
                #expect(ev.sessionID == sessionID)
                #expect(ev.keyKind == .agent)
            }
        }
    }

    @Test
    func test_001_AC2_signWithoutSessionIsDenied() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-ac2-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let agentServer = SSHAgentServer(
                role: .agent,
                keyManager: manager,
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let dataToSign = Data("test".utf8)
            let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: dataToSign)
            let response = agentServer.processAgentRequest(
                payload: signReq,
                clientPid: getpid(),
                clientStartTime: 1000
            )
            #expect(response == Data([5]))

            #expect(auditRecorder.events.contains { ev in
                ev.type == .signature && ev.result == .denied && ev.reason == .noAgentSession
            })
        }
    }

    @Test
    func test_001_AC3_signFromOutsideTreeIsDenied() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-ac3-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )
            let agentServer = SSHAgentServer(
                role: .agent,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let rootPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: rootPid)
            let currentStartTime = snap?.startTime ?? 1000

            // Register session for rootPid
            let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayload, clientPid: rootPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })

            // Sign from pid 99999 (not in tree)
            let dataToSign = Data("outside".utf8)
            let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: dataToSign)
            let response = agentServer.processAgentRequest(
                payload: signReq,
                clientPid: 99999,
                clientExecutablePath: "/bin/sh",
                clientStartTime: 9999
            )
            #expect(response == Data([5]))

            #expect(auditRecorder.events.contains { ev in
                ev.type == .signature && ev.result == .denied && ev.reason == .outsideSessionTree
            })
        }
    }

    @Test
    func test_001_AC6_personalKeyOnPersonalSocketStillPrompts() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = CountingAuthenticator()
            let countingManager = fixture.makeKeyManager(authenticator: authenticator, auditRecorder: auditRecorder)
            let agentKey = try countingManager.generateKey(label: "agent-ac6-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let personalKey = try countingManager.generateKey(label: "personal-ac6-key", biometricPolicy: .userPresence, keyPurpose: .general)

            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: countingManager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            // 1. Register agent session: count becomes 1
            let regPayload = makeRegisterPayload(keyLabel: agentKey.label, toolName: "agent-tool", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayload, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(authenticator.authenticationCount == 1)

            // 2. Personal key sign on personal socket: prompts again! Count becomes 2
            let dataToSign = Data("personal-sign".utf8)
            let signReq = makeSignPayload(keyBlob: personalKey.publicKeyBlob, data: dataToSign)
            let signResp = personalServer.processAgentRequest(
                payload: signReq,
                clientPid: currentPid,
                clientStartTime: currentStartTime
            )
            #expect(signResp[0] == 14)
            #expect(authenticator.authenticationCount == 2)
        }
    }

    @Test
    func test_001_C2_everyDecisionIsAudited() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-c2-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )
            let agentServer = SSHAgentServer(
                role: .agent,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let initialCount = auditRecorder.events.count

            // 1. Register: exactly +1 event (sessionStart)
            let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayload, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(auditRecorder.events.count == initialCount + 1)

            // 2. Sign via session: exactly +1 event (signature allowed)
            let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: Data("msg".utf8))
            _ = agentServer.processAgentRequest(payload: signReq, clientPid: currentPid, clientStartTime: currentStartTime)
            #expect(auditRecorder.events.count == initialCount + 2)

            // 3. Denied sign (outside tree): exactly +1 event (signature denied)
            _ = agentServer.processAgentRequest(payload: signReq, clientPid: 99999, clientExecutablePath: "/bin/sh", clientStartTime: 9999)
            #expect(auditRecorder.events.count == initialCount + 3)
        }
    }

    @Test
    func test_001_T4_lockAllEndsSessions() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-lockall-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayload, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })
            #expect(registry.count == 1)

            // Send lockAllRequest (242)
            let response = personalServer.processAgentRequest(
                payload: Data([242]),
                clientPid: currentPid,
                clientStartTime: currentStartTime,
                isTrustedControlPeer: { true }
            )
            #expect(response == Data([6]))
            #expect(registry.count == 0)
            #expect(auditRecorder.events.contains { $0.type == .sessionEnd && $0.reason == .lockAll })
        }
    }

    @Test
    func test_001_T4_invalidateKeyEndsSessionsForKey() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyA = try manager.generateKey(label: "agent-key-a", biometricPolicy: .userPresence, keyPurpose: .agent)
            let keyB = try manager.generateKey(label: "agent-key-b", biometricPolicy: .userPresence, keyPurpose: .agent)

            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let regPayloadA = makeRegisterPayload(keyLabel: keyA.label, toolName: "tool-a", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayloadA, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })

            let regPayloadB = makeRegisterPayload(keyLabel: keyB.label, toolName: "tool-b", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayloadB, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })

            #expect(registry.count == 2)

            // Invalidate key A (opcode 240)
            var invPayload = Data([240])
            invPayload.appendWireString(keyA.label)
            let response = personalServer.processAgentRequest(
                payload: invPayload,
                clientPid: currentPid,
                clientStartTime: currentStartTime,
                isTrustedControlPeer: { true }
            )
            #expect(response == Data([6]))
            #expect(registry.count == 1)
            #expect(auditRecorder.events.contains { $0.type == .sessionEnd && $0.reason == .keyChanged })
            #expect(registry.summaries().first?.keyLabel == keyB.label)
        }
    }

    @Test
    func test_001_T4_revokeAllReportsCount() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyA = try manager.generateKey(label: "agent-rev-a", biometricPolicy: .userPresence, keyPurpose: .agent)
            let keyB = try manager.generateKey(label: "agent-rev-b", biometricPolicy: .userPresence, keyPurpose: .agent)

            let personalServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )

            let currentPid = getpid()
            let snap = SSHAgentServer.processParentSnapshot(pid: currentPid)
            let currentStartTime = snap?.startTime ?? 1000

            let regPayloadA = makeRegisterPayload(keyLabel: keyA.label, toolName: "tool-a", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayloadA, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })

            let regPayloadB = makeRegisterPayload(keyLabel: keyB.label, toolName: "tool-b", leaseMinutes: 60)
            _ = personalServer.processAgentRequest(payload: regPayloadB, clientPid: currentPid, clientStartTime: currentStartTime, isTrustedControlPeer: { true })

            #expect(registry.count == 2)

            // Revoke all (opcode 246)
            let response = personalServer.processAgentRequest(
                payload: Data([246]),
                clientPid: currentPid,
                clientStartTime: currentStartTime,
                isTrustedControlPeer: { true }
            )
            #expect(response[0] == 6)
            var reader = DataReader(data: Data(response.dropFirst()))
            let endedCount = reader.readUInt32()
            #expect(endedCount == 2)
            #expect(registry.count == 0)
            let revokeEvents = auditRecorder.events.filter { $0.type == .sessionRevoke && $0.reason == .revokedByUser }
            #expect(revokeEvents.count == 2)
        }
    }

    @Test
    func test_001_T5_lifecycleManagerRoundTrip() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-lifecycle-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let sockPath = fixture.testRootURL.appendingPathComponent("lifecycle.sock").path
            let server = SSHAgentServer(
                socketPath: sockPath,
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry
            )
            try server.start()
            defer { server.stop() }

            let lifecycle = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })

            let session = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "my-tool", leaseMinutes: 30)
            #expect(!session.id.isEmpty)
            #expect(session.leaseSeconds == 1800)

            let list = lifecycle.listAgentSessions()
            #expect(list.count == 1)
            #expect(list.first?.id == session.id)
            #expect(list.first?.keyLabel == key.label)
            #expect(list.first?.toolName == "my-tool")

            let ended = lifecycle.endAgentSession(id: session.id)
            #expect(ended)
            #expect(lifecycle.listAgentSessions().count == 0)

            _ = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-2", leaseMinutes: 10)
            #expect(lifecycle.listAgentSessions().count == 1)
            let revoked = lifecycle.revokeAllAgentSessions()
            #expect(revoked == 1)
            #expect(lifecycle.listAgentSessions().count == 0)
        }
    }
}
