import XCTest
import Darwin
import CryptoKit
@testable import ClavisCore

final class AgentSessionProtocolTests: ClavisBaseTestCase {
    private var auditRecorder: InMemoryAuditRecorder!
    private var registry: AgentSessionRegistry!
    private var manager: KeychainManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auditRecorder = InMemoryAuditRecorder()
        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

        registry = AgentSessionRegistry(
            processInfo: { pid in
                if pid == testPid {
                    return (startTime: startTime, parentPid: 1)
                }
                return SSHAgentServer.processParentSnapshot(pid: pid).map { ($0.startTime, $0.parentPid) }
            },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        manager = makeKeyManager(auditRecorder: auditRecorder)
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

    func test_001_T3_registerRefusesUntrustedPeer() throws {
        let key = try manager.generateKey(label: "agent-key-1", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let server = makeServer()
        let payload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)

        let response = server.processAgentRequest(
            payload: payload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { false }
        )
        XCTAssertEqual(response, Data([5]))
    }

    func test_001_T3_registerRefusesPersonalKey() throws {
        let personalKey = try manager.generateKey(label: "personal-key-1", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .general)
        let server = makeServer()
        let payload = makeRegisterPayload(keyLabel: personalKey.label, toolName: "agent-tool", leaseMinutes: 60)

        let response = server.processAgentRequest(
            payload: payload,
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(response, Data([5]))

        XCTAssertTrue(auditRecorder.events.contains { event in
            event.type == .sessionStart && event.result == .denied && event.reason == .wrongKeyKind
        })
    }

    func test_001_T3_leaseIsCapped() throws {
        let key = try manager.generateKey(label: "agent-cap-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let server = makeServer()
        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

        let payload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 5000)
        let response = server.processAgentRequest(
            payload: payload,
            clientPid: testPid,
            clientStartTime: startTime,
            isTrustedControlPeer: { true }
        )

        XCTAssertFalse(response.isEmpty)
        XCTAssertEqual(response[0], 6)
        var reader = DataReader(data: Data(response.dropFirst()))
        let sessionID = reader.readWireString()
        XCTAssertNotNil(sessionID)
        let leaseSeconds = reader.readUInt32()
        XCTAssertEqual(leaseSeconds, 1440 * 60) // Capped at 1440 minutes = 86400 seconds
    }

    func test_001_T3_listAndEndRoundTrip() throws {
        let key = try manager.generateKey(label: "agent-roundtrip-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let server = makeServer()
        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

        // 1. Register session 1
        let p1 = makeRegisterPayload(keyLabel: key.label, toolName: "tool1", leaseMinutes: 10)
        let r1 = server.processAgentRequest(payload: p1, clientPid: testPid, clientStartTime: startTime, isTrustedControlPeer: { true })
        XCTAssertEqual(r1[0], 6)
        var reader1 = DataReader(data: Data(r1.dropFirst()))
        guard let id1 = reader1.readWireString() else { return XCTFail("Missing id1") }

        // 2. Register session 2
        let p2 = makeRegisterPayload(keyLabel: key.label, toolName: "tool2", leaseMinutes: 20)
        let r2 = server.processAgentRequest(payload: p2, clientPid: testPid, clientStartTime: startTime, isTrustedControlPeer: { true })
        XCTAssertEqual(r2[0], 6)
        var reader2 = DataReader(data: Data(r2.dropFirst()))
        guard let id2 = reader2.readWireString() else { return XCTFail("Missing id2") }

        // 3. List sessions
        let listReq = Data([SSHAgentServer.listAgentSessionsRequest])
        let listResp = server.processAgentRequest(payload: listReq, isTrustedControlPeer: { true })
        XCTAssertEqual(listResp[0], 6)
        var listReader = DataReader(data: Data(listResp.dropFirst()))
        let count = listReader.readUInt32()
        XCTAssertEqual(count, 2)

        // 4. End session 1
        var endReq1 = Data([SSHAgentServer.endAgentSessionRequest])
        endReq1.appendWireString(id1)
        let endResp1 = server.processAgentRequest(payload: endReq1, isTrustedControlPeer: { true })
        XCTAssertEqual(endResp1, Data([6]))

        // 5. End session 1 again -> fails (unknown id)
        let endResp1Again = server.processAgentRequest(payload: endReq1, isTrustedControlPeer: { true })
        XCTAssertEqual(endResp1Again, Data([5]))

        // 6. List sessions -> 1 session left
        let listRespAfter = server.processAgentRequest(payload: listReq, isTrustedControlPeer: { true })
        var listReaderAfter = DataReader(data: Data(listRespAfter.dropFirst()))
        XCTAssertEqual(listReaderAfter.readUInt32(), 1)
        let remainingId = listReaderAfter.readWireString()
        XCTAssertEqual(remainingId, id2)

        // 7. Revoke all -> returns 1
        let revokeReq = Data([SSHAgentServer.revokeAllAgentSessionsRequest])
        let revokeResp = server.processAgentRequest(payload: revokeReq, isTrustedControlPeer: { true })
        XCTAssertEqual(revokeResp[0], 6)
        var revokeReader = DataReader(data: Data(revokeResp.dropFirst()))
        XCTAssertEqual(revokeReader.readUInt32(), 1)
    }

    func test_001_T3_malformedPayloadsFail() throws {
        let server = makeServer()

        // Empty payload
        XCTAssertEqual(server.processAgentRequest(payload: Data(), isTrustedControlPeer: { true }), Data([5]))

        // Truncated payload for register (opcode only)
        XCTAssertEqual(
            server.processAgentRequest(payload: Data([SSHAgentServer.registerAgentSessionRequest]), isTrustedControlPeer: { true }),
            Data([5])
        )

        // Trailing bytes in register
        var malformedRegister = makeRegisterPayload(keyLabel: "k", toolName: "t", leaseMinutes: 10)
        malformedRegister.append(Data([0xFF]))
        XCTAssertEqual(
            server.processAgentRequest(payload: malformedRegister, isTrustedControlPeer: { true }),
            Data([5])
        )

        // ToolName empty
        let emptyTool = makeRegisterPayload(keyLabel: "k", toolName: "", leaseMinutes: 10)
        XCTAssertEqual(
            server.processAgentRequest(payload: emptyTool, isTrustedControlPeer: { true }),
            Data([5])
        )

        // ToolName > 256 bytes
        let longTool = makeRegisterPayload(keyLabel: "k", toolName: String(repeating: "a", count: 257), leaseMinutes: 10)
        XCTAssertEqual(
            server.processAgentRequest(payload: longTool, isTrustedControlPeer: { true }),
            Data([5])
        )

        // Trailing bytes in list
        var malformedList = Data([SSHAgentServer.listAgentSessionsRequest])
        malformedList.append(Data([0x01]))
        XCTAssertEqual(server.processAgentRequest(payload: malformedList, isTrustedControlPeer: { true }), Data([5]))

        // Trailing bytes in revoke all
        var malformedRevoke = Data([SSHAgentServer.revokeAllAgentSessionsRequest])
        malformedRevoke.append(Data([0x01]))
        XCTAssertEqual(server.processAgentRequest(payload: malformedRevoke, isTrustedControlPeer: { true }), Data([5]))
    }

    private func makeSignPayload(keyBlob: Data, data: Data) -> Data {
        var p = Data([13])
        p.appendWireData(keyBlob)
        p.appendWireData(data)
        p.appendWireUInt32(0)
        return p
    }

    func test_001_AC1_registeredSessionSignsWithoutPrompt() throws {
        let authenticator = CountingAuthenticator()
        let countingManager = makeKeyManager(authenticator: authenticator, auditRecorder: auditRecorder)
        let key = try countingManager.generateKey(label: "agent-ac1-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)

        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

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
        let regResp = personalServer.processAgentRequest(payload: regPayload, clientPid: testPid, clientStartTime: startTime, isTrustedControlPeer: { true })
        XCTAssertEqual(regResp[0], 6)
        var reader = DataReader(data: Data(regResp.dropFirst()))
        guard let sessionID = reader.readWireString() else { return XCTFail("Missing sessionID") }
        XCTAssertEqual(authenticator.authenticationCount, 1)

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBlob.subdata(in: 19..<51))

        // 2. Sign 3 times via agent socket: 0 prompts
        for i in 1...3 {
            let dataToSign = Data("agent-commit-\(i)".utf8)
            let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: dataToSign)
            let signResp = agentServer.processAgentRequest(
                payload: signReq,
                clientPid: testPid,
                clientStartTime: startTime
            )
            XCTAssertEqual(signResp[0], 14)
            var respReader = DataReader(data: Data(signResp.dropFirst()))
            guard let sigWire = respReader.readWireData() else { return XCTFail("Missing wire sig") }
            var wireReader = DataReader(data: sigWire)
            XCTAssertEqual(wireReader.readWireString(), "ssh-ed25519")
            guard let rawSig = wireReader.readWireData() else { return XCTFail("Missing raw sig") }
            XCTAssertTrue(pubKey.isValidSignature(rawSig, for: dataToSign))
        }

        // Authenticator count is STILL 1
        XCTAssertEqual(authenticator.authenticationCount, 1)

        // Audit events recorded with viaAgentSession and sessionID
        let signEvents = auditRecorder.events.filter { $0.type == .signature && $0.result == .allowed }
        XCTAssertEqual(signEvents.count, 3)
        for ev in signEvents {
            XCTAssertEqual(ev.reason, .viaAgentSession)
            XCTAssertEqual(ev.sessionID, sessionID)
            XCTAssertEqual(ev.keyKind, .agent)
        }
    }

    func test_001_AC2_signWithoutSessionIsDenied() throws {
        let key = try manager.generateKey(label: "agent-ac2-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
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
        XCTAssertEqual(response, Data([5]))

        XCTAssertTrue(auditRecorder.events.contains { ev in
            ev.type == .signature && ev.result == .denied && ev.reason == .noAgentSession
        })
    }

    func test_001_AC3_signFromOutsideTreeIsDenied() throws {
        let key = try manager.generateKey(label: "agent-ac3-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
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
        let startTime = snap?.startTime ?? 1000

        // Register session for rootPid
        let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
        _ = personalServer.processAgentRequest(payload: regPayload, clientPid: rootPid, clientStartTime: startTime, isTrustedControlPeer: { true })

        // Sign from pid 99999 (not in tree)
        let dataToSign = Data("outside".utf8)
        let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: dataToSign)
        let response = agentServer.processAgentRequest(
            payload: signReq,
            clientPid: 99999,
            clientExecutablePath: "/bin/sh",
            clientStartTime: 9999
        )
        XCTAssertEqual(response, Data([5]))

        XCTAssertTrue(auditRecorder.events.contains { ev in
            ev.type == .signature && ev.result == .denied && ev.reason == .outsideSessionTree
        })
    }

    func test_001_AC6_personalKeyOnPersonalSocketStillPrompts() throws {
        let authenticator = CountingAuthenticator()
        let countingManager = makeKeyManager(authenticator: authenticator, auditRecorder: auditRecorder)
        let agentKey = try countingManager.generateKey(label: "agent-ac6-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let personalKey = try countingManager.generateKey(label: "personal-ac6-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .general)

        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

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
        _ = personalServer.processAgentRequest(payload: regPayload, clientPid: testPid, clientStartTime: startTime, isTrustedControlPeer: { true })
        XCTAssertEqual(authenticator.authenticationCount, 1)

        // 2. Personal key sign on personal socket: prompts again! Count becomes 2
        let dataToSign = Data("personal-sign".utf8)
        let signReq = makeSignPayload(keyBlob: personalKey.publicKeyBlob, data: dataToSign)
        let signResp = personalServer.processAgentRequest(
            payload: signReq,
            clientPid: testPid,
            clientStartTime: startTime
        )
        XCTAssertEqual(signResp[0], 14)
        XCTAssertEqual(authenticator.authenticationCount, 2)
    }

    func test_001_C2_everyDecisionIsAudited() throws {
        let key = try manager.generateKey(label: "agent-c2-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let testPid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: testPid)
        let startTime = snap?.startTime ?? 1000

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
        _ = personalServer.processAgentRequest(payload: regPayload, clientPid: testPid, clientStartTime: startTime, isTrustedControlPeer: { true })
        XCTAssertEqual(auditRecorder.events.count, initialCount + 1)

        // 2. Sign via session: exactly +1 event (signature allowed)
        let signReq = makeSignPayload(keyBlob: key.publicKeyBlob, data: Data("msg".utf8))
        _ = agentServer.processAgentRequest(payload: signReq, clientPid: testPid, clientStartTime: startTime)
        XCTAssertEqual(auditRecorder.events.count, initialCount + 2)

        // 3. Denied sign (outside tree): exactly +1 event (signature denied)
        _ = agentServer.processAgentRequest(payload: signReq, clientPid: 99999, clientExecutablePath: "/bin/sh", clientStartTime: 9999)
        XCTAssertEqual(auditRecorder.events.count, initialCount + 3)
    }
}

