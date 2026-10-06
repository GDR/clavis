import XCTest
import Darwin
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
}
