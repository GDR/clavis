import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class SSHAgentServerTests: ClavisBaseTestCase {
    func testAuthenticationReasonsFitSystemPromptGrammar() {
        XCTAssertEqual(
            SSHAgentServer.sshAuthenticationReason(keyLabel: "Main Key"),
            "use \u{201c}Main Key\u{201d} for SSH authentication"
        )
        XCTAssertEqual(
            SSHAgentServer.gitCommitSigningReason(keyLabel: "Main Key"),
            "sign a Git commit with \u{201c}Main Key\u{201d}"
        )
        XCTAssertEqual(
            SSHAgentServer.gitSigningSessionReason(keyLabel: "Main Key"),
            "authorize a 5-minute Git signing session with \u{201c}Main Key\u{201d}"
        )
    }

    func testOwnerControlRequestRevokesPerKeyGitGrant() throws {
        let label = "revoke-\(UUID().uuidString)"
        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        defer { GitSigningGraceManager.shared.invalidateAll(broadcast: false) }
        _ = GitSigningGraceManager.shared.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            context: LAContext()
        )
        XCTAssertNotNil(GitSigningGraceManager.shared.getValidGrant(for: label))

        var request = Data([SSHAgentServer.invalidateKeyRequest])
        request.appendWireString(label)
        let response = SSHAgentServer(keyManager: makeKeyManager()).processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/Applications/Clavis.app/Contents/MacOS/Clavis",
            isTrustedControlPeer: { true }
        )

        XCTAssertEqual(response, Data([6]))
        XCTAssertNil(GitSigningGraceManager.shared.getValidGrant(for: label))
    }

    func testControlOpcodesAreRefusedForUntrustedPeers() throws {
        let label = "untrusted-\(UUID().uuidString)"
        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        defer { GitSigningGraceManager.shared.invalidateAll(broadcast: false) }
        _ = GitSigningGraceManager.shared.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            context: LAContext()
        )
        let server = SSHAgentServer(keyManager: makeKeyManager())

        var invalidate = Data([SSHAgentServer.invalidateKeyRequest])
        invalidate.appendWireString(label)
        let requests = [invalidate, Data([SSHAgentServer.queryGitGraceRequest]), Data([SSHAgentServer.lockAllRequest])]
        for request in requests {
            // Default (no trust callback) and an explicit "untrusted" peer are both refused.
            XCTAssertEqual(server.processAgentRequest(payload: request), Data([5]))
            XCTAssertEqual(server.processAgentRequest(payload: request, isTrustedControlPeer: { false }), Data([5]))
        }
        XCTAssertNotNil(GitSigningGraceManager.shared.getValidGrant(for: label),
                        "A refused control request must not revoke or reveal the grant")
    }

    func testTrustCallbackIsNotEvaluatedForStandardAgentMessages() {
        let server = SSHAgentServer(keyManager: makeKeyManager())
        var evaluated = false
        _ = server.processAgentRequest(payload: Data([11]), isTrustedControlPeer: { evaluated = true; return true })
        XCTAssertFalse(evaluated)
    }

    func testControlOpcodeOverRealSocketIsRefusedForNonClavisPeer() throws {
        let socketPath = testRootURL.appendingPathComponent("control.sock").path
        let server = SSHAgentServer(socketPath: socketPath, keyManager: makeKeyManager())
        try server.start()
        defer { server.stop() }

        let fd = try connectUnixSocket(path: socketPath)
        defer { close(fd) }
        var packet = Data()
        packet.appendWireUInt32(1)
        packet.append(SSHAgentServer.lockAllRequest)
        XCTAssertEqual(packet.withUnsafeBytes { write(fd, $0.baseAddress, packet.count) }, packet.count)

        var header = [UInt8](repeating: 0, count: 5)
        var received = 0
        while received < header.count {
            let n = read(fd, &header[received], header.count - received)
            if n <= 0 { break }
            received += n
        }
        // The xctest runner is not a Clavis-signed binary, so the request must be refused.
        XCTAssertEqual(header, [0, 0, 0, 1, 5])
    }


    func testSSHAgentServerLifecycle() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-unittest.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)

        XCTAssertFalse(server.isSocketActive)
        try server.start()
        XCTAssertTrue(server.isSocketActive)
        XCTAssertTrue(FileManager.default.fileExists(atPath: testSockPath))

        // Verify socket permissions are restricted to 0600
        let attrs = try FileManager.default.attributesOfItem(atPath: testSockPath)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(perms, 0o600)

        server.stop()
        XCTAssertFalse(server.isSocketActive)
    }


    func testSSHAgentServerBoundsIdleClients() throws {
        let socketPath = testRootURL.appendingPathComponent("clavis-client-limit.sock").path
        let server = SSHAgentServer(
            socketPath: socketPath,
            maxConcurrentClients: 1,
            clientIdleTimeout: 0.2
        )
        try server.start()
        defer { server.stop() }

        let idleClient = try connectUnixSocket(path: socketPath)
        defer { close(idleClient) }

        let acceptanceDeadline = Date().addingTimeInterval(1)
        while server.activeClientCount != 1 && Date() < acceptanceDeadline {
            usleep(10_000)
        }
        XCTAssertEqual(server.activeClientCount, 1)

        let rejectedClient = try connectUnixSocket(path: socketPath)
        defer { close(rejectedClient) }
        usleep(50_000)
        XCTAssertNil(socketReadFullBytes(from: rejectedClient, count: 1))

        let timeoutDeadline = Date().addingTimeInterval(1)
        while server.activeClientCount != 0 && Date() < timeoutDeadline {
            usleep(10_000)
        }
        XCTAssertEqual(server.activeClientCount, 0)
    }


    func testSSHAgentServerRequestIdentitiesSocket() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-req-ident.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)
        try server.start()
        defer { server.stop() }

        let clientSock = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientSock, 0)
        defer { close(clientSock) }

        var nosigpipe = 1
        setsockopt(clientSock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)

        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSock, $0, addrLen)
            }
        }
        XCTAssertEqual(connectResult, 0)

        // SSH2_AGENTC_REQUEST_IDENTITIES packet: 4 bytes len (1), 1 byte msg (11)
        let request = Data([0x00, 0x00, 0x00, 0x01, 11])
        _ = request.withUnsafeBytes { write(clientSock, $0.baseAddress!, request.count) }

        // Read response header (4 bytes len)
        guard let lenData = socketReadFullBytes(from: clientSock, count: 4) else {
            XCTFail("Failed to read length header from agent socket")
            return
        }
        var respLenVal: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
        let respLen = Int(UInt32(bigEndian: respLenVal))
        XCTAssertGreaterThan(respLen, 0)

        guard let payload = socketReadFullBytes(from: clientSock, count: respLen) else {
            XCTFail("Failed to read response payload from agent socket")
            return
        }

        XCTAssertGreaterThanOrEqual(payload.count, 5)
        XCTAssertEqual(payload[0], 12) // SSH2_AGENT_IDENTITIES_ANSWER
    }


    func testSSHAgentServerSignRequestMissingFlags() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-sign-req.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)
        try server.start()
        defer { server.stop() }

        let clientSock = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientSock, 0)
        defer { close(clientSock) }

        var nosigpipe = 1
        setsockopt(clientSock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)

        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSock, $0, addrLen)
            }
        }
        XCTAssertEqual(connectResult, 0)

        // SSH2_AGENTC_SIGN_REQUEST packet missing 4-byte flags
        var payloadData = Data([13]) // msg 13
        payloadData.appendWireData(Data("keyblob".utf8))
        payloadData.appendWireData(Data("datatosign".utf8))
        // Omitting 4-byte flags intentionally

        var packet = Data()
        var len = UInt32(payloadData.count).bigEndian
        Swift.withUnsafeBytes(of: &len) { packet.append(contentsOf: $0) }
        packet.append(payloadData)

        _ = packet.withUnsafeBytes { write(clientSock, $0.baseAddress!, packet.count) }

        guard let lenData = socketReadFullBytes(from: clientSock, count: 4) else {
            XCTFail("Failed to read length header from agent socket")
            return
        }
        var respLenVal: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
        let respLen = Int(UInt32(bigEndian: respLenVal))
        XCTAssertEqual(respLen, 1)

        guard let responsePayload = socketReadFullBytes(from: clientSock, count: respLen) else {
            XCTFail("Failed to read response payload from agent socket")
            return
        }

        XCTAssertEqual(responsePayload[0], 5) // SSH_AGENT_FAILURE
    }


    func testSSHAgentServerRequestIdentities() throws {
        let server = SSHAgentServer()
        let requestPayload = Data([11]) // SSH2_AGENTC_REQUEST_IDENTITIES
        let response = server.processAgentRequest(payload: requestPayload)

        XCTAssertFalse(response.isEmpty)
        XCTAssertEqual(response[0], 12) // SSH2_AGENT_IDENTITIES_ANSWER

        // Key count is 4 bytes big endian starting at index 1
        XCTAssertGreaterThanOrEqual(response.count, 5)
        let keyCount = response.subdata(in: 1..<5).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        XCTAssertGreaterThanOrEqual(keyCount, 0)
    }


    func testSSHAgentServerSignRequestParsing() throws {
        let server = SSHAgentServer()

        // 1. Invalid payload: empty or unknown msg type
        XCTAssertEqual(server.processAgentRequest(payload: Data()), Data([5]))
        XCTAssertEqual(server.processAgentRequest(payload: Data([99])), Data([5]))

        // 2. Msg type 13 with truncated payload (missing flags)
        var truncatedPayload = Data([13])
        truncatedPayload.appendWireString("fake-key-blob")
        truncatedPayload.appendWireString("data-to-sign")
        // Missing 4-byte flags parameter
        XCTAssertEqual(server.processAgentRequest(payload: truncatedPayload), Data([5]))

        // 3. Msg type 13 with valid wire framing and flags but non-existent keyBlob
        var validFramedPayload = Data([13])
        validFramedPayload.appendWireString("non-existent-key-blob")
        validFramedPayload.appendWireString("hello world")
        var flags: UInt32 = 0
        Swift.withUnsafeBytes(of: &flags) { validFramedPayload.append(contentsOf: $0) }
        XCTAssertEqual(server.processAgentRequest(payload: validFramedPayload), Data([5]))

        XCTAssertEqual(
            server.processAgentRequest(payload: Data([11, 0x00])),
            Data([5]),
            "Identities requests with trailing bytes must be rejected"
        )

        var unsupportedFlagsPayload = Data([13])
        unsupportedFlagsPayload.appendWireString("non-existent-key-blob")
        unsupportedFlagsPayload.appendWireString("hello world")
        var unsupportedFlags = UInt32(1).bigEndian
        Swift.withUnsafeBytes(of: &unsupportedFlags) { unsupportedFlagsPayload.append(contentsOf: $0) }
        XCTAssertEqual(server.processAgentRequest(payload: unsupportedFlagsPayload), Data([5]))

        var trailingPayload = validFramedPayload
        trailingPayload.append(0x00)
        XCTAssertEqual(server.processAgentRequest(payload: trailingPayload), Data([5]))
    }


    func testSSHSigningCanRequirePerRequestAuthentication() throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .oneHour
        let authenticator = CountingAuthenticator()
        let keyManager = makeKeyManager(sessionCache: cache, authenticator: authenticator)
        let label = "ssh-single-shot-\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }
        let keyInfo = try keyManager.generateKey(label: label)
        let payload = Data("ssh challenge".utf8)

        _ = try keyManager.signSSH(
            key: keyInfo,
            data: payload,
            prompt: "First request",
            useCache: false
        )
        _ = try keyManager.signSSH(
            key: keyInfo,
            data: payload,
            prompt: "Second request",
            useCache: false
        )

        XCTAssertEqual(authenticator.authenticationCount, 2)
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSSHClientAttributionUsesExecutablePath() {
        let path = SSHAgentServer.getProcessPath(pid: getpid())
        XCTAssertNotNil(path)
        XCTAssertTrue(path?.hasPrefix("/") == true)
        XCTAssertEqual(
            SSHAgentServer.getProcessName(pid: getpid()),
            path.map { ($0 as NSString).lastPathComponent }
        )
    }

    func testSSHAgentServerPerPIDClientLimit() {
        let server = SSHAgentServer(
            maxConcurrentClients: 10,
            maxConcurrentClientsPerPID: 2
        )

        let pidA: pid_t = 1000
        let pidB: pid_t = 2000

        // PID A can reserve up to 2 slots
        XCTAssertTrue(server.reserveClientSlot(clientPid: pidA))
        XCTAssertTrue(server.reserveClientSlot(clientPid: pidA))
        // 3rd attempt by PID A must be rejected
        XCTAssertFalse(server.reserveClientSlot(clientPid: pidA))

        // PID B can still reserve slots
        XCTAssertTrue(server.reserveClientSlot(clientPid: pidB))
        XCTAssertTrue(server.reserveClientSlot(clientPid: pidB))
        XCTAssertFalse(server.reserveClientSlot(clientPid: pidB))

        // Releasing a slot for PID A allows PID A to reserve again
        server.releaseClientSlot(clientPid: pidA)
        XCTAssertTrue(server.reserveClientSlot(clientPid: pidA))
        XCTAssertFalse(server.reserveClientSlot(clientPid: pidA))

        // Cleanup
        server.releaseClientSlot(clientPid: pidA)
        server.releaseClientSlot(clientPid: pidA)
        server.releaseClientSlot(clientPid: pidB)
        server.releaseClientSlot(clientPid: pidB)
        XCTAssertEqual(server.activeClientCount, 0)
    }

    // MARK: - Peer process binding

    func testPeerProcessUnchangedForCurrentProcess() throws {
        let pid = getpid()
        let path = try XCTUnwrap(SSHAgentServer.getProcessPath(pid: pid))
        let start = try XCTUnwrap(SSHAgentServer.processStartTime(pid: pid))

        XCTAssertTrue(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start))
        XCTAssertFalse(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path + "-other", startTime: start))
        XCTAssertFalse(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start &+ 1),
                       "A different start time means the PID was recycled")
    }

    func testPeerProcessUnchangedIsFalseForMissingProcess() {
        XCTAssertFalse(SSHAgentServer.peerProcessUnchanged(pid: 999_999, path: "/bin/sh", startTime: 1))
    }

    func testPeerProcessChangeAfterExecIsDetected() throws {
        // Child blocks on stdin, then exec()s a different binary while keeping its PID
        // (and any inherited sockets), which is exactly what the connection check must catch.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "read line; exec /bin/sleep 30"]
        let stdin = Pipe()
        child.standardInput = stdin
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        defer { child.terminate(); child.waitUntilExit() }

        let pid = child.processIdentifier
        var attributed: String?
        let attributeDeadline = Date().addingTimeInterval(3)
        while attributed == nil, Date() < attributeDeadline {
            attributed = SSHAgentServer.getProcessPath(pid: pid)
            if attributed == nil { Thread.sleep(forTimeInterval: 0.01) }
        }
        let path = try XCTUnwrap(attributed)
        let start = try XCTUnwrap(SSHAgentServer.processStartTime(pid: pid))
        XCTAssertTrue(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start))

        stdin.fileHandleForWriting.write(Data("go\n".utf8))
        try stdin.fileHandleForWriting.close()

        var detected = false
        let detectDeadline = Date().addingTimeInterval(3)
        while Date() < detectDeadline {
            if !SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start) {
                detected = true
                break
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(detected, "exec() of a different image must invalidate the attributed identity")
    }

    func testStopDoesNotUnlinkForeignSocket() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-foreign-stop.sock").path
        let serverA = SSHAgentServer(socketPath: testSockPath)
        try serverA.start()
        defer { serverA.stop() }

        // Instance B points to the same path but never started (never bound)
        let serverB = SSHAgentServer(socketPath: testSockPath)
        serverB.stop()

        // Socket file must still exist because serverB does not own it
        XCTAssertTrue(FileManager.default.fileExists(atPath: testSockPath),
                      "serverB.stop() must not unlink a socket file created by serverA")

        // serverA should still be active and accept connections
        let clientSock = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientSock, 0)
        defer { close(clientSock) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSock, $0, addrLen)
            }
        }
        XCTAssertEqual(connectResult, 0, "serverA must still accept connections after serverB.stop()")

        // Calling serverA.stop() removes the socket it created
        serverA.stop()
        XCTAssertFalse(FileManager.default.fileExists(atPath: testSockPath),
                       "serverA.stop() should remove its own socket")
    }
}

