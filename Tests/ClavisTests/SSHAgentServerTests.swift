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
            clientExecutablePath: "/Applications/Clavis.app/Contents/MacOS/Clavis"
        )

        XCTAssertEqual(response, Data([6]))
        XCTAssertNil(GitSigningGraceManager.shared.getValidGrant(for: label))
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
}
