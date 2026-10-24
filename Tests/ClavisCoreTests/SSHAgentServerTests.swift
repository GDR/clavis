import Foundation
import Testing
import CryptoKit
import LocalAuthentication
import Darwin
@testable import ClavisCore
@testable import ClavisTestSupport

private final class GrandchildPidTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var urls: [URL] = []

    func append(_ url: URL) {
        lock.lock()
        defer { lock.unlock() }
        urls.append(url)
    }

    func cleanup() {
        lock.lock()
        let items = urls
        urls.removeAll()
        lock.unlock()
        for pidFileURL in items {
            if let pidText = try? String(contentsOf: pidFileURL, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines),
               let grandchildPid = pid_t(pidText),
               grandchildPid > 0 {
                kill(grandchildPid, SIGKILL)
            }
        }
    }
}

final class SSHAgentServerTests {
    private static let gitEnvLock = NSLock()
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }
    private let grandchildPidFilesToClean: GrandchildPidTracker

    init() throws {
        self.fixture = try ClavisTestFixture()
        self.grandchildPidFilesToClean = GrandchildPidTracker()
    }

    deinit {
        grandchildPidFilesToClean.cleanup()
        fixture.cleanup()
    }

    private func makeKeyManager(
        authenticator: UserAuthenticating = AllowingAuthenticator(),
        privateKeyStore: PrivateKeyStoring = InMemoryPrivateKeyStore(),
        vaultStore: EncryptedVaultStore? = nil,
        auditRecorder: AuditRecording = InMemoryAuditRecorder(),
        signingProvider: SecureEnclaveSigningProviding? = nil,
        gitSigningGraceManager: GitSigningGraceManager = .shared
    ) -> KeychainManager {
        fixture.makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: privateKeyStore,
            vaultStore: vaultStore,
            auditRecorder: auditRecorder,
            signingProvider: signingProvider,
            gitSigningGraceManager: gitSigningGraceManager
        )
    }

    private func connectUnixSocket(path: String) throws -> Int32 {
        try fixture.connectUnixSocket(path: path)
    }

    private func socketReadFullBytes(from sock: Int32, count: Int) -> Data? {
        fixture.socketReadFullBytes(from: sock, count: count)
    }

    @Test func testAuthenticationReasonsFitSystemPromptGrammar() {
        #expect(
            SSHAgentServer.sshAuthenticationReason(keyLabel: "Main Key") ==
            "use \u{201c}Main Key\u{201d} for SSH authentication"
        )
        #expect(
            SSHAgentServer.gitCommitSigningReason(keyLabel: "Main Key") ==
            "sign a Git commit with \u{201c}Main Key\u{201d}"
        )
        #expect(
            SSHAgentServer.gitSigningSessionReason(keyLabel: "Main Key") ==
            "authorize a 5-minute Git signing session with \u{201c}Main Key\u{201d}"
        )
    }

    @Test func testOwnerControlRequestRevokesPerKeyGitGrant() throws {
        let label = "revoke-\(UUID().uuidString)"
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)
        _ = graceManager.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            context: LAContext()
        )
        #expect(graceManager.getValidGrant(for: label) != nil)

        var request = Data([SSHAgentServer.invalidateKeyRequest])
        request.appendWireString(label)
        let response = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            keyManager: makeKeyManager(gitSigningGraceManager: graceManager),
            gitSigningGraceManager: graceManager
        ).processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/Applications/Clavis.app/Contents/MacOS/Clavis",
            isTrustedControlPeer: { true }
        )

        #expect(response == Data([6]))
        #expect(graceManager.getValidGrant(for: label) == nil)
    }

    @Test func testControlOpcodesAreRefusedForUntrustedPeers() throws {
        let label = "untrusted-\(UUID().uuidString)"
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)
        _ = graceManager.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            context: LAContext()
        )
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            keyManager: makeKeyManager(gitSigningGraceManager: graceManager),
            gitSigningGraceManager: graceManager
        )

        let invalidate = Data([SSHAgentServer.invalidateKeyRequest])
        requestLoop: for request in [invalidate, Data([SSHAgentServer.queryGitGraceRequest]), Data([SSHAgentServer.lockAllRequest])] {
            var req = request
            if req == invalidate {
                req.appendWireString(label)
            }
            // Default (no trust callback) and an explicit "untrusted" peer are both refused.
            #expect(server.processAgentRequest(payload: req) == Data([5]))
            #expect(server.processAgentRequest(payload: req, isTrustedControlPeer: { false }) == Data([5]))
        }
        #expect(graceManager.getValidGrant(for: label) != nil,
                "A refused control request must not revoke or reveal the grant")
    }

    @Test func testTrustCallbackIsNotEvaluatedForStandardAgentMessages() {
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: makeKeyManager())
        var evaluated = false
        _ = server.processAgentRequest(payload: Data([11]), isTrustedControlPeer: { evaluated = true; return true })
        #expect(!evaluated)
    }

    @Test func testControlOpcodeOverRealSocketIsRefusedForNonClavisPeer() throws {
        let socketPath = testRootURL.appendingPathComponent("control.sock").path
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: socketPath, keyManager: makeKeyManager())
        try server.start()
        defer { server.stop() }

        let fd = try connectUnixSocket(path: socketPath)
        defer { close(fd) }
        var packet = Data()
        packet.appendWireUInt32(1)
        packet.append(SSHAgentServer.lockAllRequest)
        #expect(packet.withUnsafeBytes { write(fd, $0.baseAddress, packet.count) } == packet.count)

        var header = [UInt8](repeating: 0, count: 5)
        var received = 0
        while received < header.count {
            let n = read(fd, &header[received], header.count - received)
            if n <= 0 { break }
            received += n
        }
        // The xctest/runner is not a Clavis-signed binary, so the request must be refused.
        #expect(header == [0, 0, 0, 1, 5])
    }

    @Test func testSSHAgentServerLifecycle() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-unittest.sock").path
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: testSockPath)

        #expect(!server.isSocketActive)
        try server.start()
        #expect(server.isSocketActive)
        #expect(FileManager.default.fileExists(atPath: testSockPath))

        // Verify socket permissions are restricted to 0600
        let attrs = try FileManager.default.attributesOfItem(atPath: testSockPath)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
        #expect(perms == 0o600)

        server.stop()
        #expect(!server.isSocketActive)
    }

    @Test func testSSHAgentServerBoundsIdleClients() throws {
        let socketPath = testRootURL.appendingPathComponent("clavis-client-limit.sock").path
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            socketPath: socketPath,
            maxConcurrentClients: 1,
            clientIdleTimeout: 0.6
        )
        try server.start()
        defer { server.stop() }

        let idleClient = try connectUnixSocket(path: socketPath)
        defer { close(idleClient) }

        let acceptanceDeadline = Date().addingTimeInterval(3)
        while server.activeClientCount != 1 && Date() < acceptanceDeadline {
            usleep(5_000)
        }
        #expect(server.activeClientCount == 1)


        let rejectedClient = try connectUnixSocket(path: socketPath)
        defer { close(rejectedClient) }
        #expect(socketReadFullBytes(from: rejectedClient, count: 1) == nil)

        let timeoutDeadline = Date().addingTimeInterval(3)
        while server.activeClientCount != 0 && Date() < timeoutDeadline {
            usleep(5_000)
        }
        #expect(server.activeClientCount == 0)
    }

    @Test func testSSHAgentServerRequestIdentitiesSocket() throws {
        try fixture.runSync {
            let testSockPath = testRootURL.appendingPathComponent("clavis-req-ident.sock").path
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                socketPath: testSockPath,
                keyManager: makeKeyManager(),
                testContext: fixture.context
            )
            try server.start()
            defer { server.stop() }

            let clientSock = try connectUnixSocket(path: testSockPath)
            defer { close(clientSock) }

            // SSH2_AGENTC_REQUEST_IDENTITIES packet: 4 bytes len (1), 1 byte msg (11)
            let request = Data([0x00, 0x00, 0x00, 0x01, 11])
            _ = request.withUnsafeBytes { write(clientSock, $0.baseAddress!, request.count) }

            // Read response header (4 bytes len)
            guard let lenData = socketReadFullBytes(from: clientSock, count: 4) else {
                Issue.record("Failed to read length header from agent socket")
                return
            }
            var respLenVal: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
            let respLen = Int(UInt32(bigEndian: respLenVal))
            #expect(respLen > 0)

            guard let payload = socketReadFullBytes(from: clientSock, count: respLen) else {
                Issue.record("Failed to read response payload from agent socket")
                return
            }

            #expect(payload.count >= 5)
            #expect(payload[0] == 12) // SSH2_AGENT_IDENTITIES_ANSWER
        }
    }

    @Test func testSSHAgentServerSignRequestMissingFlags() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-sign-req.sock").path
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: testSockPath, keyManager: makeKeyManager())
        try server.start()
        defer { server.stop() }

        let clientSock = try connectUnixSocket(path: testSockPath)
        defer { close(clientSock) }

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
            Issue.record("Failed to read length header from agent socket")
            return
        }
        var respLenVal: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
        let respLen = Int(UInt32(bigEndian: respLenVal))
        #expect(respLen == 1)

        guard let responsePayload = socketReadFullBytes(from: clientSock, count: respLen) else {
            Issue.record("Failed to read response payload from agent socket")
            return
        }

        #expect(responsePayload[0] == 5) // SSH_AGENT_FAILURE
    }

    @Test func testSSHAgentServerRequestIdentities() {
        fixture.runSync {
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: makeKeyManager(), testContext: fixture.context)
            let requestPayload = Data([11]) // SSH2_AGENTC_REQUEST_IDENTITIES
            let response = server.processAgentRequest(payload: requestPayload)

            #expect(!response.isEmpty)
            #expect(response[0] == 12) // SSH2_AGENT_IDENTITIES_ANSWER

            // Key count is 4 bytes big endian starting at index 1
            #expect(response.count >= 5)
            let keyCount = response.subdata(in: 1..<5).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
            #expect(keyCount >= 0)
        }
    }

    @Test func testSSHAgentServerSignRequestParsing() {
        fixture.runSync {
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: makeKeyManager(), testContext: fixture.context)

            // 1. Invalid payload: empty or unknown msg type
            #expect(server.processAgentRequest(payload: Data()) == Data([5]))
            #expect(server.processAgentRequest(payload: Data([99])) == Data([5]))

            // 2. Msg type 13 with truncated payload (missing flags)
            var truncatedPayload = Data([13])
            truncatedPayload.appendWireString("fake-key-blob")
            truncatedPayload.appendWireString("data-to-sign")
            // Missing 4-byte flags parameter
            #expect(server.processAgentRequest(payload: truncatedPayload) == Data([5]))

            // 3. Msg type 13 with valid wire framing and flags but non-existent keyBlob
            var validFramedPayload = Data([13])
            validFramedPayload.appendWireString("non-existent-key-blob")
            validFramedPayload.appendWireString("hello world")
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { validFramedPayload.append(contentsOf: $0) }
            #expect(server.processAgentRequest(payload: validFramedPayload) == Data([5]))

            #expect(
                server.processAgentRequest(payload: Data([11, 0x00])) == Data([5]),
                "Identities requests with trailing bytes must be rejected"
            )

            var unsupportedFlagsPayload = Data([13])
            unsupportedFlagsPayload.appendWireString("non-existent-key-blob")
            unsupportedFlagsPayload.appendWireString("hello world")
            var unsupportedFlags = UInt32(1).bigEndian
            Swift.withUnsafeBytes(of: &unsupportedFlags) { unsupportedFlagsPayload.append(contentsOf: $0) }
            #expect(server.processAgentRequest(payload: unsupportedFlagsPayload) == Data([5]))

            var trailingPayload = validFramedPayload
            trailingPayload.append(0x00)
            #expect(server.processAgentRequest(payload: trailingPayload) == Data([5]))
        }
    }

    @Test func testSSHSigningCanRequirePerRequestAuthentication() throws {
        try fixture.runSync {
            let authenticator = CountingAuthenticator()
            let keyManager = makeKeyManager(authenticator: authenticator)
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

            #expect(authenticator.authenticationCount == 2)
        }
    }

    @Test func testSSHClientAttributionUsesExecutablePath() {
        let path = SSHAgentServer.getProcessPath(pid: getpid())
        #expect(path != nil)
        #expect(path?.hasPrefix("/") == true)
        #expect(
            SSHAgentServer.getProcessName(pid: getpid()) ==
            path.map { ($0 as NSString).lastPathComponent }
        )
    }

    @Test func testSSHAgentServerPerPIDClientLimit() {
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            maxConcurrentClients: 10,
            maxConcurrentClientsPerPID: 2
        )

        let pidA: pid_t = 1000
        let pidB: pid_t = 2000

        // PID A can reserve up to 2 slots
        #expect(server.reserveClientSlot(clientPid: pidA))
        #expect(server.reserveClientSlot(clientPid: pidA))
        // 3rd attempt by PID A must be rejected
        #expect(!server.reserveClientSlot(clientPid: pidA))

        // PID B can still reserve slots
        #expect(server.reserveClientSlot(clientPid: pidB))
        #expect(server.reserveClientSlot(clientPid: pidB))
        #expect(!server.reserveClientSlot(clientPid: pidB))

        // Releasing a slot for PID A allows PID A to reserve again
        server.releaseClientSlot(clientPid: pidA)
        #expect(server.reserveClientSlot(clientPid: pidA))
        #expect(!server.reserveClientSlot(clientPid: pidA))

        // Cleanup
        server.releaseClientSlot(clientPid: pidA)
        server.releaseClientSlot(clientPid: pidA)
        server.releaseClientSlot(clientPid: pidB)
        server.releaseClientSlot(clientPid: pidB)
        #expect(server.activeClientCount == 0)
    }

    // MARK: - Peer process binding

    @Test func testPeerProcessUnchangedForCurrentProcess() throws {
        let pid = getpid()
        let path = try #require(SSHAgentServer.getProcessPath(pid: pid))
        let start = try #require(SSHAgentServer.processStartTime(pid: pid))

        #expect(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start))
        #expect(!SSHAgentServer.peerProcessUnchanged(pid: pid, path: path + "-other", startTime: start))
        #expect(!SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start &+ 1),
                "A different start time means the PID was recycled")
    }

    @Test func testPeerProcessUnchangedIsFalseForMissingProcess() {
        #expect(!SSHAgentServer.peerProcessUnchanged(pid: 999_999, path: "/bin/sh", startTime: 1))
    }

    @Test func testPeerProcessChangeAfterExecIsDetected() throws {
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
        let path = try #require(attributed)
        let start = try #require(SSHAgentServer.processStartTime(pid: pid))
        #expect(SSHAgentServer.peerProcessUnchanged(pid: pid, path: path, startTime: start))

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
        #expect(detected, "exec() of a different image must invalidate the attributed identity")
    }

    @Test func testStopDoesNotUnlinkForeignSocket() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-foreign-stop.sock").path
        let serverA = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: testSockPath)
        try serverA.start()
        defer { serverA.stop() }

        // Instance B points to the same path but never started (never bound)
        let serverB = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: testSockPath)
        serverB.stop()

        // Socket file must still exist because serverB does not own it
        #expect(FileManager.default.fileExists(atPath: testSockPath),
                "serverB.stop() must not unlink a socket file created by serverA")

        // serverA should still be active and accept connections
        let clientSock = try connectUnixSocket(path: testSockPath)
        defer { close(clientSock) }

        // Calling serverA.stop() removes the socket it created
        serverA.stop()
        #expect(!FileManager.default.fileExists(atPath: testSockPath),
                "serverA.stop() should remove its own socket")
    }

    @Test func testStopDoesNotUnlinkReplacedSocket() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-replaced-stop.sock").path
        let serverA = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: testSockPath)
        try serverA.start()

        // Replace socket file with a newly created socket (different inode)
        _ = unlink(testSockPath)

        let newSock = socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(newSock >= 0)
        defer {
            close(newSock)
            _ = unlink(testSockPath)
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(newSock, $0, addrLen)
            }
        }
        #expect(bindResult == 0)

        // Calling serverA.stop() must not remove the replaced socket file
        serverA.stop()
        #expect(FileManager.default.fileExists(atPath: testSockPath),
                "serverA.stop() must not remove a socket replaced with a different inode")
    }

    // MARK: - Server loop hardening tests

    @Test func testAcceptErrorBackoffBehavior() throws {
        let socketPath = testRootURL.appendingPathComponent("accept-backoff.sock").path
        var sleepCalls: [useconds_t] = []
        let lock = NSLock()
        var acceptInvocations = 0

        let errorsToSimulate: [(Int32, Int32)] = [
            (-1, EINTR),
            (-1, ECONNABORTED),
            (-1, EMFILE),
            (-1, ENFILE),
            (-1, ENOBUFS),
        ]

        let finished = DispatchSemaphore(value: 0)
        var signaled = false
        func finish() {
            if !signaled {
                signaled = true
                finished.signal()
            }
        }

        var server: SSHAgentServer!
        server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            socketPath: socketPath,
            keyManager: makeKeyManager(),
            backoffHandler: { duration in
                lock.lock()
                sleepCalls.append(duration)
                lock.unlock()
            },
            acceptCall: { _ in
                lock.lock()
                defer { lock.unlock() }
                if acceptInvocations < errorsToSimulate.count {
                    let result = errorsToSimulate[acceptInvocations]
                    acceptInvocations += 1
                    return result
                }
                server.stop()
                finish()
                return (-1, EBADF)
            }
        )

        try server.start()
        defer { server.stop() }
        #expect(finished.wait(timeout: .now() + 5.0) == .success)

        lock.lock()
        defer { lock.unlock() }
        #expect(acceptInvocations == 5)
        // EINTR and ECONNABORTED must NOT back off.
        // EMFILE, ENFILE, ENOBUFS must each back off 100_000 us (100ms).
        #expect(sleepCalls == [100_000, 100_000, 100_000])
        #expect(!server.isSocketActive)
    }

    @Test func testConnectionLifetimeAndRequestCapLimit() throws {
        try fixture.runSync {
            // 1. Verify default values
            #expect(SSHAgentServer.defaultMaxConnectionLifetime == 120.0)
            #expect(SSHAgentServer.defaultMaxRequestsPerConnection == 200)

            // 2. Request cap limit (200 requests)
            let capSocketPath = testRootURL.appendingPathComponent("req-cap.sock").path
            let capServer = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                socketPath: capSocketPath,
                maxRequestsPerConnection: 200,
                keyManager: makeKeyManager(),
                testContext: fixture.context
            )
            try capServer.start()
            defer { capServer.stop() }

            let capClient = try connectUnixSocket(path: capSocketPath)
            defer { close(capClient) }

            let requestPacket = Data([0x00, 0x00, 0x00, 0x01, 11])
            for _ in 1...200 {
                let written = requestPacket.withUnsafeBytes { write(capClient, $0.baseAddress!, requestPacket.count) }
                #expect(written == requestPacket.count)

                guard let lenData = socketReadFullBytes(from: capClient, count: 4) else {
                    Issue.record("Expected response header")
                    return
                }
                let respLen = Int(lenData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian })
                guard let respPayload = socketReadFullBytes(from: capClient, count: respLen) else {
                    Issue.record("Expected response payload")
                    return
                }
                #expect(respPayload.first == 12)
            }

            // The 201st request must trigger connection drop (EOF)
            _ = requestPacket.withUnsafeBytes { write(capClient, $0.baseAddress!, requestPacket.count) }
            let eofResult = socketReadFullBytes(from: capClient, count: 4)
            #expect(eofResult == nil, "Server must drop connection after reaching 200 requests")

            let capDeadline = Date().addingTimeInterval(1.0)
            while capServer.activeClientCount > 0 && Date() < capDeadline {
                usleep(10_000)
            }
            #expect(capServer.activeClientCount == 0)

            // 3. Connection lifetime limit
            let lifeSocketPath = testRootURL.appendingPathComponent("lifetime.sock").path
            let lifeServer = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                socketPath: lifeSocketPath,
                maxConnectionLifetime: 0.05,
                keyManager: makeKeyManager(),
                testContext: fixture.context
            )
            try lifeServer.start()
            defer { lifeServer.stop() }

            let lifeClient = try connectUnixSocket(path: lifeSocketPath)
            defer { close(lifeClient) }

            let deadline = Date().addingTimeInterval(1)
            while lifeServer.activeClientCount != 1 && Date() < deadline {
                usleep(5_000)
            }
            #expect(lifeServer.activeClientCount == 1)

            // Wait for lifetime limit (0.05s) to elapse
            usleep(80_000)
            #expect(socketReadFullBytes(from: lifeClient, count: 1) == nil, "Server must drop connection after lifetime limit")

            let lifeDeadline = Date().addingTimeInterval(1.0)
            while lifeServer.activeClientCount > 0 && Date() < lifeDeadline {
                usleep(5_000)
            }
            #expect(lifeServer.activeClientCount == 0)
        }
    }

    @Test func testTOCTOUPeerProcessMismatchAfterPromptWithholdsSignatureAndDropsConnection() throws {
        try fixture.runSync {
            let socketPath = testRootURL.appendingPathComponent("toctou.sock").path

            var promptInvoked = false
            var peerProcessChanged = false

            let authenticator = HookAuthenticator(onAuthenticate: {
                promptInvoked = true
                // Injected mismatching peer process after prompt has started/returned
                peerProcessChanged = true
            })

            let keyManager = makeKeyManager(authenticator: authenticator)
            let label = "toctou-key-\(UUID().uuidString)"
            defer { try? keyManager.deleteKey(label: label) }
            let keyInfo = try keyManager.generateKey(label: label)

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                socketPath: socketPath,
                keyManager: keyManager,
                peerProcessValidator: { pid, path, startTime in
                    if peerProcessChanged {
                        return false
                    }
                    return true
                },
                testContext: fixture.context
            )
            try server.start()
            defer { server.stop() }

            let client = try connectUnixSocket(path: socketPath)
            defer { close(client) }

            var payloadData = Data([13])
            payloadData.appendWireData(keyInfo.publicKeyBlob)
            payloadData.appendWireData(Data("challenge-to-sign".utf8))
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { payloadData.append(contentsOf: $0) }

            var packet = Data()
            var len = UInt32(payloadData.count).bigEndian
            Swift.withUnsafeBytes(of: &len) { packet.append(contentsOf: $0) }
            packet.append(payloadData)

            let written = packet.withUnsafeBytes { write(client, $0.baseAddress!, packet.count) }
            #expect(written == packet.count)

            // Reading from client socket: signature must be withheld and connection dropped (EOF)
            let responseHeader = socketReadFullBytes(from: client, count: 4)
            #expect(responseHeader == nil, "Signature must be withheld and connection dropped on TOCTOU mismatch")
            #expect(promptInvoked, "Signing prompt must have been executed")

            close(client)
            let deadline = Date().addingTimeInterval(3.0)
            while server.activeClientCount > 0 && Date() < deadline {
                usleep(10_000)
            }
            #expect(server.activeClientCount == 0, "Client slot must be released")
        }
    }

    @Test func testPermanentSocketErrorClassification() {
        #expect(SSHAgentServer.isPermanentSocketError(EBADF))
        #expect(SSHAgentServer.isPermanentSocketError(EINVAL))
        #expect(SSHAgentServer.isPermanentSocketError(ENOTSOCK))

        #expect(!SSHAgentServer.isPermanentSocketError(EMFILE))
        #expect(!SSHAgentServer.isPermanentSocketError(ENFILE))
        #expect(!SSHAgentServer.isPermanentSocketError(ENOBUFS))
        #expect(!SSHAgentServer.isPermanentSocketError(ENOMEM))
        #expect(!SSHAgentServer.isPermanentSocketError(EINTR))
        #expect(!SSHAgentServer.isPermanentSocketError(ECONNABORTED))
    }

    @Test func testAcceptPermanentErrorEBADFExitsLoopAndFiresFailureCallback() throws {
        let socketPath = testRootURL.appendingPathComponent("accept-ebadf.sock").path
        let lock = NSLock()
        var failureCallCount = 0
        var acceptCount = 0
        var backoffCallCount = 0

        let finished = DispatchSemaphore(value: 0)
        var signaled = false
        let resumeLock = NSLock()
        func finish() {
            resumeLock.lock()
            defer { resumeLock.unlock() }
            if !signaled {
                signaled = true
                finished.signal()
            }
        }

        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            socketPath: socketPath,
            keyManager: makeKeyManager(),
            backoffHandler: { _ in
                lock.lock()
                backoffCallCount += 1
                lock.unlock()
            },
            acceptCall: { _ in
                lock.lock()
                acceptCount += 1
                lock.unlock()
                return (-1, EBADF)
            }
        )

        server.onPermanentListenerFailure = {
            lock.lock()
            failureCallCount += 1
            lock.unlock()
            finish()
        }

        try server.start()
        defer { server.stop() }
        #expect(finished.wait(timeout: .now() + 5.0) == .success)

        usleep(50_000)

        lock.lock()
        defer { lock.unlock() }
        #expect(failureCallCount == 1, "Failure callback must fire exactly once")
        #expect(!server.isSocketActive, "Server socket must not be active")
        #expect(acceptCount == 1, "Accept loop must exit immediately on permanent error")
        #expect(backoffCallCount == 0, "Permanent error must not invoke backoffHandler")
    }

    @Test func testAcceptTransientErrorEMFILECallsBackoffAndKeepsLooping() throws {
        let socketPath = testRootURL.appendingPathComponent("accept-emfile.sock").path
        let targetBackoffCalls = 3
        let lock = NSLock()
        var backoffCount = 0
        var acceptCount = 0
        var failureCallbackCalled = false

        let finished = DispatchSemaphore(value: 0)
        var signaled = false
        let resumeLock = NSLock()
        func finish() {
            resumeLock.lock()
            defer { resumeLock.unlock() }
            if !signaled {
                signaled = true
                finished.signal()
            }
        }

        var server: SSHAgentServer!
        server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            socketPath: socketPath,
            keyManager: makeKeyManager(),
            backoffHandler: { duration in
                lock.lock()
                backoffCount += 1
                let currentCount = backoffCount
                lock.unlock()

                #expect(duration == 100_000)
                if currentCount == targetBackoffCalls {
                    server.stop()
                    finish()
                }
            },
            acceptCall: { _ in
                lock.lock()
                acceptCount += 1
                lock.unlock()
                return (-1, EMFILE)
            }
        )

        server.onPermanentListenerFailure = {
            lock.lock()
            failureCallbackCalled = true
            lock.unlock()
        }

        try server.start()
        defer { server.stop() }
        #expect(finished.wait(timeout: .now() + 5.0) == .success)

        lock.lock()
        defer { lock.unlock() }
        #expect(backoffCount == targetBackoffCalls, "backoffHandler should be called for each transient error")
        #expect(acceptCount >= targetBackoffCalls, "Accept loop should keep looping across transient errors")
        #expect(!failureCallbackCalled, "Failure callback must not fire for transient errors")
        #expect(!server.isSocketActive)
    }

    // MARK: - resolveGpgSSHProgram tests

    private func createStubGitScript(named name: String, content: String) throws -> String {
        let scriptURL = testRootURL.appendingPathComponent(name)
        try content.write(to: scriptURL, atomically: true, encoding: .utf8)
        chmod(scriptURL.path, 0o755)
        return scriptURL.path
    }

    @Test func testResolveGpgSSHProgramSuccessReturnsPath() throws {
        let scriptPath = try createStubGitScript(
            named: "git-success.sh",
            content: "#!/bin/sh\nprintf \"/path/to/signer\\n\"\nexit 0\n"
        )
        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 2.0)
        #expect(resolved == "/path/to/signer")
    }

    @Test func testResolveGpgSSHProgramTimeoutReturnsNilPromptly() throws {
        let scriptPath = try createStubGitScript(
            named: "git-timeout.sh",
            content: "#!/bin/sh\nexec sleep 30\n"
        )
        let start = Date()
        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 0.08)
        let elapsed = Date().timeIntervalSince(start)
        #expect(resolved == nil)
        #expect(elapsed < 1.5)
    }

    @Test func testResolveGpgSSHProgramGrandchildHoldingStdoutTimesOutCleanly() throws {
        let pidFileURL = testRootURL.appendingPathComponent("grandchild.pid")
        grandchildPidFilesToClean.append(pidFileURL)

        let scriptPath = try createStubGitScript(
            named: "git-grandchild.sh",
            content: """
            #!/bin/sh
            sh -c 'sleep 30 & echo $! > "\(pidFileURL.path)"; wait'
            """
        )
        let start = Date()
        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 0.08)
        let elapsed = Date().timeIntervalSince(start)
        #expect(resolved == nil)
        #expect(elapsed < 1.5)
    }

    @Test func testResolveGpgSSHProgramBoundedOutputWithoutHang() throws {
        let scriptPath = try createStubGitScript(
            named: "git-large-output.sh",
            content: """
            #!/bin/sh
            head -c 1048576 /dev/zero | tr '\\0' 'A'
            exit 0
            """
        )
        let start = Date()
        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 2.0)
        let elapsed = Date().timeIntervalSince(start)
        #expect(elapsed < 1.5)
        if let resolved {
            #expect(resolved.utf8.count <= 64 * 1024)
        }
    }

    @Test func testResolveGpgSSHProgramNonZeroExitReturnsNil() throws {
        let scriptPath = try createStubGitScript(
            named: "git-failure.sh",
            content: "#!/bin/sh\nprintf \"/path/to/signer\\n\"\nexit 1\n"
        )
        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 2.0)
        #expect(resolved == nil)
    }

    @Test func testResolveGpgSSHProgramSanitizesGitEnvironmentVariables() throws {
        Self.gitEnvLock.lock()
        defer { Self.gitEnvLock.unlock() }

        let scriptPath = try createStubGitScript(
            named: "git-env-test.sh",
            content: """
            #!/bin/sh
            if [ -n "$GIT_CONFIG_GLOBAL" ] || [ -n "$GIT_CONFIG_SYSTEM" ] || [ -n "$GIT_CONFIG_NOSYSTEM" ] || [ -n "$GIT_CONFIG_PARAMETERS" ]; then
                printf "UNSANITIZED\\n"
                exit 0
            fi
            printf "/usr/bin/ssh-keygen\\n"
            exit 0
            """
        )

        setenv("GIT_CONFIG_GLOBAL", "/tmp/malicious_global.gitconfig", 1)
        setenv("GIT_CONFIG_SYSTEM", "/tmp/malicious_system.gitconfig", 1)
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1)
        setenv("GIT_CONFIG_PARAMETERS", "'user.name=attacker'", 1)
        defer {
            unsetenv("GIT_CONFIG_GLOBAL")
            unsetenv("GIT_CONFIG_SYSTEM")
            unsetenv("GIT_CONFIG_NOSYSTEM")
            unsetenv("GIT_CONFIG_PARAMETERS")
        }

        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 2.0)
        #expect(resolved == "/usr/bin/ssh-keygen", "resolveGpgSSHProgram must sanitize GIT_CONFIG_* environment variables")
    }

    @Test func testResolveGpgSSHProgramSanitizesGitConfigLegacyEnvVar() throws {
        Self.gitEnvLock.lock()
        defer { Self.gitEnvLock.unlock() }

        let scriptPath = try createStubGitScript(
            named: "git-env-gitconfig.sh",
            content: """
            #!/bin/sh
            if [ -n "$GIT_CONFIG" ]; then
                printf "UNSANITIZED\\n"
                exit 0
            fi
            printf "/usr/bin/ssh-keygen\\n"
            exit 0
            """
        )

        setenv("GIT_CONFIG", "/tmp/malicious.config", 1)
        defer {
            unsetenv("GIT_CONFIG")
        }

        let resolved = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptPath, timeout: 2.0)
        #expect(resolved == "/usr/bin/ssh-keygen", "resolveGpgSSHProgram must sanitize GIT_CONFIG environment variable")
    }

    static func makeSSH2UserAuthRequest(
        sessionID: Data,
        user: String = "git",
        service: String = "ssh-connection",
        method: String = "publickey",
        hasSig: Bool = true,
        algo: String = "ssh-ed25519",
        keyBlob: Data
    ) -> Data {
        var data = Data()
        data.appendWireData(sessionID)
        data.append(50) // SSH2_MSG_USERAUTH_REQUEST
        data.appendWireString(user)
        data.appendWireString(service)
        data.appendWireString(method)
        data.append(hasSig ? 1 : 0)
        data.appendWireString(algo)
        data.appendWireData(keyBlob)
        return data
    }

    @Test func test_F04_gitCommitSigningReasonIncludesRequester() {
        let reason = SSHAgentServer.gitCommitSigningReason(keyLabel: "DeployKey", requester: "/usr/bin/git (PID 4242)")
        #expect(reason.contains("(requested by /usr/bin/git (PID 4242))"), "gitCommitSigningReason must include requester description")
        #expect(reason.contains("DeployKey"))
    }

    @Test func test_F04_gitCommitSigningPromptPresentedOnlyForVerifiedSignerHelper() throws {
        try fixture.runSync {
            let countingAuth = CountingAuthenticator()
            let audit = InMemoryAuditRecorder()
            let keyMgr = makeKeyManager(authenticator: countingAuth, auditRecorder: audit)
            let gitOnlyKey = try keyMgr.generateKey(label: "git-only-key", biometricPolicy: .userPresence, keyPurpose: .gitSigningOnly)
            let generalKey = try keyMgr.generateKey(label: "general-key", biometricPolicy: .userPresence, keyPurpose: .general)

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                role: .personal,
                keyManager: keyMgr,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: audit,
                testContext: fixture.context
            )

            let validGitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x55, count: 32)).serialize()

            // 1. Unverified peer with .gitSigningOnly key receives SSH_AGENT_FAILURE (5) and audit denied
            var signGitOnly = Data([13])
            signGitOnly.appendWireData(gitOnlyKey.publicKeyBlob)
            signGitOnly.appendWireData(validGitPayload)
            signGitOnly.appendWireUInt32(0)

            let respUnverifiedGitOnly = server.processAgentRequest(
                payload: signGitOnly,
                clientPid: 9999,
                clientExecutablePath: "/bin/cat",
                clientStartTime: 1000
            )
            #expect(respUnverifiedGitOnly == Data([5]), "Unverified peer requesting SSHSIG on gitSigningOnly key must fail")
            let gitOnlyDeniedAudit = audit.events.last { e in
                e.sensitive.keyLabel == gitOnlyKey.label && e.type == .signature
            }
            #expect(gitOnlyDeniedAudit != nil)
            #expect(gitOnlyDeniedAudit?.result == .denied)
            #expect(gitOnlyDeniedAudit?.reason == .wrongKeyKind)

            // 2. Unverified peer with .general key receives generic data signing prompt (not gitCommitSigning)
            var signGeneral = Data([13])
            signGeneral.appendWireData(generalKey.publicKeyBlob)
            signGeneral.appendWireData(validGitPayload)
            signGeneral.appendWireUInt32(0)

            let respUnverifiedGeneral = server.processAgentRequest(
                payload: signGeneral,
                clientPid: 9999,
                clientExecutablePath: "/bin/cat",
                clientStartTime: 1000
            )
            #expect(respUnverifiedGeneral.first == 14, "Unverified peer requesting SSHSIG on general key should succeed with data prompt")
            #expect(countingAuth.lastReason != nil)
            #expect(!countingAuth.lastReason!.contains("sign a Git commit"), "Unverified peer must NOT receive git commit prompt: \(countingAuth.lastReason!)")
            #expect(countingAuth.lastReason!.contains("sign data requested by"), "Unverified peer must receive generic data prompt: \(countingAuth.lastReason!)")

            // 3. Verified Git signer helper with .gitSigningOnly key receives gitCommitSigning prompt
            let respVerifiedGitOnly = server.processAgentRequest(
                payload: signGitOnly,
                clientPid: 9999,
                clientExecutablePath: "/usr/bin/ssh-keygen",
                clientStartTime: 1000
            )
            #expect(respVerifiedGitOnly.first == 14, "Verified signer helper on gitSigningOnly key must succeed")
            #expect(countingAuth.lastReason != nil)
            #expect(countingAuth.lastReason!.contains("sign a Git commit"), "Verified signer helper must receive Git commit prompt: \(countingAuth.lastReason!)")
        }
    }

    @Test func test_F05_sshAuthenticationPromptPresentedOnlyForTrustedSSHBinaryAndRFC4252Payload() throws {
        let keyBlob = Data("test-ed25519-public-key-blob".utf8)
        let otherKeyBlob = Data("other-ed25519-public-key-blob".utf8)
        let sessionID = Data("valid-session-id-123".utf8)

        let validAuthData = SSHAgentServerTests.makeSSH2UserAuthRequest(
            sessionID: sessionID,
            user: "git",
            service: "ssh-connection",
            method: "publickey",
            hasSig: true,
            algo: "ssh-ed25519",
            keyBlob: keyBlob
        )

        let reqDesc = "/usr/bin/ssh (PID 1234)"

        // (a) Trusted ssh binary with valid RFC 4252 payload
        let reasonDirect = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/usr/bin/ssh",
            dataToSign: validAuthData,
            keyBlob: keyBlob,
            hasForwarding: false
        )
        #expect(reasonDirect == ClavisUIStrings.Prompt.sshAuthentication(keyLabel: "MyKey", requester: reqDesc))

        let reasonForwarded = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/usr/bin/ssh",
            dataToSign: validAuthData,
            keyBlob: keyBlob,
            hasForwarding: true
        )
        #expect(reasonForwarded == ClavisUIStrings.Prompt.sshAuthenticationFromForwardedAgent(keyLabel: "MyKey", requester: reqDesc))

        // (b) Untrusted binary (e.g. /tmp/ssh or /bin/cat) with valid RFC 4252 payload
        let reasonUntrustedPath = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/tmp/ssh",
            dataToSign: validAuthData,
            keyBlob: keyBlob
        )
        #expect(reasonUntrustedPath == ClavisUIStrings.Prompt.dataSigning(keyLabel: "MyKey", requester: reqDesc))

        // (c) Trusted ssh binary with non-RFC 4252 payload (e.g. random data)
        let randomData = Data("random-bytes-not-rfc4252".utf8)
        let reasonRandom = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/usr/bin/ssh",
            dataToSign: randomData,
            keyBlob: keyBlob
        )
        #expect(reasonRandom == ClavisUIStrings.Prompt.dataSigning(keyLabel: "MyKey", requester: reqDesc))

        // (d) Trusted ssh binary with RFC 4252 payload matching different keyBlob
        let reasonKeyMismatch = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/usr/bin/ssh",
            dataToSign: validAuthData,
            keyBlob: otherKeyBlob
        )
        #expect(reasonKeyMismatch == ClavisUIStrings.Prompt.dataSigning(keyLabel: "MyKey", requester: reqDesc))

        // (e) Trusted ssh binary with RFC 4252 payload with invalid service
        let invalidServiceData = SSHAgentServerTests.makeSSH2UserAuthRequest(
            sessionID: sessionID,
            service: "wrong-service",
            keyBlob: keyBlob
        )
        let reasonWrongService = SSHAgentServer.signatureReason(
            keyLabel: "MyKey",
            requester: reqDesc,
            processPath: "/usr/bin/ssh",
            dataToSign: invalidServiceData,
            keyBlob: keyBlob
        )
        #expect(reasonWrongService == ClavisUIStrings.Prompt.dataSigning(keyLabel: "MyKey", requester: reqDesc))
    }

    @Test func test_F06_handleSetAgentPolicyAndExtendEnforceBiometricPolicyAndContext() throws {
        try fixture.runSync {
            let countingAuth = CountingAuthenticator()
            let audit = InMemoryAuditRecorder()
            let store = InMemoryPrivateKeyStore()
            let keyMgr = makeKeyManager(authenticator: countingAuth, privateKeyStore: store, auditRecorder: audit)

            let key = try keyMgr.generateKey(label: "biometric-agent-key", biometricPolicy: .biometryCurrentSet, keyPurpose: .agent)
            defer { PublicKeyStore.remove(label: "biometric-agent-key") }

            let policyStore = InMemoryAgentPolicyStore()
            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: audit,
                watchRootExit: false
            )

            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                role: .personal,
                keyManager: keyMgr,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: audit,
                agentSessions: registry,
                agentPolicies: policyStore,
                authenticator: countingAuth,
                testContext: fixture.context
            )

            // 1. handleSetAgentPolicy enforces key's biometricPolicy.laPolicy (.deviceOwnerAuthenticationWithBiometrics)
            // and contextual prompt
            let newPolicy = AgentKeyPolicy(mode: .ask)
            let policyData = try JSONEncoder().encode(newPolicy)
            let policyJson = String(data: policyData, encoding: .utf8)!
            var setPolicyPayload = Data([SSHAgentServer.setAgentPolicyRequest])
            setPolicyPayload.appendWireString(key.fingerprint)
            setPolicyPayload.appendWireString(policyJson)

            let setResp = server.processAgentRequest(
                payload: setPolicyPayload,
                clientPid: 1234,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(setResp == Data([6]))
            #expect(countingAuth.lastPolicy == .deviceOwnerAuthenticationWithBiometrics)
            #expect(countingAuth.lastReason != nil)
            #expect(countingAuth.lastReason!.contains(key.label))
            #expect(countingAuth.lastReason!.contains("1234"))

            // 2. Register session
            var regPayload = Data([SSHAgentServer.registerAgentSessionRequest])
            regPayload.appendWireString(key.label)
            regPayload.appendWireString("build-tool")
            regPayload.appendWireUInt32(30)
            let regResp = server.processAgentRequest(
                payload: regPayload,
                clientPid: 1234,
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(regResp.first == 6)

            let summaries = registry.summaries()
            #expect(summaries.count == 1)
            let sessionID = summaries[0].id

            // 3. handleExtendAgentSession enforces key's biometricPolicy.laPolicy and contextual prompt
            var extendPayload = Data([SSHAgentServer.extendAgentSessionRequest])
            extendPayload.appendWireString(sessionID)
            extendPayload.appendWireUInt32(45)

            let extendResp = server.processAgentRequest(
                payload: extendPayload,
                clientPid: 5678,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(extendResp.first == 6)
            #expect(countingAuth.lastPolicy == .deviceOwnerAuthenticationWithBiometrics)
            #expect(countingAuth.lastReason != nil)
            #expect(countingAuth.lastReason!.contains(key.label))
            #expect(countingAuth.lastReason!.contains("build-tool"))
            #expect(countingAuth.lastReason!.contains("45"))
            #expect(countingAuth.lastReason!.contains("5678"))

            // 4. .ask mode on agent socket enforces key's biometricPolicy.laPolicy and contextual prompt
            let agentServer = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                role: .agent,
                keyManager: keyMgr,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: audit,
                agentSessions: registry,
                agentPolicies: policyStore,
                authenticator: countingAuth,
                testContext: fixture.context
            )

            var signPayload = Data([13])
            signPayload.appendWireData(key.publicKeyBlob)
            signPayload.appendWireData(Data("ask-mode-payload".utf8))
            signPayload.appendWireUInt32(0)

            let signResp = agentServer.processAgentRequest(
                payload: signPayload,
                clientPid: 1234,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: 1000
            )
            #expect(signResp.first == 14)
            #expect(countingAuth.lastPolicy == .deviceOwnerAuthenticationWithBiometrics)
            #expect(countingAuth.lastReason != nil)
            #expect(countingAuth.lastReason!.contains(key.label))
            #expect(countingAuth.lastReason!.contains("build-tool"))
            #expect(countingAuth.lastReason!.contains("1234"))
        }
    }
}

private final class HookAuthenticator: UserAuthenticating {
    private let onAuthenticate: () -> Void

    init(onAuthenticate: @escaping () -> Void) {
        self.onAuthenticate = onAuthenticate
    }

    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
        onAuthenticate()
        return LAContext()
    }

    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
        onAuthenticate()
        return LAContext()
    }
}
