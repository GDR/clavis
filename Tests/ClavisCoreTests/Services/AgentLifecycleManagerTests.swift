import Testing
import Darwin
import Foundation
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("AgentLifecycleManagerTests")
struct AgentLifecycleManagerTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    @Test
    func testStopAgentReturnsFalseAndPreservesSocketWhenProcessSurvivesSigkill() async {
        defer { fixture.cleanup() }
        await fixture.run {
            let sockPath = fixture.testRootURL.appendingPathComponent("agent-survive.sock").path
            FileManager.default.createFile(atPath: sockPath, contents: Data())
            #expect(FileManager.default.fileExists(atPath: sockPath))

            let manager = AgentLifecycleManager(
                socketPath: sockPath,
                agentPIDProvider: { 99999 },
                processNameProvider: { _ in "clavis-agent" },
                isAlive: { _ in true },
                sigtermTimeout: 0.005,
                sigkillTimeout: 0.02
            )

            let stopped = manager.stopAgent()
            #expect(!stopped, "stopAgent() must return false if the process survives SIGKILL")
            #expect(FileManager.default.fileExists(atPath: sockPath), "Socket must NOT be removed if agent process survived SIGKILL")

            let logURL = ClavisLogger.logFileURL
            let logs = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
            #expect(logs.contains("Failed to terminate agent daemon PID 99999; process survived SIGKILL"))
        }
    }

    @Test
    func testSendLockAllThrowsAgentStopFailedWhenProcessSurvivesSigkill() async {
        defer { fixture.cleanup() }
        await fixture.run {
            let sockPath = fixture.testRootURL.appendingPathComponent("agent-lockall-survive.sock").path
            FileManager.default.createFile(atPath: sockPath, contents: Data())
            #expect(FileManager.default.fileExists(atPath: sockPath))

            let manager = AgentLifecycleManager(
                socketPath: sockPath,
                agentPIDProvider: { 99999 },
                processNameProvider: { _ in "clavis-agent" },
                isAlive: { _ in true },
                sigtermTimeout: 0.005,
                sigkillTimeout: 0.02
            )

            #expect {
                try manager.sendLockAllToAgent()
            } throws: { error in
                if case .agentStopFailed(let reason) = (error as? AgentLifecycleError) {
                    return reason.contains("Failed to stop unresponsive agent")
                }
                return false
            }

            #expect(FileManager.default.fileExists(atPath: sockPath), "Socket must NOT be removed if agent process survived SIGKILL")
        }
    }

    @Test
    func testStopAgentReturnsTrueAndRemovesSocketWhenProcessTerminatesOnSigterm() throws {
        defer { fixture.cleanup() }
        let sockPath = fixture.testRootURL.appendingPathComponent("agent-sigterm.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        #expect(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" },
            isAlive: { _ in false },
            sigtermTimeout: 0.005,
            sigkillTimeout: 0.02
        )

        let stopped = manager.stopAgent()
        #expect(stopped)
        #expect(!FileManager.default.fileExists(atPath: sockPath), "Socket should be removed when process terminates")
    }

    @Test
    func testStopAgentReturnsTrueAndRemovesSocketWhenProcessTerminatesOnSigkill() throws {
        defer { fixture.cleanup() }
        let sockPath = fixture.testRootURL.appendingPathComponent("agent-sigkill.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        #expect(FileManager.default.fileExists(atPath: sockPath))

        var queryCount = 0
        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" },
            isAlive: { _ in
                queryCount += 1
                // Alive during SIGTERM wait, then dies after SIGKILL
                return queryCount <= 3
            },
            sigtermTimeout: 0.005,
            sigkillTimeout: 0.02
        )

        let stopped = manager.stopAgent()
        #expect(stopped)
        #expect(!FileManager.default.fileExists(atPath: sockPath), "Socket should be removed when process terminates after SIGKILL")
    }

    @Test
    func testStopAgentRefusesToSignalWhenProcessNameIsNotClavisAgent() throws {
        defer { fixture.cleanup() }
        let sockPath = fixture.testRootURL.appendingPathComponent("agent-alien.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        #expect(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "other-process" },
            isAlive: { _ in true },
            sigtermTimeout: 0.005,
            sigkillTimeout: 0.02
        )

        let stopped = manager.stopAgent()
        #expect(!stopped)
        // Stale socket is cleaned up when process is not clavis-agent
        #expect(!FileManager.default.fileExists(atPath: sockPath))
    }

    private func spawnExitingProcess() throws -> pid_t {
        var pid: pid_t = 0
        let path = "/bin/sh"
        let cPath = path.withCString { strdup($0) }
        let cArg1 = "-c".withCString { strdup($0) }
        let cArg2 = "exit 0".withCString { strdup($0) }
        defer {
            free(cPath)
            free(cArg1)
            free(cArg2)
        }
        var argv: [UnsafeMutablePointer<CChar>?] = [cPath, cArg1, cArg2, nil]
        let ret = posix_spawn(&pid, path, nil, nil, &argv, nil)
        guard ret == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ret))
        }
        return pid
    }

    @Test
    func testIsProcessAliveForLiveProcess() {
        #expect(AgentLifecycleManager.isProcessAlive(pid: getpid()))
    }

    @Test
    func testIsProcessAliveForDeadProcess() throws {
        let pid = try spawnExitingProcess()
        var status: Int32 = 0
        let waited = waitpid(pid, &status, 0)
        #expect(waited == pid)
        #expect(!AgentLifecycleManager.isProcessAlive(pid: pid))
    }

    @Test
    func testIsProcessAliveForZombieProcess() throws {
        let pid = try spawnExitingProcess()
        defer {
            var status: Int32 = 0
            waitpid(pid, &status, 0)
        }

        let deadline = Date().addingTimeInterval(2.0)
        var reachedZombie = false
        while Date() < deadline {
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
            if (ret == size && info.pbi_status == 5) || (ret == 0 && errno == ESRCH) {
                reachedZombie = true
                break
            }
            usleep(10_000)
        }

        #expect(reachedZombie, "Process should have entered zombie state")
        #expect(kill(pid, 0) == 0, "kill(pid, 0) returns 0 for zombies (proves old check was wrong)")
        #expect(!AgentLifecycleManager.isProcessAlive(pid: pid), "isProcessAlive must filter zombie processes and return false")
    }

    @Test
    func testControlClientRejectsUntrustedServerPeer() throws {
        defer { fixture.cleanup() }
        let sockPath = fixture.testRootURL.appendingPathComponent("untrusted-server.sock").path
        let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
            socketPath: sockPath,
            role: .personal,
            controlPeerValidator: { _ in true }
        )
        try server.start()
        defer { server.stop() }

        let untrustedManager = AgentLifecycleManager(
            socketPath: sockPath,
            isTrustedServerPeer: { _ in false }
        )

        #expect {
            try untrustedManager.sendControlRequest(Data([SSHAgentServer.lockAllRequest]))
        } throws: { error in
            if case .agentControlFailed(let reason) = (error as? AgentLifecycleError) {
                return reason.contains("untrusted control socket server peer")
            }
            return false
        }

        // Default validator uses ClavisCodeTrust.isTrustedPeer(socket:), which also rejects the test runner
        let defaultManager = AgentLifecycleManager(socketPath: sockPath)
        #expect(throws: (any Error).self) {
            try defaultManager.sendControlRequest(Data([SSHAgentServer.lockAllRequest]))
        }
        #expect(defaultManager.listAgentSessions().isEmpty)
        #expect(defaultManager.queryAgentGitGrace() == nil)
    }

    @Test
    func testQueryAllActiveGrantsRoundTripAndFallback() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let graceManager = GitSigningGraceManager(observeSystemEvents: false)
            let myPid = getpid()
            let mySnap = try #require(ProcessInspector.processParentSnapshot(pid: myPid))
            let approved = GitApprovedProcess(pid: myPid, startTime: mySnap.startTime, path: "/usr/bin/git")

            _ = graceManager.recordGrant(
                keyLabel: "git-key",
                clientIdentity: "/usr/bin/git",
                duration: 86_400,
                maxOperations: 15,
                context: LAContext(),
                approvedProcess: approved,
                endsAtLock: true,
                callerName: "Terminal"
            )
            _ = graceManager.recordPersonalSSHGrant(
                keyLabel: "ssh-key",
                approvalIdentity: "app:/usr/bin/ssh",
                duration: 300,
                maxOperations: 10,
                context: LAContext(),
                endsAtLock: false,
                callerName: "OpenSSH"
            )

            let sockPath = fixture.testRootURL.appendingPathComponent("grants-roundtrip.sock").path
            let server = SSHAgentServer(
                applicationAccess: TestApplicationAccess(),
                socketPath: sockPath,
                role: .personal,
                keyManager: fixture.makeKeyManager(),
                gitSigningGraceManager: graceManager,
                controlPeerValidator: { _ in true }
            )
            try server.start()
            defer { server.stop() }

            let lifecycle = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
            let snapshots = lifecycle.queryAllActiveGrants()
            #expect(snapshots.count == 2)
            #expect(snapshots.first { $0.keyLabel == "git-key" }?.endsAtLock == true)
            #expect(snapshots.first { $0.keyLabel == "git-key" }?.callerName == "Terminal")
            #expect(snapshots.first { $0.keyLabel == "ssh-key" }?.endsAtLock == false)
            #expect(snapshots.first { $0.keyLabel == "ssh-key" }?.callerName == "OpenSSH")

            // Verify fallback to opcode 241 when server rejects opcode 252
            let legacySockPath = fixture.testRootURL.appendingPathComponent("grants-legacy.sock").path
            let stub = try LegacyGraceOnlyStubServer(socketPath: legacySockPath, keyLabel: "legacy-key", remainingSeconds: 240, remainingOperations: 7)
            defer { stub.stop() }
            let legacyLifecycle = AgentLifecycleManager(socketPath: legacySockPath, isTrustedServerPeer: { _ in true })
            let fallback = legacyLifecycle.queryAllActiveGrants()
            #expect(fallback.count == 1)
            #expect(fallback.first?.keyLabel == "legacy-key")
            #expect(fallback.first?.remainingOperations == 7)
            #expect(fallback.first?.endsAtLock == false)
        }
    }
}

private final class LegacyGraceOnlyStubServer: @unchecked Sendable {
    let socketPath: String
    private let keyLabel: String
    private let remainingSeconds: UInt32
    private let remainingOperations: UInt32
    private let lock = NSLock()
    private var listeningFd: Int32 = -1
    private var isRunning = true

    init(socketPath: String, keyLabel: String, remainingSeconds: UInt32, remainingOperations: UInt32) throws {
        self.socketPath = socketPath
        self.keyLabel = keyLabel
        self.remainingSeconds = remainingSeconds
        self.remainingOperations = remainingOperations

        unlink(socketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, b) in pathBytes.enumerated() { raw[i] = b }
        }
        let len = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        guard Darwin.bind(fd, withUnsafePointer(to: &addr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1, { $0 }) }), len) == 0,
              Darwin.listen(fd, 4) == 0 else {
            let err = errno
            close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
        }
        self.listeningFd = fd
        Thread { [weak self] in self?.acceptLoop() }.start()
    }

    private func acceptLoop() {
        while true {
            lock.lock()
            let active = isRunning
            let fd = listeningFd
            lock.unlock()
            guard active, fd >= 0 else { break }
            let client = accept(fd, nil, nil)
            guard client >= 0 else { break }
            var hdr = [UInt8](repeating: 0, count: 4)
            guard read(client, &hdr, 4) == 4 else { close(client); continue }
            var reqLen: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &reqLen) { hdr.copyBytes(to: $0) }
            reqLen = UInt32(bigEndian: reqLen)
            var body = [UInt8](repeating: 0, count: Int(reqLen))
            if reqLen > 0 { _ = read(client, &body, body.count) }
            let opcode = body.first ?? 0
            let reply: Data
            if opcode == SSHAgentServer.queryGitGraceRequest {
                var r = Data([6])
                r.appendWireString(keyLabel)
                r.appendWireUInt32(remainingSeconds)
                r.appendWireUInt32(remainingOperations)
                reply = r
            } else {
                reply = Data([5])
            }
            var packet = Data()
            var rLen = UInt32(reply.count).bigEndian
            Swift.withUnsafeBytes(of: &rLen) { packet.append(contentsOf: $0) }
            packet.append(reply)
            _ = packet.withUnsafeBytes { write(client, $0.baseAddress!, packet.count) }
            close(client)
        }
    }

    func stop() {
        lock.lock()
        isRunning = false
        let fd = listeningFd
        listeningFd = -1
        lock.unlock()
        if fd >= 0 { close(fd) }
        unlink(socketPath)
    }
}
