import Testing
import Darwin
import Foundation
@testable import ClavisCore
@testable import Clavis

@Suite("AgentLifecycleManagerTests")
struct AgentLifecycleManagerTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    @Test
    func testStopAgentReturnsFalseAndPreservesSocketWhenProcessSurvivesSigkill() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
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
    func testSendLockAllThrowsAgentStopFailedWhenProcessSurvivesSigkill() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
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
        let server = SSHAgentServer(
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
}
