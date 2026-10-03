import XCTest
import Darwin
@testable import ClavisCore
@testable import Clavis

final class AgentLifecycleManagerTests: ClavisBaseTestCase {

    func testStopAgentReturnsFalseAndPreservesSocketWhenProcessSurvivesSigkill() throws {
        let sockPath = testRootURL.appendingPathComponent("agent-survive.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" },
            isAlive: { _ in true },
            sigtermTimeout: 0.05
        )

        let stopped = manager.stopAgent()
        XCTAssertFalse(stopped, "stopAgent() must return false if the process survives SIGKILL")
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath), "Socket must NOT be removed if agent process survived SIGKILL")

        let securityLogURL = ClavisLogger.securityLogFileURL
        let logs = (try? String(contentsOf: securityLogURL, encoding: .utf8)) ?? ""
        XCTAssertTrue(logs.contains("Failed to terminate agent daemon PID 99999; process survived SIGKILL"))
    }

    func testSendLockAllThrowsAgentStopFailedWhenProcessSurvivesSigkill() throws {
        let sockPath = testRootURL.appendingPathComponent("agent-lockall-survive.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" },
            isAlive: { _ in true },
            sigtermTimeout: 0.05
        )

        XCTAssertThrowsError(try manager.sendLockAllToAgent()) { error in
            guard let lifecycleError = error as? AgentLifecycleError else {
                XCTFail("Expected AgentLifecycleError, got \(error)")
                return
            }
            switch lifecycleError {
            case .agentStopFailed(let reason):
                XCTAssertTrue(reason.contains("Failed to stop unresponsive agent"))
            default:
                XCTFail("Expected .agentStopFailed, got \(lifecycleError)")
            }
        }

        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath), "Socket must NOT be removed if agent process survived SIGKILL")
    }

    func testStopAgentReturnsTrueAndRemovesSocketWhenProcessTerminatesOnSigterm() throws {
        let sockPath = testRootURL.appendingPathComponent("agent-sigterm.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" },
            isAlive: { _ in false },
            sigtermTimeout: 0.05
        )

        let stopped = manager.stopAgent()
        XCTAssertTrue(stopped)
        XCTAssertFalse(FileManager.default.fileExists(atPath: sockPath), "Socket should be removed when process terminates")
    }

    func testStopAgentReturnsTrueAndRemovesSocketWhenProcessTerminatesOnSigkill() throws {
        let sockPath = testRootURL.appendingPathComponent("agent-sigkill.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath))

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
            sigtermTimeout: 0.05
        )

        let stopped = manager.stopAgent()
        XCTAssertTrue(stopped)
        XCTAssertFalse(FileManager.default.fileExists(atPath: sockPath), "Socket should be removed when process terminates after SIGKILL")
    }

    func testStopAgentRefusesToSignalWhenProcessNameIsNotClavisAgent() throws {
        let sockPath = testRootURL.appendingPathComponent("agent-alien.sock").path
        FileManager.default.createFile(atPath: sockPath, contents: Data())
        XCTAssertTrue(FileManager.default.fileExists(atPath: sockPath))

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "other-process" },
            isAlive: { _ in true },
            sigtermTimeout: 0.05
        )

        let stopped = manager.stopAgent()
        XCTAssertFalse(stopped)
        // Stale socket is cleaned up when process is not clavis-agent
        XCTAssertFalse(FileManager.default.fileExists(atPath: sockPath))
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

    func testIsProcessAliveForLiveProcess() {
        XCTAssertTrue(AgentLifecycleManager.isProcessAlive(pid: getpid()))
    }

    func testIsProcessAliveForDeadProcess() throws {
        let pid = try spawnExitingProcess()
        var status: Int32 = 0
        let waited = waitpid(pid, &status, 0)
        XCTAssertEqual(waited, pid)
        XCTAssertFalse(AgentLifecycleManager.isProcessAlive(pid: pid))
    }

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

        XCTAssertTrue(reachedZombie, "Process should have entered zombie state")
        XCTAssertEqual(kill(pid, 0), 0, "kill(pid, 0) returns 0 for zombies (proves old check was wrong)")
        XCTAssertFalse(AgentLifecycleManager.isProcessAlive(pid: pid), "isProcessAlive must filter zombie processes and return false")
    }
}
