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
}
