import XCTest
import Foundation
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

final class SettingsViewModelTests: ClavisBaseTestCase {
    private var mockAgent: MockAgentController!
    private var server: SSHAgentServer!
    private var sockPath: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        mockAgent = MockAgentController()
        sockPath = testRootURL.appendingPathComponent("settings-test.sock").path
        server = SSHAgentServer(socketPath: sockPath)
    }

    override func tearDownWithError() throws {
        server?.stop()
        server = nil
        mockAgent = nil
        try super.tearDownWithError()
    }

    @MainActor
    func testStartStopRestartAgentUpdatesState() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        XCTAssertFalse(viewModel.isSocketActive)
        XCTAssertNil(viewModel.agentPID)

        viewModel.startAgent()
        XCTAssertTrue(viewModel.isSocketActive)
        XCTAssertEqual(viewModel.agentPID, 12345)
        XCTAssertEqual(mockAgent.startAgentCallCount, 1)

        viewModel.stopAgent()
        XCTAssertFalse(viewModel.isSocketActive)
        XCTAssertNil(viewModel.agentPID)
        XCTAssertEqual(mockAgent.stopAgentCallCount, 1)

        viewModel.restartAgent()
        XCTAssertTrue(viewModel.isSocketActive)
        XCTAssertEqual(viewModel.agentPID, 12346)
        XCTAssertEqual(mockAgent.restartAgentCallCount, 1)
    }

    @MainActor
    func testStartAgentFailureSetsErrorMessage() throws {
        struct DummyError: LocalizedError {
            var errorDescription: String? { "Failed to launch agent binary" }
        }
        mockAgent.startAgentError = DummyError()

        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.startAgent()

        XCTAssertNotNil(viewModel.errorMessage)
        XCTAssertEqual(viewModel.errorMessage, "Failed to launch agent binary")
        XCTAssertFalse(viewModel.isSocketActive)
    }

    @MainActor
    func testEndGitSigningSessionCallsLockAllAndClearsGrace() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-grace", remainingSeconds: 300, remainingOperations: 5)

        viewModel.endGitSigningSession()

        XCTAssertEqual(mockAgent.sendLockAllCallCount, 1)
        XCTAssertNil(viewModel.activeGitGrace)
        XCTAssertNil(viewModel.errorMessage)
    }

    @MainActor
    func testEndGitSigningSessionFailsClosedWhenAgentThrows() throws {
        struct DummyError: LocalizedError {
            var errorDescription: String? { "Agent rejected lock-all command" }
        }
        mockAgent.sendLockAllError = DummyError()

        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-grace", remainingSeconds: 300, remainingOperations: 5)

        viewModel.endGitSigningSession()

        XCTAssertEqual(mockAgent.sendLockAllCallCount, 1)
        XCTAssertNotNil(viewModel.errorMessage)
        XCTAssertEqual(viewModel.errorMessage, "Agent rejected lock-all command")
        XCTAssertNotNil(viewModel.activeGitGrace, "activeGitGrace must NOT be cleared when lock-all fails")
    }

    @MainActor
    func testLockNowPreservesErrorMessageOnFailure() throws {
        struct DummyError: LocalizedError {
            var errorDescription: String? { "Lock-all failed" }
        }
        mockAgent.sendLockAllError = DummyError()

        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-grace", remainingSeconds: 300, remainingOperations: 5)

        viewModel.lockNow()

        XCTAssertNotNil(viewModel.errorMessage)
        XCTAssertEqual(viewModel.errorMessage, "Lock-all failed")
        XCTAssertNotNil(viewModel.activeGitGrace)
    }

    @MainActor
    func testUpdateGitGraceStateInProcessVsDaemon() async throws {
        // Setup in-process active grant in GitSigningGraceManager
        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        defer { GitSigningGraceManager.shared.invalidateAll(broadcast: false) }
        _ = GitSigningGraceManager.shared.recordGrant(
            keyLabel: "in-process-key",
            clientIdentity: "/usr/bin/git",
            context: LAContext()
        )

        mockAgent.stubbedGitGrace = (keyLabel: "remote-agent-key", remainingSeconds: 120, remainingOperations: 3)

        // Case 1: In-process daemon mode -> reads GitSigningGraceManager.shared
        let daemonVM = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: true
        )
        daemonVM.updateGitGraceState()
        XCTAssertEqual(daemonVM.activeGitGrace?.keyLabel, "in-process-key")
        XCTAssertEqual(mockAgent.queryAgentGitGraceCallCount, 0, "In daemon mode, must not query remote agent socket")

        // Case 2: Out-of-process standalone GUI -> does NOT read GitSigningGraceManager.shared
        let guiVM = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        guiVM.activeGitGrace = nil
        guiVM.updateGitGraceState()

        // Wait for detached task to populate activeGitGrace from mockAgent
        for _ in 0..<50 {
            if guiVM.activeGitGrace != nil { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        XCTAssertEqual(guiVM.activeGitGrace?.keyLabel, "remote-agent-key", "Out of process mode must query remote agent, not in-process grant")
        XCTAssertGreaterThanOrEqual(mockAgent.queryAgentGitGraceCallCount, 1)
    }

    @MainActor
    func testShutdownForTermination() throws {
        var terminationCallbackCalled = false
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: true,
            terminationAgentStop: {
                terminationCallbackCalled = true
                return true
            }
        )
        viewModel.isSocketActive = true
        viewModel.agentPID = 9999
        viewModel.activeGitGrace = ActiveGitGraceInfo(keyLabel: "k", remainingSeconds: 10, remainingOperations: 1)

        viewModel.shutdownForTermination()

        XCTAssertTrue(terminationCallbackCalled)
        XCTAssertFalse(viewModel.isSocketActive)
        XCTAssertNil(viewModel.agentPID)
        XCTAssertNil(viewModel.activeGitGrace)
    }

    @MainActor
    func testSetLaunchAtLogin() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.setLaunchAtLogin(true)
        XCTAssertTrue(viewModel.launchAtLogin)

        viewModel.setLaunchAtLogin(false)
        XCTAssertFalse(viewModel.launchAtLogin)
    }
}
