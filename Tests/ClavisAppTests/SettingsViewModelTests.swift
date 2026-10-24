import Testing
import Foundation
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport
@testable import Clavis

@Suite
final class SettingsViewModelTests {
    private let fixture: ClavisTestFixture
    private let mockAgent: MockAgentController
    private let server: SSHAgentServer
    private let sockPath: String

    init() throws {
        let fixture = try ClavisTestFixture()
        self.fixture = fixture
        self.mockAgent = MockAgentController()
        let sockPath = fixture.testRootURL.appendingPathComponent("settings-test.sock").path
        self.sockPath = sockPath
        self.server = SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: sockPath, keyManager: fixture.makeKeyManager())
    }

    deinit {
        server.stop()
        fixture.cleanup()
    }

    @Test @MainActor
    func testStartStopRestartAgentUpdatesState() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        #expect(!viewModel.isSocketActive)
        #expect(viewModel.agentPID == nil)

        viewModel.startAgent()
        #expect(viewModel.isSocketActive)
        #expect(viewModel.agentPID == 12345)
        #expect(mockAgent.startAgentCallCount == 1)

        viewModel.stopAgent()
        #expect(!viewModel.isSocketActive)
        #expect(viewModel.agentPID == nil)
        #expect(mockAgent.stopAgentCallCount == 1)

        viewModel.restartAgent()
        #expect(viewModel.isSocketActive)
        #expect(viewModel.agentPID == 12346)
        #expect(mockAgent.restartAgentCallCount == 1)
    }

    @Test @MainActor
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

        #expect(viewModel.errorMessage != nil)
        #expect(viewModel.errorMessage == "Failed to launch agent binary")
        #expect(!viewModel.isSocketActive)
    }

    @Test @MainActor
    func testEndGitSigningSessionCallsLockAllAndClearsGrace() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-grace", remainingSeconds: 300, remainingOperations: 5)

        viewModel.endGitSigningSession()

        #expect(mockAgent.sendLockAllCallCount == 1)
        #expect(viewModel.activeGitGrace == nil)
        #expect(viewModel.errorMessage == nil)
    }

    @Test @MainActor
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

        #expect(mockAgent.sendLockAllCallCount == 1)
        #expect(viewModel.errorMessage != nil)
        #expect(viewModel.errorMessage == "Agent rejected lock-all command")
        #expect(viewModel.activeGitGrace != nil, "activeGitGrace must NOT be cleared when lock-all fails")
    }

    @Test @MainActor
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

        #expect(viewModel.errorMessage != nil)
        #expect(viewModel.errorMessage == "Lock-all failed")
        #expect(viewModel.activeGitGrace != nil)
    }

    @Test @MainActor
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
        #expect(daemonVM.activeGitGrace?.keyLabel == "in-process-key")
        #expect(mockAgent.queryAgentGitGraceCallCount == 0, "In daemon mode, must not query remote agent socket")

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

        #expect(guiVM.activeGitGrace?.keyLabel == "remote-agent-key", "Out of process mode must query remote agent, not in-process grant")
        #expect(mockAgent.queryAgentGitGraceCallCount >= 1)
    }

    @Test @MainActor
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

        #expect(terminationCallbackCalled)
        #expect(!viewModel.isSocketActive)
        #expect(viewModel.agentPID == nil)
        #expect(viewModel.activeGitGrace == nil)
    }

    @Test @MainActor
    func testSetLaunchAtLogin() throws {
        let viewModel = SettingsViewModel(
            agentLifecycle: mockAgent,
            sshAgentServer: server,
            isDaemonMode: false
        )
        viewModel.setLaunchAtLogin(true)
        #expect(viewModel.launchAtLogin)

        viewModel.setLaunchAtLogin(false)
        #expect(!viewModel.launchAtLogin)
    }
}
