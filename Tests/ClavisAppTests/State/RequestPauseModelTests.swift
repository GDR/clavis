import Foundation
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor struct RequestPauseModelTests {
    @Test func unavailableIsNotReportedAsActive() async {
        let model = RequestPauseModel(agent: MockAgentController())
        #expect(model.state == .unknown)
        await model.refresh()
        #expect(model.state == .unknown)
        #expect(model.status == "Agent status unavailable")
        #expect(!model.isBusy)
    }

    @Test func restoredPersistentPauseIsShownAfterLaunch() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init(requestsPaused: true)
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(model.state == .paused)
        #expect(model.isPaused)
        #expect(model.status == "Requests paused")
    }

    @Test func pauseAndResumeFollowDaemonAcknowledgement() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init()
        agent.applicationPolicyHandler = { change in
            agent.stubbedApplicationRegistry = .init(requestsPaused: change == .pause)
            return true
        }
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(model.state == .accepting)
        #expect(await model.setPaused(true))
        #expect(model.state == .paused)
        #expect(await model.setPaused(false))
        #expect(model.state == .accepting)
        #expect(agent.applicationPolicyChanges == [.pause, .resume])
    }

    @Test func cancelledResumeKeepsPauseAndReportsFailure() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init(requestsPaused: true)
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(!(await model.setPaused(false)))
        #expect(model.state == .paused)
        #expect(model.errorMessage != nil)
        #expect(agent.applicationPolicyChanges == [.resume])
    }

    @Test func lostReadbackNeverInventsSuccessfulResume() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init(requestsPaused: true)
        agent.applicationPolicyHandler = { _ in
            agent.stubbedApplicationRegistry = nil
            return true
        }
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(!(await model.setPaused(false)))
        #expect(model.state == .unknown)
        #expect(model.errorMessage?.contains("could not be confirmed") == true)
    }

    @Test func contradictoryReadbackUsesActualPolicy() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init()
        agent.applicationPolicyHandler = { _ in true }
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(!(await model.setPaused(true)))
        #expect(model.state == .accepting)
        #expect(model.errorMessage != nil)
    }

    @Test func sameStateDoesNotReauthenticateOrRestoreApprovals() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init(requestsPaused: true)
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(await model.setPaused(true))
        #expect(agent.applicationPolicyChanges.isEmpty)
        #expect(agent.endAgentSessionCallCount == 0)
    }

    @Test func failedPauseCanReflectAnotherSuccessfulPause() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init()
        agent.applicationPolicyHandler = { _ in
            agent.stubbedApplicationRegistry = .init(requestsPaused: true)
            return false
        }
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(!(await model.setPaused(true)))
        #expect(model.state == .paused)
        #expect(model.errorMessage != nil)
    }
    @Test func appStateConnectsPolicyAndSessionRefresh() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let agent = MockAgentController()
            agent.stubbedApplicationRegistry = .init()
            agent.applicationPolicyHandler = { change in
                agent.stubbedApplicationRegistry = .init(requestsPaused: change == .pause)
                return true
            }
            let state = AppState(keyManager: manager,
                sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: manager),
                agentLifecycle: agent)
            await state.requestPolicy.refresh()
            await state.setRequestsPaused(true)
            #expect(state.requestPolicy.isPaused)
            #expect(state.errorMessage == nil)
            await state.setRequestsPaused(false)
            #expect(state.requestPolicy.state == .accepting)
            #expect(agent.applicationPolicyChanges == [.pause, .resume])
            #expect(agent.startAgentCallCount == 0)
            #expect(agent.extendAgentSessionCallCount == 0)
        }
    }

    @Test func concurrentChangesCannotStartDuplicateControlRequests() async throws {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        agent.applicationPolicyHandler = { _ in
            entered.signal()
            _ = release.wait(timeout: .now() + 5)
            agent.stubbedApplicationRegistry = .init(requestsPaused: true)
            return true
        }
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        let first = Task { await model.setPaused(true) }
        let didEnter = await Task.detached { entered.wait(timeout: .now() + 5) == .success }.value
        defer { release.signal() }
        #expect(didEnter)
        #expect(model.isBusy)
        #expect(!(await model.setPaused(false)))
        await model.refresh()
        #expect(model.isBusy)
        release.signal()
        #expect(await first.value)
        #expect(agent.applicationPolicyChanges == [.pause])
        #expect(!model.isBusy)
    }

    @Test func refreshAfterDaemonLossRemovesStaleActiveStatus() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init()
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(model.state == .accepting)
        agent.stubbedApplicationRegistry = nil
        await model.refresh()
        #expect(model.state == .unknown)
        #expect(model.status == "Agent status unavailable")
    }

    @Test func explicitRetryAfterCancellationCanResume() async {
        let agent = MockAgentController()
        agent.stubbedApplicationRegistry = .init(requestsPaused: true)
        let model = RequestPauseModel(agent: agent)
        await model.refresh()
        #expect(!(await model.setPaused(false)))
        agent.applicationPolicyHandler = { _ in
            agent.stubbedApplicationRegistry = .init(requestsPaused: false)
            return true
        }
        #expect(await model.setPaused(false))
        #expect(model.errorMessage == nil)
        #expect(agent.applicationPolicyChanges == [.resume, .resume])
    }

}
