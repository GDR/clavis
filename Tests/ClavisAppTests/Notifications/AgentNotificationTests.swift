@testable import ClavisTestSupport
import Testing
import Foundation
import LocalAuthentication
import UserNotifications
@testable import ClavisCore
@testable import Clavis

@Suite("AgentNotificationTests", .serialized)
final class AgentNotificationTests {
    private let mockAgent: MockAgentController

    init() {
        self.mockAgent = MockAgentController()
    }

    deinit {
        AgentSessionViewModel.resetTestOverrides()
    }

    // MARK: - ClavisNotificationCenterDelegate Tests

    @Test
    func testNotificationCenterDelegateReturnsBannerAndSound() {
        let delegate = ClavisNotificationCenterDelegate()
        let options = delegate.foregroundPresentationOptions()
        #expect(options.contains(.banner))
        #expect(options.contains(.sound))
    }

    @Test
    func testNotificationCenterDelegateWillPresentInvokesCompletionWithBannerAndSound() {
        let delegate = ClavisNotificationCenterDelegate.shared
        var receivedOptions: UNNotificationPresentationOptions?

        let dummyObj = NSObject()
        let dummyCenter: UNUserNotificationCenter = unsafeBitCast(Unmanaged.passUnretained(dummyObj).toOpaque(), to: UNUserNotificationCenter.self)
        let dummyNotification: UNNotification = unsafeBitCast(Unmanaged.passUnretained(dummyObj).toOpaque(), to: UNNotification.self)

        delegate.userNotificationCenter(dummyCenter, willPresent: dummyNotification) { options in
            receivedOptions = options
        }

        #expect(receivedOptions != nil)
        #expect(receivedOptions?.contains(.banner) == true)
        #expect(receivedOptions?.contains(.sound) == true)
    }

    @Test
    func testNotificationCenterDelegateDidReceiveInvokesCompletion() {
        let delegate = ClavisNotificationCenterDelegate.shared
        var completionCalled = false

        let dummyObj = NSObject()
        let dummyCenter: UNUserNotificationCenter = unsafeBitCast(Unmanaged.passUnretained(dummyObj).toOpaque(), to: UNUserNotificationCenter.self)
        let dummyResponse: UNNotificationResponse = unsafeBitCast(Unmanaged.passUnretained(dummyObj).toOpaque(), to: UNNotificationResponse.self)

        delegate.userNotificationCenter(dummyCenter, didReceive: dummyResponse) {
            completionCalled = true
        }

        #expect(completionCalled)
    }

    // MARK: - Delegate Registration Tests

    @Test @MainActor
    func testAgentSessionViewModelRegistersDelegateByDefault() {
        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        #expect(viewModel.registeredNotificationCenterDelegate is ClavisNotificationCenterDelegate)
    }

    @Test @MainActor
    func testAgentSessionViewModelAcceptsCustomDelegate() {
        final class CustomDelegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {}
        let custom = CustomDelegate()
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            notificationCenterDelegate: custom
        )
        #expect(viewModel.registeredNotificationCenterDelegate === custom)
    }

    @Test @MainActor
    func testStaticRegisterNotificationCenterDelegateExecutesSafely() {
        AgentSessionViewModel.registerNotificationCenterDelegate(ClavisNotificationCenterDelegate.shared)
        // Passes without throwing or crashing
    }

    // MARK: - Rate-Limiting / Cooldown Tests

    @Test @MainActor
    func testRateLimitedNotificationThrottlesWithinCooldown() {
        var simulatedTime = Date(timeIntervalSince1970: 10_000)
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            rateLimitedCooldownInterval: 5.0
        )
        viewModel.dateProvider = { simulatedTime }

        var posted: [(title: String, body: String)] = []
        viewModel.onAgentNotificationPosted = { title, body in
            posted.append((title: title, body: body))
        }

        // 1. Initial notification
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-1"]
        ))
        #expect(posted.count == 1)
        #expect(posted[0].title == ClavisUIStrings.AgentSession.notificationRateLimitedTitle)

        // 2. Repeat notification within cooldown (2.0s later) -> must be coalesced/dropped
        simulatedTime.addTimeInterval(2.0)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-1"]
        ))
        #expect(posted.count == 1, "Repeated notification within 5.0s cooldown must be throttled")

        // 3. Notification after cooldown expired (5.1s later) -> must be posted
        simulatedTime.addTimeInterval(3.1)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-1"]
        ))
        #expect(posted.count == 2, "Notification after cooldown expires must be posted")
    }

    @Test @MainActor
    func testRateLimitingIsIndependentPerSession() {
        let simulatedTime = Date(timeIntervalSince1970: 10_000)
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            rateLimitedCooldownInterval: 5.0
        )
        viewModel.dateProvider = { simulatedTime }

        var posted: [(title: String, body: String)] = []
        viewModel.onAgentNotificationPosted = { title, body in
            posted.append((title: title, body: body))
        }

        // Event for Session A
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-A"]
        ))
        #expect(posted.count == 1)

        // Immediate event for Session B -> should NOT be throttled by Session A
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-B"]
        ))
        #expect(posted.count == 2)
    }

    @Test @MainActor
    func testSignedAndRateLimitedCooldownsAreIndependent() {
        let simulatedTime = Date(timeIntervalSince1970: 10_000)
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            signedCooldownInterval: 10.0,
            rateLimitedCooldownInterval: 5.0
        )
        viewModel.dateProvider = { simulatedTime }

        var posted: [(title: String, body: String)] = []
        viewModel.onAgentNotificationPosted = { title, body in
            posted.append((title: title, body: body))
        }

        // 1. Signed notification for session-1
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "session-1"]
        ))
        #expect(posted.count == 1)
        #expect(posted[0].title == ClavisUIStrings.AgentSession.notificationSignedTitle)

        // 2. Rate-limited notification for session-1 at same instant -> must not be throttled by signed cooldown
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "session-1"]
        ))
        #expect(posted.count == 2)
        #expect(posted[1].title == ClavisUIStrings.AgentSession.notificationRateLimitedTitle)
    }

    @Test @MainActor
    func testSignedNotificationCooldownBehavior() {
        var simulatedTime = Date(timeIntervalSince1970: 10_000)
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            signedCooldownInterval: 10.0
        )
        viewModel.dateProvider = { simulatedTime }

        var posted: [(title: String, body: String)] = []
        viewModel.onAgentNotificationPosted = { title, body in
            posted.append((title: title, body: body))
        }

        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "session-signed"]
        ))
        #expect(posted.count == 1)

        simulatedTime.addTimeInterval(9.9)
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "session-signed"]
        ))
        #expect(posted.count == 1, "9.9s is within 10.0s cooldown")

        simulatedTime.addTimeInterval(0.2)
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "session-signed"]
        ))
        #expect(posted.count == 2, "10.1s is past 10.0s cooldown")
    }

    // MARK: - Notification Permission Status Check Tests

    @Test @MainActor
    func testNotificationPermissionCheckWithInstanceOverrideDenied() async {
        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        viewModel.authorizationStatusOverride = .denied

        let status = await viewModel.checkNotificationAuthorizationStatus()
        #expect(status == .denied)
        #expect(viewModel.isNotificationPermissionDenied == true)
        #expect(viewModel.notificationAuthorizationStatus == .denied)
    }

    @Test @MainActor
    func testNotificationPermissionCheckWithInstanceOverrideAuthorized() async {
        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        viewModel.authorizationStatusOverride = .authorized

        let status = await viewModel.checkNotificationAuthorizationStatus()
        #expect(status == .authorized)
        #expect(viewModel.isNotificationPermissionDenied == false)
        #expect(viewModel.notificationAuthorizationStatus == .authorized)
    }

    @Test @MainActor
    func testNotificationPermissionCheckWithStaticOverride() async {
        defer { AgentSessionViewModel.resetTestOverrides() }
        AgentSessionViewModel.testAuthorizationStatusOverride = .denied

        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        let status = await viewModel.checkNotificationAuthorizationStatus()
        #expect(status == .denied)
        #expect(viewModel.isNotificationPermissionDenied == true)
        #expect(viewModel.notificationAuthorizationStatus == .denied)

        AgentSessionViewModel.resetTestOverrides()
        #expect(AgentSessionViewModel.testAuthorizationStatusOverride == nil)
    }

    @Test @MainActor
    func testNotificationPermissionCheckWithCustomProvider() async {
        final class CallCounter: @unchecked Sendable {
            var calls = 0
        }
        let counter = CallCounter()
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            authorizationStatusProvider: {
                counter.calls += 1
                return .denied
            }
        )

        let status = await viewModel.checkNotificationAuthorizationStatus()
        #expect(status == .denied)
        #expect(viewModel.isNotificationPermissionDenied == true)
        #expect(counter.calls == 1)
    }

    @Test @MainActor
    func testConvenienceCheckNotificationPermissionsTriggersUpdate() async throws {
        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        viewModel.authorizationStatusOverride = .denied

        viewModel.checkNotificationPermissions()

        for _ in 0..<50 {
            if viewModel.isNotificationPermissionDenied { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(viewModel.isNotificationPermissionDenied == true)
        #expect(viewModel.notificationAuthorizationStatus == .denied)
    }

    @Test @MainActor
    func testHeadlessFallbackDefaultsToNotDeterminedWithoutCrashing() async {
        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        let status = await viewModel.checkNotificationAuthorizationStatus()
        #expect(status == .notDetermined)
        #expect(viewModel.isNotificationPermissionDenied == false)
        #expect(viewModel.notificationAuthorizationStatus == .notDetermined)
    }

    @Test @MainActor func testSettingsViewModelAndAppStateMultiGrantRevocation() throws {
        let mockController = MockAgentController()
        let settingsVM = SettingsViewModel(
            agentLifecycle: mockController,
            isDaemonMode: true
        )
        let appState = AppState(
            agentLifecycle: mockController,
            isDaemonMode: true,
            settingsViewModel: settingsVM
        )

        let key1 = "grace-key-1-\(UUID().uuidString)"
        let key2 = "grace-key-2-\(UUID().uuidString)"

        let myPid = getpid()
        let mySnap = try #require(ProcessInspector.processParentSnapshot(pid: myPid))
        let approved = GitApprovedProcess(pid: myPid, startTime: mySnap.startTime, path: "/usr/bin/git")

        // Record grants in GitSigningGraceManager.shared
        GitSigningGraceManager.shared.recordGrant(
            keyLabel: key1,
            clientIdentity: "/usr/bin/git",
            duration: 300,
            maxOperations: 15,
            context: LAContext(),
            approvedProcess: approved
        )
        GitSigningGraceManager.shared.recordGrant(
            keyLabel: key2,
            clientIdentity: "/usr/bin/git",
            duration: 300,
            maxOperations: 25,
            context: LAContext(),
            approvedProcess: approved
        )

        // Refresh state
        settingsVM.updateGitGraceState()
        appState.updateGitGraceState()

        #expect(settingsVM.activeGitGraces.count >= 2)
        #expect(settingsVM.activeGitGraces.contains(where: { $0.keyLabel == key1 }))
        #expect(settingsVM.activeGitGraces.contains(where: { $0.keyLabel == key2 }))
        #expect(appState.activeGitGraces.contains(where: { $0.keyLabel == key1 }))

        // Revoke key1 specifically from AppState
        appState.revokeGitGrace(for: key1)

        #expect(!appState.activeGitGraces.contains(where: { $0.keyLabel == key1 }))
        #expect(appState.activeGitGraces.contains(where: { $0.keyLabel == key2 }))
        #expect(GitSigningGraceManager.shared.getValidGrant(for: key1) == nil)
        #expect(GitSigningGraceManager.shared.getValidGrant(for: key2) != nil)

        // Revoke key2 with keyLabel: overload
        appState.revokeGitGrace(keyLabel: key2)
        #expect(!appState.activeGitGraces.contains(where: { $0.keyLabel == key2 }))
        #expect(GitSigningGraceManager.shared.getValidGrant(for: key2) == nil)

        // Cleanup
        GitSigningGraceManager.shared.invalidateAll()
    }

    @Test @MainActor
    func testAdversarialNotificationRateLimitingUnderRapidFlooding() async throws {
        let mockAgent = MockAgentController()
        var simulatedTime = Date(timeIntervalSince1970: 50_000)
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            signedCooldownInterval: 10.0,
            rateLimitedCooldownInterval: 5.0
        )
        viewModel.dateProvider = { simulatedTime }

        final class NotificationSpy: @unchecked Sendable {
            private let lock = NSLock()
            private var _posts: [(title: String, body: String)] = []
            var posts: [(title: String, body: String)] {
                lock.lock()
                defer { lock.unlock() }
                return _posts
            }
            func append(title: String, body: String) {
                lock.lock()
                defer { lock.unlock() }
                _posts.append((title: title, body: body))
            }
        }
        let spy = NotificationSpy()
        viewModel.onAgentNotificationPosted = { title, body in
            spy.append(title: title, body: body)
        }

        let sessionID1 = "adversarial-session-1"
        let sessionID2 = "adversarial-session-2"

        // Burst 1: Send 50 rapid rate-limited notifications for session 1
        for i in 0..<50 {
            simulatedTime.addTimeInterval(0.01) // 0.5s total burst
            viewModel.handleAgentRateLimitedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentRateLimited"),
                object: nil,
                userInfo: ["sessionID": sessionID1, "attempt": i]
            ))
        }
        // Exactly 1 notification must be posted
        #expect(spy.posts.count == 1)
        #expect(spy.posts.first?.title == ClavisUIStrings.AgentSession.notificationRateLimitedTitle)

        // Concurrently flood session 1 and session 2
        simulatedTime.addTimeInterval(1.0) // 1.5s into 5.0s cooldown
        for _ in 0..<20 {
            viewModel.handleAgentRateLimitedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentRateLimited"),
                object: nil,
                userInfo: ["sessionID": sessionID1]
            ))
        }
        // Session 1 is still throttled
        #expect(spy.posts.count == 1)

        // Session 2 sends first notification -> should be posted immediately (independent per session)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": sessionID2]
        ))
        #expect(spy.posts.count == 2)

        // Flood session 2 with 30 rapid notifications
        for _ in 0..<30 {
            simulatedTime.addTimeInterval(0.02)
            viewModel.handleAgentRateLimitedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentRateLimited"),
                object: nil,
                userInfo: ["sessionID": sessionID2]
            ))
        }
        #expect(spy.posts.count == 2)

        // Advance time past 5.0s cooldown for session 1
        simulatedTime.addTimeInterval(4.0)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": sessionID1]
        ))
        #expect(spy.posts.count == 3)

        // Advance time past 5.0s cooldown for session 2
        simulatedTime.addTimeInterval(5.1)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": sessionID2]
        ))
        #expect(spy.posts.count == 4)
    }
}
