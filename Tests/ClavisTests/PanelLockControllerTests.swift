import XCTest
import SwiftUI
@preconcurrency import LocalAuthentication
@testable import Clavis
@testable import ClavisCore

final class MockLAContext: LAContext {
    var didInvalidate = false

    override func invalidate() {
        didInvalidate = true
        super.invalidate()
    }
}

final class FakePanelAuthenticator: PanelAuthenticating {
    var authCount = 0
    var lastReason: String?
    var shouldFail = false
    var failureError: Error = LAError(.userCancel)
    var contextToReturn: LAContext = MockLAContext()

    func authenticate(reason: String) async throws -> LAContext {
        authCount += 1
        lastReason = reason
        if shouldFail {
            throw failureError
        }
        return contextToReturn
    }
}

final class FakeSystemEventMonitor: SystemEventMonitoring {
    var handlers: [String: () -> Void] = [:]

    func addHandler(id: String, handler: @escaping () -> Void) {
        handlers[id] = handler
    }

    func fire(id: String) {
        handlers[id]?()
    }
}

@MainActor
final class PanelLockControllerTests: ClavisBaseTestCase {
    private var testDefaults: UserDefaults!
    private var suiteName: String!

    override func setUp() {
        super.setUp()
        MainActor.assumeIsolated {
            suiteName = "com.clavis.tests.panelLock.\(UUID().uuidString)"
            testDefaults = UserDefaults(suiteName: suiteName)!
        }
    }

    override func tearDown() {
        MainActor.assumeIsolated {
            testDefaults?.removePersistentDomain(forName: suiteName)
            testDefaults = nil
        }
        super.tearDown()
    }

    func test_003_AC7_freshInstallIsLocked() {
        let controller = PanelLockController(defaults: testDefaults)
        XCTAssertTrue(controller.isEnabled)
        XCTAssertEqual(controller.state, .locked)
        XCTAssertTrue(controller.isLocked)
        XCTAssertNil(controller.unlockContext)
        XCTAssertEqual(controller.idleMinutes, 5)
    }

    func test_003_AC1_unlockRequiresAuthentication() async {
        let fakeAuth = FakePanelAuthenticator()
        let mockContext = MockLAContext()
        fakeAuth.contextToReturn = mockContext
        let currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        XCTAssertTrue(controller.isLocked)
        await controller.unlock()

        XCTAssertEqual(fakeAuth.authCount, 1)
        XCTAssertEqual(fakeAuth.lastReason, ClavisUIStrings.PanelLock.reason)
        XCTAssertEqual(controller.state, .unlocked(since: currentTime))
        XCTAssertFalse(controller.isLocked)
        XCTAssertIdentical(controller.unlockContext, mockContext)
    }

    func test_003_AC1_cancelledUnlockStaysLocked() async {
        let fakeAuth = FakePanelAuthenticator()
        fakeAuth.shouldFail = true
        fakeAuth.failureError = LAError(.userCancel)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        XCTAssertTrue(controller.isLocked)
        await controller.unlock()

        XCTAssertEqual(fakeAuth.authCount, 1)
        XCTAssertEqual(controller.state, .locked)
        XCTAssertTrue(controller.isLocked)
        XCTAssertNil(controller.unlockContext)
    }

    func test_003_AC4_lockInvalidatesContext() async {
        let fakeAuth = FakePanelAuthenticator()
        let mockContext = MockLAContext()
        fakeAuth.contextToReturn = mockContext
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        XCTAssertNotNil(controller.unlockContext)
        XCTAssertFalse(mockContext.didInvalidate)

        controller.lock(reason: .lockNow)
        XCTAssertTrue(mockContext.didInvalidate)
        XCTAssertNil(controller.unlockContext)
        XCTAssertEqual(controller.state, .locked)
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(controller.lastLockReason, .lockNow)
    }

    func test_003_AC4_idleLocksAfterTimeout() async {
        let fakeAuth = FakePanelAuthenticator()
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        await controller.unlock()
        XCTAssertFalse(controller.isLocked)

        // 5 minutes - 1 second: should remain unlocked
        currentTime += (5 * 60 - 1)
        controller.tick()
        XCTAssertFalse(controller.isLocked)

        // 2 seconds later (5 min + 1 sec total): should lock
        currentTime += 2
        controller.tick()
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(controller.state, .locked)
        XCTAssertEqual(controller.lastLockReason, .idle)
    }

    func test_003_AC4_activityResetsIdle() async {
        let fakeAuth = FakePanelAuthenticator()
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        await controller.unlock()
        XCTAssertFalse(controller.isLocked)

        // 4 minutes pass
        currentTime += (4 * 60)
        controller.tick()
        XCTAssertFalse(controller.isLocked)

        // User activity happens
        controller.noteActivity()

        // 2 more minutes pass (6 min since unlock, but only 2 min since activity)
        currentTime += (2 * 60)
        controller.tick()
        XCTAssertFalse(controller.isLocked)

        // 3 more minutes pass (5 min since activity) -> should lock
        currentTime += (3 * 60)
        controller.tick()
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(controller.lastLockReason, .idle)
    }

    func test_003_AC6_disablingRequiresFreshAuthentication() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        XCTAssertEqual(fakeAuth.authCount, 1)

        // Disabling while unlocked requires fresh authentication
        let success = await controller.setEnabled(false)
        XCTAssertTrue(success)
        XCTAssertEqual(fakeAuth.authCount, 2)
        XCTAssertEqual(fakeAuth.lastReason, ClavisUIStrings.PanelLock.disableReason)
        XCTAssertFalse(controller.isEnabled)
        XCTAssertFalse(controller.isLocked)

        // When disabled, isLocked is false regardless of state
        controller.lock(reason: .lockNow)
        XCTAssertFalse(controller.isLocked)

        // Re-enabling does not require authentication
        let enabledSuccess = await controller.setEnabled(true)
        XCTAssertTrue(enabledSuccess)
        XCTAssertEqual(fakeAuth.authCount, 2)
        XCTAssertTrue(controller.isEnabled)
        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(controller.lastLockReason, .disabledChange)

        // Failed auth when disabling leaves lock enabled
        fakeAuth.shouldFail = true
        let failSuccess = await controller.setEnabled(false)
        XCTAssertFalse(failSuccess)
        XCTAssertEqual(fakeAuth.authCount, 3)
        XCTAssertTrue(controller.isEnabled)
        XCTAssertTrue(controller.isLocked)
    }

    func test_003_T1_idleMinutesClampsToOptions() {
        let controller = PanelLockController(defaults: testDefaults)
        XCTAssertEqual(controller.idleMinutes, 5)

        controller.idleMinutes = 1
        XCTAssertEqual(controller.idleMinutes, 1)

        controller.idleMinutes = 15
        XCTAssertEqual(controller.idleMinutes, 15)

        controller.idleMinutes = 60
        XCTAssertEqual(controller.idleMinutes, 60)

        controller.idleMinutes = 0
        XCTAssertEqual(controller.idleMinutes, 1)

        controller.idleMinutes = 100
        XCTAssertEqual(controller.idleMinutes, 60)

        controller.idleMinutes = 7
        XCTAssertEqual(controller.idleMinutes, 5)
    }

    func test_003_AC4_screenLockHandlerLocks() async {
        let fakeAuth = FakePanelAuthenticator()
        let fakeMonitor = FakeSystemEventMonitor()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        XCTAssertFalse(controller.isLocked)

        controller.installSystemEventHandler(monitor: fakeMonitor)
        XCTAssertNotNil(fakeMonitor.handlers["panel.lock"])

        fakeMonitor.fire(id: "panel.lock")
        for _ in 0..<10 {
            if controller.isLocked { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }

        XCTAssertTrue(controller.isLocked)
        XCTAssertEqual(controller.state, .locked)
        XCTAssertEqual(controller.lastLockReason, .screenLocked)
    }

    func test_003_T3_gateBuildsContentOnlyWhenUnlocked() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)
        var buildCount = 0

        let gate = PanelLockGate(lock: controller) {
            buildCount += 1
            return Text("Secret Content")
        }

        XCTAssertTrue(controller.isLocked)
        let hostingView = NSHostingView(rootView: gate)
        hostingView.layout()
        _ = gate.body
        XCTAssertEqual(buildCount, 0, "Content should not be built when locked")

        await controller.unlock()
        XCTAssertFalse(controller.isLocked)

        _ = gate.body
        hostingView.layout()
        XCTAssertGreaterThanOrEqual(buildCount, 1, "Content should be built when unlocked")
    }

    func test_003_AC5_lockedMenuShowsOnlyLockNowRevokeAndCount() {
        let lockedWithSessions = MenuBarSections.visible(isLocked: true, hasSessions: true)
        XCTAssertTrue(lockedWithSessions.contains(.lockNow))
        XCTAssertTrue(lockedWithSessions.contains(.revokeAll))
        XCTAssertTrue(lockedWithSessions.contains(.sessionCount))
        XCTAssertTrue(lockedWithSessions.contains(.unlock))
        XCTAssertTrue(lockedWithSessions.contains(.agentLifecycle))
        XCTAssertTrue(lockedWithSessions.contains(.quit))

        XCTAssertFalse(lockedWithSessions.contains(.identities))
        XCTAssertFalse(lockedWithSessions.contains(.gitBanner))
        XCTAssertFalse(lockedWithSessions.contains(.newKey))
        XCTAssertFalse(lockedWithSessions.contains(.importKey))
        XCTAssertFalse(lockedWithSessions.contains(.openKeyManager))
        XCTAssertFalse(lockedWithSessions.contains(.history))
        XCTAssertFalse(lockedWithSessions.contains(.settings))

        let lockedNoSessions = MenuBarSections.visible(isLocked: true, hasSessions: false)
        XCTAssertTrue(lockedNoSessions.contains(.lockNow))
        XCTAssertFalse(lockedNoSessions.contains(.revokeAll))
        XCTAssertFalse(lockedNoSessions.contains(.sessionCount))
    }

    func test_003_T4_unlockedMenuShowsEverything() {
        let unlockedWithSessions = MenuBarSections.visible(isLocked: false, hasSessions: true)
        XCTAssertTrue(unlockedWithSessions.contains(.identities))
        XCTAssertTrue(unlockedWithSessions.contains(.gitBanner))
        XCTAssertTrue(unlockedWithSessions.contains(.newKey))
        XCTAssertTrue(unlockedWithSessions.contains(.importKey))
        XCTAssertTrue(unlockedWithSessions.contains(.openKeyManager))
        XCTAssertTrue(unlockedWithSessions.contains(.agentLifecycle))
        XCTAssertTrue(unlockedWithSessions.contains(.history))
        XCTAssertTrue(unlockedWithSessions.contains(.settings))
        XCTAssertTrue(unlockedWithSessions.contains(.quit))
        XCTAssertTrue(unlockedWithSessions.contains(.lockNow))
        XCTAssertTrue(unlockedWithSessions.contains(.revokeAll))
        XCTAssertTrue(unlockedWithSessions.contains(.sessionCount))
        XCTAssertFalse(unlockedWithSessions.contains(.unlock))

        let unlockedNoSessions = MenuBarSections.visible(isLocked: false, hasSessions: false)
        XCTAssertTrue(unlockedNoSessions.contains(.identities))
        XCTAssertTrue(unlockedNoSessions.contains(.gitBanner))
        XCTAssertFalse(unlockedNoSessions.contains(.lockNow))
        XCTAssertFalse(unlockedNoSessions.contains(.sessionCount))
        XCTAssertFalse(unlockedNoSessions.contains(.revokeAll))
        XCTAssertFalse(unlockedNoSessions.contains(.unlock))
    }

    func test_003_C1_deleteStillPromptsWhenUnlocked() async throws {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)
        await controller.unlock()
        XCTAssertFalse(controller.isLocked)
        XCTAssertNotNil(controller.unlockContext)

        let countingAuth = CountingAuthenticator()
        let keyManager = makeKeyManager(authenticator: countingAuth)
        let testLabel = "c1-test-key-\(UUID().uuidString)"
        _ = try keyManager.generateKey(label: testLabel)

        let countBeforeDelete = countingAuth.authenticationCount
        try keyManager.deleteKey(label: testLabel)
        let countAfterDelete = countingAuth.authenticationCount

        XCTAssertEqual(countAfterDelete, countBeforeDelete + 1, "Deleting a key must still require its own authentication prompt even when the control panel is unlocked")
    }
}



