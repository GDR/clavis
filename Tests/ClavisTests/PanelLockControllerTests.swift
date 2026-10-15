import Testing
import SwiftUI
import CryptoKit
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

@Suite @MainActor
final class PanelLockControllerTests {
    private let fixture: ClavisTestFixture
    private let suiteName: String
    nonisolated(unsafe) private let testDefaults: UserDefaults

    init() throws {
        self.fixture = try ClavisTestFixture()
        let suite = "com.clavis.tests.panelLock.\(UUID().uuidString)"
        self.suiteName = suite
        self.testDefaults = UserDefaults(suiteName: suite)!
    }

    deinit {
        testDefaults.removePersistentDomain(forName: suiteName)
        fixture.cleanup()
    }

    @Test func test_003_AC7_freshInstallIsLocked() {
        let controller = PanelLockController(defaults: testDefaults)
        #expect(controller.isEnabled)
        #expect(controller.state == .locked)
        #expect(controller.isLocked)
        #expect(controller.unlockContext == nil)
        #expect(controller.idleMinutes == 5)
    }

    @Test func test_003_AC1_unlockRequiresAuthentication() async {
        let fakeAuth = FakePanelAuthenticator()
        let mockContext = MockLAContext()
        fakeAuth.contextToReturn = mockContext
        let currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        #expect(controller.isLocked)
        await controller.unlock()

        #expect(fakeAuth.authCount == 1)
        #expect(fakeAuth.lastReason == ClavisUIStrings.PanelLock.reason)
        #expect(controller.state == .unlocked(since: currentTime))
        #expect(!controller.isLocked)
        #expect(controller.unlockContext === mockContext)
    }

    @Test func test_003_AC1_cancelledUnlockStaysLocked() async {
        let fakeAuth = FakePanelAuthenticator()
        fakeAuth.shouldFail = true
        fakeAuth.failureError = LAError(.userCancel)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        #expect(controller.isLocked)
        await controller.unlock()

        #expect(fakeAuth.authCount == 1)
        #expect(controller.state == .locked)
        #expect(controller.isLocked)
        #expect(controller.unlockContext == nil)
    }

    @Test func test_003_AC4_lockInvalidatesContext() async {
        let fakeAuth = FakePanelAuthenticator()
        let mockContext = MockLAContext()
        fakeAuth.contextToReturn = mockContext
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        #expect(controller.unlockContext != nil)
        #expect(!mockContext.didInvalidate)

        controller.lock(reason: .lockNow)
        #expect(mockContext.didInvalidate)
        #expect(controller.unlockContext == nil)
        #expect(controller.state == .locked)
        #expect(controller.isLocked)
        #expect(controller.lastLockReason == .lockNow)
    }

    @Test func test_003_AC4_idleLocksAfterTimeout() async {
        let fakeAuth = FakePanelAuthenticator()
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        await controller.unlock()
        #expect(!controller.isLocked)

        // 5 minutes - 1 second: should remain unlocked
        currentTime += (5 * 60 - 1)
        controller.tick()
        #expect(!controller.isLocked)

        // 2 seconds later (5 min + 1 sec total): should lock
        currentTime += 2
        controller.tick()
        #expect(controller.isLocked)
        #expect(controller.state == .locked)
        #expect(controller.lastLockReason == .idle)
    }

    @Test func test_003_AC4_activityResetsIdle() async {
        let fakeAuth = FakePanelAuthenticator()
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth, now: { currentTime })

        await controller.unlock()
        #expect(!controller.isLocked)

        // 4 minutes pass
        currentTime += (4 * 60)
        controller.tick()
        #expect(!controller.isLocked)

        // User activity happens
        controller.noteActivity()

        // 2 more minutes pass (6 min since unlock, but only 2 min since activity)
        currentTime += (2 * 60)
        controller.tick()
        #expect(!controller.isLocked)

        // 3 more minutes pass (5 min since activity) -> should lock
        currentTime += (3 * 60)
        controller.tick()
        #expect(controller.isLocked)
        #expect(controller.lastLockReason == .idle)
    }

    @Test func test_003_AC6_disablingRequiresFreshAuthentication() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        #expect(fakeAuth.authCount == 1)

        // Disabling while unlocked requires fresh authentication
        let success = await controller.setEnabled(false)
        #expect(success)
        #expect(fakeAuth.authCount == 2)
        #expect(fakeAuth.lastReason == ClavisUIStrings.PanelLock.disableReason)
        #expect(!controller.isEnabled)
        #expect(!controller.isLocked)

        // When disabled, isLocked is false regardless of state
        controller.lock(reason: .lockNow)
        #expect(!controller.isLocked)

        // Re-enabling does not require authentication
        let enabledSuccess = await controller.setEnabled(true)
        #expect(enabledSuccess)
        #expect(fakeAuth.authCount == 2)
        #expect(controller.isEnabled)
        #expect(controller.isLocked)
        #expect(controller.lastLockReason == .disabledChange)

        // Failed auth when disabling leaves lock enabled
        fakeAuth.shouldFail = true
        let failSuccess = await controller.setEnabled(false)
        #expect(!failSuccess)
        #expect(fakeAuth.authCount == 3)
        #expect(controller.isEnabled)
        #expect(controller.isLocked)
    }

    @Test func test_003_T1_idleMinutesClampsToOptions() {
        let controller = PanelLockController(defaults: testDefaults)
        #expect(controller.idleMinutes == 5)

        controller.idleMinutes = 1
        #expect(controller.idleMinutes == 1)

        controller.idleMinutes = 15
        #expect(controller.idleMinutes == 15)

        controller.idleMinutes = 60
        #expect(controller.idleMinutes == 60)

        controller.idleMinutes = 0
        #expect(controller.idleMinutes == 1)

        controller.idleMinutes = 100
        #expect(controller.idleMinutes == 60)

        controller.idleMinutes = 7
        #expect(controller.idleMinutes == 5)
    }

    @Test func test_003_AC4_screenLockHandlerLocks() async {
        let fakeAuth = FakePanelAuthenticator()
        let fakeMonitor = FakeSystemEventMonitor()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        #expect(!controller.isLocked)

        controller.installSystemEventHandler(monitor: fakeMonitor)
        #expect(fakeMonitor.handlers["panel.lock"] != nil)

        fakeMonitor.fire(id: "panel.lock")
        for _ in 0..<10 {
            if controller.isLocked { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(controller.isLocked)
        #expect(controller.state == .locked)
        #expect(controller.lastLockReason == .screenLocked)
    }

    @Test func test_003_T3_gateBuildsContentOnlyWhenUnlocked() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)
        var buildCount = 0

        let gate = PanelLockGate(lock: controller) {
            buildCount += 1
            return Text("Secret Content")
        }

        #expect(controller.isLocked)
        let hostingView = NSHostingView(rootView: gate)
        hostingView.layout()
        _ = gate.body
        #expect(buildCount == 0, "Content should not be built when locked")

        await controller.unlock()
        #expect(!controller.isLocked)

        _ = gate.body
        hostingView.layout()
        #expect(buildCount >= 1, "Content should be built when unlocked")
    }

    @Test func test_003_AC5_lockedMenuShowsOnlyLockNowRevokeAndCount() {
        let lockedWithSessions = MenuBarSections.visible(isLocked: true, hasSessions: true)
        #expect(lockedWithSessions.contains(.lockNow))
        #expect(lockedWithSessions.contains(.revokeAll))
        #expect(lockedWithSessions.contains(.sessionCount))
        #expect(lockedWithSessions.contains(.unlock))
        #expect(lockedWithSessions.contains(.agentLifecycle))
        #expect(lockedWithSessions.contains(.quit))

        #expect(!lockedWithSessions.contains(.identities))
        #expect(!lockedWithSessions.contains(.gitBanner))
        #expect(!lockedWithSessions.contains(.newKey))
        #expect(!lockedWithSessions.contains(.openKeyManager))
        #expect(!lockedWithSessions.contains(.history))
        #expect(!lockedWithSessions.contains(.settings))

        let lockedNoSessions = MenuBarSections.visible(isLocked: true, hasSessions: false)
        #expect(lockedNoSessions.contains(.lockNow))
        #expect(!lockedNoSessions.contains(.revokeAll))
        #expect(!lockedNoSessions.contains(.sessionCount))
    }

    @Test func test_003_T4_unlockedMenuShowsEverything() {
        let unlockedWithSessions = MenuBarSections.visible(isLocked: false, hasSessions: true)
        #expect(unlockedWithSessions.contains(.identities))
        #expect(unlockedWithSessions.contains(.gitBanner))
        #expect(unlockedWithSessions.contains(.newKey))
        #expect(unlockedWithSessions.contains(.openKeyManager))
        #expect(unlockedWithSessions.contains(.agentLifecycle))
        #expect(unlockedWithSessions.contains(.history))
        #expect(unlockedWithSessions.contains(.settings))
        #expect(unlockedWithSessions.contains(.quit))
        #expect(unlockedWithSessions.contains(.lockNow))
        #expect(unlockedWithSessions.contains(.revokeAll))
        #expect(unlockedWithSessions.contains(.sessionCount))
        #expect(!unlockedWithSessions.contains(.unlock))

        let unlockedNoSessions = MenuBarSections.visible(isLocked: false, hasSessions: false)
        #expect(unlockedNoSessions.contains(.identities))
        #expect(unlockedNoSessions.contains(.gitBanner))
        #expect(!unlockedNoSessions.contains(.lockNow))
        #expect(!unlockedNoSessions.contains(.sessionCount))
        #expect(!unlockedNoSessions.contains(.revokeAll))
        #expect(!unlockedNoSessions.contains(.unlock))
    }

    @Test func test_003_C1_deleteStillPromptsWhenUnlocked() async throws {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)
        await controller.unlock()
        #expect(!controller.isLocked)
        #expect(controller.unlockContext != nil)

        let countingAuth = CountingAuthenticator()
        let keyManager = fixture.makeKeyManager(authenticator: countingAuth)
        let testLabel = "c1-test-key-\(UUID().uuidString)"
        _ = try keyManager.generateKey(label: testLabel)

        let countBeforeDelete = countingAuth.authenticationCount
        try keyManager.deleteKey(label: testLabel)
        let countAfterDelete = countingAuth.authenticationCount

        #expect(countAfterDelete == countBeforeDelete + 1, "Deleting a key must still require its own authentication prompt even when the control panel is unlocked")
    }

    @Test func test_008_T5_unlockValidatesKeyringAndRotatesOnMismatch() async throws {
        let fakeAuth = FakePanelAuthenticator()
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let recorder = InMemoryAuditRecorder()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            keyring: keyring,
            recorder: recorder
        )

        let initialKey = try keyring.currentPublicKey()
        let intruderKey = P256.KeyAgreement.PrivateKey()
        keyring.tamperPublicKey(for: initialKey.keyID, with: intruderKey.publicKey)

        await controller.unlock()

        for _ in 0..<50 {
            if !recorder.events.isEmpty { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(recorder.events.count == 1)
        #expect(recorder.events.first?.type == .securityAlert)
        #expect(recorder.events.first?.reason == .auditKeyMismatch)

        let rotatedKey = try keyring.currentPublicKey()
        #expect(rotatedKey.keyID != initialKey.keyID)
    }

    @Test func test_008_T5_unlockRotatesOnMissingKey() async throws {
        let fakeAuth = FakePanelAuthenticator()
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let recorder = InMemoryAuditRecorder()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            keyring: keyring,
            recorder: recorder
        )

        let initialKey = try keyring.currentPublicKey()
        keyring.dropKey(keyID: initialKey.keyID)

        await controller.unlock()

        for _ in 0..<50 {
            let cur = try keyring.currentPublicKey()
            if cur.keyID != initialKey.keyID { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        let rotatedKey = try keyring.currentPublicKey()
        #expect(rotatedKey.keyID != initialKey.keyID)
        #expect(recorder.events.isEmpty)
    }

    @Test func test_setEnabled_false_whenAuthenticated_doesNotPrompt() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)

        await controller.unlock()
        #expect(fakeAuth.authCount == 1)

        // Disabling with authenticated: true should NOT invoke authenticator again
        let success = await controller.setEnabled(false, authenticated: true)
        #expect(success)
        #expect(fakeAuth.authCount == 1)
        #expect(!controller.isEnabled)
        #expect(!controller.isLocked)
    }

    @Test func test_authenticateUser_success_appliesUnlock() async throws {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(defaults: testDefaults, authenticator: fakeAuth)
        #expect(controller.isLocked)

        _ = try await controller.authenticateUser()
        #expect(fakeAuth.authCount == 1)
        #expect(!controller.isLocked)
    }
}
