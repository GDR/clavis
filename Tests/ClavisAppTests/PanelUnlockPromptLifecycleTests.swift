import Foundation
import LocalAuthentication
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor
struct PanelUnlockPromptLifecycleTests {
    private func controller(auth: PanelAuthenticating, now: @escaping () -> Date = Date.init) -> (PanelLockController, UserDefaults, String) {
        let name = "clavis.tests.prompt-lifecycle.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        let controller = PanelLockController(
            defaults: defaults, authenticator: auth, keyring: nil,
            recorder: InMemoryAuditRecorder(), now: now, vaultKeyCount: { 1 }
        )
        return (controller, defaults, name)
    }

    @Test func productionAuthenticationAdaptersCannotPromptFromTests() async throws {
        try #require(ClavisEnvironment.isTesting)
        let core = LocalUserAuthenticator()
        let synchronous: () throws -> LAContext = { try core.authenticate(reason: "Must not prompt") }
        #expect(throws: (any Error).self) { try synchronous() }
        await #expect(throws: (any Error).self) {
            try await core.authenticate(reason: "Must not prompt")
        }
        await #expect(throws: (any Error).self) {
            try await LAPanelAuthenticator().authenticate(reason: "Must not prompt")
        }
    }

    @Test func initialPresentationClaimsExactlyOneAttempt() {
        var gate = PanelUnlockPromptLifecycle()
        let claimed1 = gate.claimAutomaticAttempt(trigger: .presentation, isLocked: true, isAuthenticating: false)
        #expect(claimed1)
        for _ in 0..<100 {
            let claimed2 = gate.claimAutomaticAttempt(trigger: .windowFocus, isLocked: true, isAuthenticating: false)
            #expect(!claimed2)
            let claimed3 = gate.claimAutomaticAttempt(trigger: .presentation, isLocked: true, isAuthenticating: false)
            #expect(!claimed3)
        }
    }

    @Test func explicitReopenRetriesButFocusDoesNot() {
        var gate = PanelUnlockPromptLifecycle()
        _ = gate.claimAutomaticAttempt(trigger: .presentation, isLocked: true, isAuthenticating: false)
        let claimed4 = gate.claimAutomaticAttempt(trigger: .windowFocus, isLocked: true, isAuthenticating: false)
        #expect(!claimed4)
        let claimed5 = gate.claimAutomaticAttempt(trigger: .explicitOpen, isLocked: true, isAuthenticating: false)
        #expect(claimed5)
        let claimed6 = gate.claimAutomaticAttempt(trigger: .windowFocus, isLocked: true, isAuthenticating: false)
        #expect(!claimed6)
    }

    @Test func busyOrUnlockedEventsDoNotResetConsumedAttempt() {
        var gate = PanelUnlockPromptLifecycle()
        _ = gate.beganManualAttempt()
        let claimed7 = gate.claimAutomaticAttempt(trigger: .explicitOpen, isLocked: true, isAuthenticating: true)
        #expect(!claimed7)
        let claimed8 = gate.claimAutomaticAttempt(trigger: .explicitOpen, isLocked: false, isAuthenticating: false)
        #expect(!claimed8)
        #expect(gate.automaticAttemptConsumed)
    }

    @Test func repeatedLockNotificationsDoNotRestartPrompting() {
        var gate = PanelUnlockPromptLifecycle()
        let original = gate.beganManualAttempt()
        gate.didLock(wasAlreadyLocked: true)
        #expect(!gate.acceptsCompletion(from: original))
        let claimed9 = gate.claimAutomaticAttempt(trigger: .windowFocus, isLocked: true, isAuthenticating: false)
        #expect(!claimed9)
        gate.didLock(wasAlreadyLocked: false)
        let claimed10 = gate.claimAutomaticAttempt(trigger: .presentation, isLocked: true, isAuthenticating: false)
        #expect(claimed10)
    }

    @Test func deliberateLockSuppressesAutomaticAuthenticationUntilReopen() {
        var gate = PanelUnlockPromptLifecycle()
        gate.didLock(wasAlreadyLocked: false, suppressAutomaticAttempt: true)
        let claimed11 = gate.claimAutomaticAttempt(trigger: .presentation, isLocked: true, isAuthenticating: false)
        #expect(!claimed11)
        let claimed12 = gate.claimAutomaticAttempt(trigger: .windowFocus, isLocked: true, isAuthenticating: false)
        #expect(!claimed12)
        let claimed13 = gate.claimAutomaticAttempt(trigger: .explicitOpen, isLocked: true, isAuthenticating: false)
        #expect(claimed13)
    }

    @Test func cancelledLoginDoesNotRepromptAfterAnyElapsedTime() async {
        let auth = FakePanelAuthenticator()
        auth.shouldFail = true
        var time = Date(timeIntervalSince1970: 1_000)
        let (lock, defaults, name) = controller(auth: auth, now: { time })
        defer { defaults.removePersistentDomain(forName: name) }
        await lock.unlockIfNeededOnWindowFocus()
        #expect(auth.authCount == 1)
        for seconds in [0.1, 2.0, 60.0, 3_600.0] {
            time = time.addingTimeInterval(seconds)
            await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
            await lock.unlockIfNeededOnWindowFocus()
        }
        #expect(auth.authCount == 1)
        #expect(lock.isLocked)
    }

    @Test func explicitUnlockRemainsAvailableAfterCancellation() async {
        let auth = FakePanelAuthenticator()
        auth.shouldFail = true
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        await lock.unlockIfNeededOnWindowFocus()
        auth.shouldFail = false
        await lock.unlock()
        #expect(auth.authCount == 2)
        #expect(!lock.isLocked)
    }

    @Test func deliberateReopenCanRetryFailedAutomaticLogin() async {
        let auth = FakePanelAuthenticator()
        auth.shouldFail = true
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        await lock.unlockIfNeededOnWindowFocus()
        await lock.unlockIfNeededOnWindowFocus(isUserInitiatedOpen: true)
        #expect(auth.authCount == 2)
        await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(auth.authCount == 2)
    }

    @Test(arguments: [PanelLockReason.idle, .lockNow])
    func explicitLockDoesNotImmediatelyUnlockItself(_ reason: PanelLockReason) async {
        let auth = FakePanelAuthenticator()
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        lock.applyUnlock(context: nil)
        lock.lock(reason: reason)
        await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(auth.authCount == 0)
        #expect(lock.isLocked)
        await lock.unlockIfNeededOnWindowFocus(isUserInitiatedOpen: true)
        #expect(auth.authCount == 1)
    }

    @Test func focusStormWhileAuthenticationIsPendingStartsOneRequest() async {
        let auth = SuspendedPanelAuthenticator()
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        let request = Task { await lock.unlockIfNeededOnWindowFocus() }
        while auth.continuation == nil { await Task.yield() }
        for _ in 0..<100 {
            await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        }
        #expect(auth.count == 1)
        auth.continuation?.resume(throwing: LAError(.userCancel))
        await request.value
        #expect(lock.isLocked)
        #expect(!lock.isUnlocking)
    }

    @Test func newLockDiscardsSuccessfulPendingAuthentication() async {
        let auth = SuspendedPanelAuthenticator()
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        let request = Task { await lock.unlock() }
        while auth.continuation == nil { await Task.yield() }
        lock.lock(reason: .screenLocked)
        let context = MockLAContext()
        auth.continuation?.resume(returning: context)
        await request.value
        #expect(context.didInvalidate)
        #expect(lock.isLocked)
        #expect(lock.unlockContext == nil)
    }

    @Test func settingsAuthenticationCannotUnlockAfterScreenLock() async {
        let auth = SuspendedPanelAuthenticator()
        let (lock, defaults, name) = controller(auth: auth)
        defer { defaults.removePersistentDomain(forName: name) }
        let request = Task {
            do { _ = try await lock.authenticateUser(); return false }
            catch { return true }
        }
        while auth.continuation == nil { await Task.yield() }
        lock.lock(reason: .screenLocked)
        let context = MockLAContext()
        auth.continuation?.resume(returning: context)
        #expect(await request.value)
        #expect(context.didInvalidate)
        #expect(lock.isLocked)
    }
}

private final class SuspendedPanelAuthenticator: PanelAuthenticating {
    var count = 0
    var continuation: CheckedContinuation<LAContext, Error>?
    func authenticate(reason: String) async throws -> LAContext {
        count += 1
        return try await withCheckedThrowingContinuation { continuation = $0 }
    }
}
