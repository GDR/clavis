import Foundation
import AppKit
import SwiftUI
import Testing
@preconcurrency import LocalAuthentication
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor
struct HaloLockAuthenticationTests {
    private func makeController(
        auth: PanelAuthenticating = FakePanelAuthenticator(),
        verifier: @escaping @Sendable (String) -> Bool = { _ in false },
        context: LAContext? = nil,
        keyring: AuditKeyring? = nil
    ) -> (PanelLockController, () -> Void) {
        let name = "clavis.halo-tests.\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        let controller = PanelLockController(
            defaults: defaults, authenticator: auth, keyring: keyring,
            recorder: InMemoryAuditRecorder(), vaultKeyCount: { 1 },
            loginPasswordVerifier: verifier,
            embeddedContextFactory: context.map { context in { context } }
        )
        return (controller, { defaults.removePersistentDomain(forName: name) })
    }

    @Test func embeddedEvaluationWaitsForMountedSystemView() async {
        let context = HaloTestLAContext()
        let (lock, cleanup) = makeController(auth: LAPanelAuthenticator(), context: context)
        defer { cleanup() }
        let request = Task { await lock.unlockIfNeededOnWindowFocus() }
        while lock.embeddedUnlockContext == nil { await Task.yield() }
        #expect(context.reply == nil)
        #expect(lock.embeddedUnlockContext === context)
        lock.embeddedUnlockViewDidMount(context)
        while context.reply == nil { await Task.yield() }
        #expect(context.policy == .deviceOwnerAuthenticationWithBiometrics)
        context.finish(success: true)
        await request.value
        #expect(!lock.isLocked)
        #expect(lock.unlockContext === context)
        #expect(lock.embeddedUnlockContext == nil)
    }

    @Test(arguments: [LAError.Code.biometryLockout, .authenticationFailed])
    func lockoutSurvivesRefocusReconstructionAndRepeatedLock(_ code: LAError.Code) async {
        let auth = FakePanelAuthenticator()
        auth.shouldFail = true
        auth.failureError = LAError(code)
        let (lock, cleanup) = makeController(auth: auth, verifier: { _ in true })
        defer { cleanup() }
        await lock.unlock()
        #expect(lock.biometricStatus == .locked)
        lock.cancelEmbeddedUnlock() // view removal / reconstruction
        lock.lockedWindowDidDeactivate()
        lock.lock(reason: .windowsClosed)
        for _ in 0..<5 {
            await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
            await lock.unlockIfNeededOnWindowFocus(isUserInitiatedOpen: true)
            await lock.unlock()
        }
        #expect(auth.authCount == 1)
        #expect(lock.biometricStatus == .locked)
        #expect(await lock.unlockWithLoginPassword("test-password"))
        #expect(!lock.isLocked)
    }

    @Test func unavailableSensorNeverStartsEvaluation() async {
        let context = HaloTestLAContext()
        context.availabilityError = .biometryNotAvailable
        let (lock, cleanup) = makeController(auth: LAPanelAuthenticator(), context: context)
        defer { cleanup() }
        await lock.unlock()
        #expect(lock.biometricStatus == .unavailable)
        #expect(context.reply == nil)
        #expect(lock.embeddedUnlockContext == nil)
        #expect(lock.isLocked)
    }

    @Test func systemLockoutIsHonouredBeforeMounting() async {
        let context = HaloTestLAContext()
        context.availabilityError = .biometryLockout
        let (lock, cleanup) = makeController(auth: LAPanelAuthenticator(), context: context)
        defer { cleanup() }
        await lock.unlock()
        #expect(lock.biometricStatus == .locked)
        #expect(context.reply == nil)
    }

    @Test func passwordSupersedesBiometricsAndRejectsLateSuccess() async {
        let auth = HaloSuspendedAuthenticator()
        let verifier = HaloBlockingVerifier()
        defer { verifier.release.signal() }
        let (lock, cleanup) = makeController(auth: auth, verifier: { verifier.verify($0) })
        defer { cleanup() }
        let biometric = Task { await lock.unlock() }
        while auth.reply == nil { await Task.yield() }
        let password = Task { await lock.unlockWithLoginPassword("test-password") }
        while !verifier.started { await Task.yield() }
        let staleContext = MockLAContext()
        auth.reply?.resume(returning: staleContext)
        await biometric.value
        #expect(lock.isLocked)
        #expect(staleContext.didInvalidate)
        #expect(lock.isVerifyingPassword)
        #expect(lock.isUnlocking, "Old biometric cleanup cannot clear the password's busy state")
        verifier.release.signal()
        #expect(await password.value)
        #expect(!lock.isLocked)
        #expect(!lock.isUnlocking)
    }

    @Test func backgroundingRejectsPendingPasswordSuccess() async {
        let verifier = HaloBlockingVerifier()
        defer { verifier.release.signal() }
        let (lock, cleanup) = makeController(verifier: { verifier.verify($0) })
        defer { cleanup() }
        let password = Task { await lock.unlockWithLoginPassword("test-password") }
        while !verifier.started { await Task.yield() }
        lock.lockedWindowDidDeactivate()
        verifier.release.signal()
        #expect(!(await password.value))
        #expect(lock.isLocked)
        #expect(!lock.isVerifyingPassword)
    }

    @Test func deactivationInvalidatesContextAndDiscardsLateBiometricSuccess() async {
        let context = HaloTestLAContext()
        let (lock, cleanup) = makeController(auth: LAPanelAuthenticator(), context: context)
        defer { cleanup() }
        let request = Task { await lock.unlock() }
        while lock.embeddedUnlockContext == nil { await Task.yield() }
        lock.embeddedUnlockViewDidMount(context)
        while context.reply == nil { await Task.yield() }
        lock.lockedWindowDidDeactivate()
        #expect(context.didInvalidate)
        context.finish(success: true)
        await request.value
        #expect(lock.isLocked)
        #expect(lock.unlockContext == nil)
        #expect(!lock.isUnlocking)
    }

    @Test func foregroundResumesWhenSystemCancellationArrivesBeforeDeactivation() async {
        let auth = FakePanelAuthenticator()
        auth.shouldFail = true
        auth.failureError = LAError(.systemCancel)
        let (lock, cleanup) = makeController(auth: auth)
        defer { cleanup() }
        await lock.unlockIfNeededOnWindowFocus()
        #expect(!lock.isUnlocking)
        lock.lockedWindowDidDeactivate()
        auth.shouldFail = false
        await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(auth.authCount == 2)
        #expect(!lock.isLocked)
    }

    @Test func oldEvaluationCannotClearReplacementContextOrLatchLockout() async {
        let first = HaloTestLAContext()
        let second = HaloTestLAContext()
        let suiteName = "clavis.halo-replacement.\(UUID())"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        var contexts = [first, second]
        let lock = PanelLockController(defaults: defaults, keyring: nil,
                                       recorder: InMemoryAuditRecorder(), vaultKeyCount: { 1 },
                                       embeddedContextFactory: { contexts.removeFirst() })
        let oldRequest = Task { await lock.unlockIfNeededOnWindowFocus() }
        while lock.embeddedUnlockContext == nil { await Task.yield() }
        lock.embeddedUnlockViewDidMount(first)
        while first.reply == nil { await Task.yield() }
        lock.lockedWindowDidDeactivate()
        let newRequest = Task { await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true) }
        while lock.embeddedUnlockContext == nil { await Task.yield() }
        lock.embeddedUnlockViewDidMount(second)
        while second.reply == nil { await Task.yield() }
        first.finish(success: false)
        await oldRequest.value
        #expect(lock.embeddedUnlockContext === second)
        #expect(lock.biometricStatus == .ready)
        #expect(lock.isUnlocking)
        second.finish(success: true)
        await newRequest.value
        #expect(!lock.isLocked)
    }

    @Test(arguments: [AuditReadMode.biometryOrPIN, .biometryAndPIN])
    func loginPasswordCannotBypassPINMode(_ mode: AuditReadMode) async throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        _ = try keyring.rotate(mode: mode)
        let (lock, cleanup) = makeController(verifier: { _ in true }, keyring: keyring)
        defer { cleanup() }
        #expect(!(await lock.unlockWithLoginPassword("test-password")))
        #expect(lock.isLocked)
    }

    @Test(arguments: [AuditReadMode.biometryOrPIN, .biometryAndPIN])
    func explicitLockRetainsPINModeAutomaticPromptSuppression(_ mode: AuditReadMode) async throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        _ = try keyring.rotate(mode: mode)
        let (lock, cleanup) = makeController(keyring: keyring)
        defer { cleanup() }
        lock.applyUnlock(context: nil)
        lock.lock(reason: .lockNow)
        await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(lock.isLocked)
        #expect(!lock.isUnlocking)
    }

    @Test func systemLockoutDistinguishesScopeAndRecoversViaSystemPasswordOrMacUnlock() async {
        // 1. Distinguish .authenticationFailed (.prompt) vs .biometryLockout (.system)
        let promptAuth = FakePanelAuthenticator()
        promptAuth.shouldFail = true
        promptAuth.failureError = LAError(.authenticationFailed)
        let (promptLock, cleanupPrompt) = makeController(auth: promptAuth)
        defer { cleanupPrompt() }
        await promptLock.unlock()
        #expect(promptLock.biometricStatus == .locked)
        #expect(promptLock.biometricLockoutScope == .prompt)

        // 2. Re-enable with system password clears .system lockout without unlocking panel
        let recoveryContext = MockLAContext()
        let sysAuth = HaloReturningContextAuthenticator(context: recoveryContext)
        let (sysLock, cleanupSys) = makeController(auth: sysAuth)
        defer { cleanupSys() }
        sysLock.handleEmbeddedAuthenticationError(LAError(.biometryLockout))
        #expect(sysLock.biometricStatus == .locked)
        #expect(sysLock.biometricLockoutScope == .system)

        let reEnabled = await sysLock.reEnableBiometricsWithSystemPassword()
        #expect(reEnabled)
        #expect(recoveryContext.didInvalidate)
        #expect(sysLock.isLocked)
        #expect(sysLock.biometricStatus == .ready)
        #expect(sysLock.biometricLockoutScope == nil)
        #expect(sysLock.biometricRecoveryMessage == "Touch ID re-enabled by macOS. Rest your finger on the sensor.")

        // 3. Clearing macOS lockout externally (e.g. ^⌘Q Mac unlock) re-arms on probe refresh
        let probeContext = HaloTestLAContext()
        probeContext.availabilityError = .biometryLockout
        let (macLock, cleanupMac) = makeController(auth: LAPanelAuthenticator(), context: probeContext)
        defer { cleanupMac() }
        await macLock.unlock()
        #expect(macLock.biometricStatus == .locked)
        #expect(macLock.biometricLockoutScope == .system)
        #expect(!macLock.refreshSystemBiometricLockoutIfCleared())
        probeContext.availabilityError = nil
        #expect(macLock.refreshSystemBiometricLockoutIfCleared())
        #expect(probeContext.didInvalidate)
        #expect(macLock.biometricStatus == .ready)
        #expect(macLock.biometricLockoutScope == nil)
        #expect(macLock.biometricRecoveryMessage == "Touch ID re-enabled by macOS. Rest your finger on the sensor.")
    }

    @Test func haloUsesOnlyCompositorAnimationsAndStopsThem() {
        let view = HaloReflectionNSView(frame: NSRect(x: 0, y: 0, width: 600, height: 420))
        view.layoutSubtreeIfNeeded()
        view.setAnimating(true)
        let layers = view.layer?.sublayers ?? []
        #expect(layers.count == 2)
        let rotatingColours = layers[0].sublayers!.first!
        #expect(layers[0].mask != nil, "The stationary field must feather the rotating colour")
        #expect((layers[0].animationKeys() ?? []).isEmpty, "The outer ellipse must not spin")
        for layer in [rotatingColours, layers[1]] {
            guard let contents = layer.contents else { Issue.record("Missing Halo bitmap"); continue }
            let image = contents as! CGImage
            guard let pixelData = image.dataProvider?.data else { Issue.record("Missing pixel data"); continue }
            let bytes = pixelData as Data
            var edgeAlpha: [UInt8] = []
            for x in 0..<image.width {
                edgeAlpha.append(bytes[x * 4 + 3])
                edgeAlpha.append(bytes[(image.height - 1) * image.bytesPerRow + x * 4 + 3])
            }
            for y in 0..<image.height {
                edgeAlpha.append(bytes[y * image.bytesPerRow + 3])
                edgeAlpha.append(bytes[y * image.bytesPerRow + (image.width - 1) * 4 + 3])
            }
            #expect(edgeAlpha.allSatisfy { $0 <= 1 }, "Rotating bitmap edges must be transparent")
            #expect(bytes.enumerated().contains { $0.offset % 4 == 3 && $0.element > 10 },
                    "Feathering must retain visible ambient colour")
        }
        #expect(rotatingColours.animation(forKey: "haloOrbit")?.duration == 42)
        #expect(layers[1].animation(forKey: "haloBreath")?.duration == 12)
        view.setAnimating(false)
        #expect(([rotatingColours] + layers).allSatisfy { ($0.animationKeys() ?? []).isEmpty })
        #expect(view.hitTest(.zero) == nil)
    }
}

private final class HaloSuspendedAuthenticator: PanelAuthenticating {
    var reply: CheckedContinuation<LAContext, Error>?
    func authenticate(reason: String) async throws -> LAContext {
        try await withCheckedThrowingContinuation { reply = $0 }
    }
}

private final class HaloReturningContextAuthenticator: PanelAuthenticating {
    let context: LAContext
    init(context: LAContext) { self.context = context }
    func authenticate(reason: String) async throws -> LAContext { context }
}

private final class HaloBlockingVerifier: @unchecked Sendable {
    let release = DispatchSemaphore(value: 0)
    private let mutex = NSLock()
    private var didStart = false
    var started: Bool { mutex.withLock { didStart } }
    func verify(_ password: String) -> Bool {
        mutex.withLock { didStart = true }
        release.wait()
        return true
    }
}

private final class HaloTestLAContext: LAContext {
    var availabilityError: LAError.Code?
    var policy: LAPolicy?
    var reply: (@Sendable (Bool, Error?) -> Void)?
    var didInvalidate = false
    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        if let availabilityError {
            error?.pointee = LAError(availabilityError) as NSError
            return false
        }
        return true
    }
    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String,
                                 reply: @escaping @Sendable (Bool, Error?) -> Void) {
        self.policy = policy
        self.reply = reply
    }
    override func invalidate() { didInvalidate = true }
    func finish(success: Bool) { reply?(success, success ? nil : LAError(.authenticationFailed)) }
}
