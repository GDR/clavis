import Foundation
@preconcurrency import LocalAuthentication
import OpenDirectory
import ClavisCore

public enum PanelLockReason: String, CaseIterable, Equatable {
    case windowsClosed
    case screenLocked
    case lockNow
    case idle
    case disabledChange
}

public protocol PanelAuthenticating {
    /// Evaluates .deviceOwnerAuthentication with a new LAContext and returns it.
    func authenticate(reason: String) async throws -> LAContext
}


public final class LAPanelAuthenticator: PanelAuthenticating {
    public init() {}

    public func authenticate(reason: String) async throws -> LAContext {
        #if DEBUG
        guard !ClavisEnvironment.isTesting else {
            throw UserAuthenticationError.testAuthenticationNotInjected
        }
        #endif
        ClavisLogger.promptDebug("calvis-ui", "LAPanelAuthenticator: prompting system authentication (reason: \"\(reason)\")")
        let context = LAContext()
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    ClavisLogger.promptDebug("calvis-ui", "LAPanelAuthenticator: prompt SUCCEEDED (reason: \"\(reason)\")")
                    continuation.resume(returning: context)
                } else {
                    ClavisLogger.promptDebug("calvis-ui", "LAPanelAuthenticator: prompt FAILED: \(String(describing: error)) (reason: \"\(reason)\")")
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }
}

@MainActor
public final class PanelLockController: ObservableObject {
    public static let shared = PanelLockController()

    public enum State: Equatable {
        case locked
        case unlocked(since: Date)
    }

    @Published public private(set) var state: State = .locked
    @Published public private(set) var isUnlocking: Bool = false
    public private(set) var unlockContext: LAContext?
    public private(set) var lastLockReason: PanelLockReason?

    public static let didLockNotification = NSNotification.Name("com.clavis.panelDidLock")
    public static let enabledKey = "panelLock.enabled"
    public static let idleMinutesKey = "panelLock.idleMinutes"
    public static let idleOptions = [1, 5, 15, 30, 60]

    private let defaults: UserDefaults
    private let authenticator: PanelAuthenticating
    private let keyring: AuditKeyring?
    public private(set) var pinUnlockService: PinUnlockService?
    private let recorder: AuditRecording
    private let now: () -> Date
    private var lastActivity: Date
    private var vaultKeyCountProvider: (() -> Int)?
    private let loginPasswordVerifier: @Sendable (String) -> Bool

    public var currentMode: AuditReadMode {
        (try? keyring?.currentMode()) ?? .passwordOrBiometry
    }

    @Published public private(set) var isEnabled: Bool {
        didSet {
            defaults.set(isEnabled, forKey: Self.enabledKey)
        }
    }

    @Published public var idleMinutes: Int {
        didSet {
            let clamped = Self.clampIdleMinutes(idleMinutes)
            if idleMinutes != clamped {
                idleMinutes = clamped
                return
            }
            defaults.set(idleMinutes, forKey: Self.idleMinutesKey)
        }
    }

    public var isLocked: Bool {
        isEnabled && state == .locked
    }

    /// Returns true if the lock gate should be bypassed because the vault contains 0 keys
    /// and no custom PIN policy is configured.
    public var shouldBypassLock: Bool {
        guard !currentMode.requiresPIN else { return false }
        guard let provider = vaultKeyCountProvider else { return false }
        return provider() == 0
    }

    /// Convenience alias for `shouldBypassLock`.
    public var isBypassed: Bool {
        shouldBypassLock
    }

    /// Indicates whether the panel is actively locked and not bypassed.
    public var isEffectivelyLocked: Bool {
        isLocked && !shouldBypassLock
    }

    public func setVaultKeyCountProvider(_ provider: @escaping () -> Int) {
        self.vaultKeyCountProvider = provider
    }

    public nonisolated static func makeDefaultKeyring() -> AuditKeyring? {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return nil
        }
        #endif
        return KeychainAuditKeyring()
    }

    public nonisolated static func makeDefaultVaultKeyCountProvider() -> (() -> Int)? {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return nil
        }
        #endif
        return { PublicKeyStore.loadAll().count }
    }

    /// Verifies the current macOS user's login password against local OpenDirectory without storing it.
    @Sendable public nonisolated static func verifyLocalAccountPassword(_ password: String) -> Bool {
        guard !password.isEmpty else { return false }
        do {
            let session = ODSession.default()
            let node = try ODNode(session: session, type: ODNodeType(kODNodeTypeLocalNodes))
            let record = try node.record(
                withRecordType: kODRecordTypeUsers,
                name: NSUserName(),
                attributes: nil
            )
            try record.verifyPassword(password)
            return true
        } catch {
            return false
        }
    }

    public init(
        defaults: UserDefaults = .standard,
        authenticator: PanelAuthenticating = LAPanelAuthenticator(),
        keyring: AuditKeyring? = PanelLockController.makeDefaultKeyring(),
        pinUnlockService: PinUnlockService? = nil,
        recorder: AuditRecording = AuditRecorder.shared,
        now: @escaping () -> Date = Date.init,
        vaultKeyCount: (() -> Int)? = PanelLockController.makeDefaultVaultKeyCountProvider(),
        loginPasswordVerifier: @escaping @Sendable (String) -> Bool = PanelLockController.verifyLocalAccountPassword
    ) {
        self.defaults = defaults
        self.authenticator = authenticator
        self.keyring = keyring
        self.recorder = recorder
        self.now = now
        self.vaultKeyCountProvider = vaultKeyCount
        self.loginPasswordVerifier = loginPasswordVerifier
        let currentTime = now()
        self.lastActivity = currentTime

        if let pinUnlockService = pinUnlockService {
            self.pinUnlockService = pinUnlockService
        } else if let keyring = keyring {
            self.pinUnlockService = PinUnlockService(
                keyring: keyring,
                counter: KeychainPinAttemptStore(),
                keyAuth: PanelKeyAuthenticator(keyring: keyring),
                passwordAuth: DevicePasswordAuthenticator(),
                now: now
            )
        }

        if let storedEnabled = defaults.object(forKey: Self.enabledKey) as? Bool {
            self.isEnabled = storedEnabled
        } else {
            self.isEnabled = true
        }

        let storedMinutes = defaults.object(forKey: Self.idleMinutesKey) as? Int ?? 5
        self.idleMinutes = Self.clampIdleMinutes(storedMinutes)
    }

    public static func clampIdleMinutes(_ minutes: Int) -> Int {
        if idleOptions.contains(minutes) {
            return minutes
        }
        if minutes <= 1 { return 1 }
        if minutes >= 60 { return 60 }
        return idleOptions.min(by: { abs($0 - minutes) <= abs($1 - minutes) }) ?? 5
    }

    public func unlock() async {
        guard isLocked, !shouldBypassLock else { return }
        if isUnlocking {
            while isUnlocking {
                await Task.yield()
            }
            return
        }

        let mode = (try? keyring?.currentMode()) ?? .passwordOrBiometry
        if mode.requiresPIN {
            // In PIN modes, the placeholder drives PinUnlockService
            return
        }

        let generation = promptLifecycle.beganManualAttempt()
        isUnlocking = true
        defer { isUnlocking = false }

        do {
            ClavisLogger.promptDebug("calvis-ui", "PanelLockController: requesting panel unlock prompt: \"\(ClavisUIStrings.PanelLock.reason)\"")
            let context = try await authenticator.authenticate(reason: ClavisUIStrings.PanelLock.reason)
            guard promptLifecycle.acceptsCompletion(from: generation) else {
                context.invalidate()
                return
            }
            applyUnlock(context: context)
        } catch {
            // Cancellation stays locked. Focus restoration is not a retry.
        }
    }

    private var promptLifecycle = PanelUnlockPromptLifecycle()

    /// One automatic attempt per locked period; explicit reopening may retry.
    public func unlockIfNeededOnWindowFocus(
        isWindowFocusEvent: Bool = false,
        isUserInitiatedOpen: Bool = false
    ) async {
        let trigger: PanelUnlockPromptLifecycle.Trigger = isUserInitiatedOpen
            ? .explicitOpen : (isWindowFocusEvent ? .windowFocus : .presentation)
        guard promptLifecycle.claimAutomaticAttempt(
            trigger: trigger, isLocked: isEffectivelyLocked, isAuthenticating: isUnlocking
        ) else { return }
        switch currentMode {
        case .passwordOrBiometry:
            await unlock()
        case .biometryOrPIN:
            _ = await unlockWithPIN(nil)
        case .biometryAndPIN:
            // Requires PIN entry first
            break
        }
    }

    @discardableResult
    public func authenticateUser(reason: String = ClavisUIStrings.PanelLock.reason) async throws -> LAContext {
        ClavisLogger.promptDebug("calvis-ui", "PanelLockController: authenticating user: \"\(reason)\"")
        let generation = promptLifecycle.beganManualAttempt()
        let context = try await authenticator.authenticate(reason: reason)
        guard promptLifecycle.acceptsCompletion(from: generation) else {
            context.invalidate()
            throw LAError(.appCancel)
        }
        applyUnlock(context: context)
        return context
    }

    @discardableResult
    public func unlockWithPIN(_ pin: String?) async -> PinUnlockService.Outcome {
        ClavisLogger.promptDebug("calvis-ui", "PanelLockController: attempting unlock with PIN")
        guard let service = pinUnlockService else {
            return isLocked ? .wrongPIN : .unlocked
        }
        isUnlocking = true
        defer { isUnlocking = false }

        let generation = promptLifecycle.beganManualAttempt()
        let (outcome, context) = await service.unlock(pin: pin)
        guard promptLifecycle.acceptsCompletion(from: generation) else {
            context?.invalidate()
            return .cancelled
        }
        if outcome == .unlocked {
            applyUnlock(context: context)
        }
        return outcome
    }

    @discardableResult
    public func unlockWithPassword() async -> PinUnlockService.Outcome {
        ClavisLogger.promptDebug("calvis-ui", "PanelLockController: attempting unlock with password")
        guard let service = pinUnlockService else {
            return isLocked ? .wrongPIN : .unlocked
        }
        isUnlocking = true
        defer { isUnlocking = false }

        let generation = promptLifecycle.beganManualAttempt()
        let (outcome, context) = await service.unlockWithPassword()
        guard promptLifecycle.acceptsCompletion(from: generation) else {
            context?.invalidate()
            return .cancelled
        }
        if outcome == .unlocked {
            applyUnlock(context: context)
        }
        return outcome
    }

    @discardableResult
    public func unlockWithLoginPassword(_ password: String) async -> Bool {
        guard isLocked, !shouldBypassLock else { return true }
        guard !password.isEmpty else { return false }
        if isUnlocking {
            while isUnlocking {
                await Task.yield()
            }
            return !isLocked
        }

        isUnlocking = true
        defer { isUnlocking = false }

        ClavisLogger.promptDebug("calvis-ui", "PanelLockController: verifying Mac login password via OpenDirectory")
        let generation = promptLifecycle.beganManualAttempt()
        let verifier = self.loginPasswordVerifier
        let verified = await Task.detached {
            verifier(password)
        }.value

        guard promptLifecycle.acceptsCompletion(from: generation) else { return false }
        if verified {
            applyUnlock(context: nil)
            return true
        }
        return false
    }

    public func applyUnlock(context: LAContext?) {
        self.unlockContext = context
        let currentTime = now()
        self.state = .unlocked(since: currentTime)
        self.lastActivity = currentTime

        let mode = (try? self.keyring?.currentMode()) ?? .passwordOrBiometry
        if mode == .passwordOrBiometry, let keyring = self.keyring, let context = context {
            let recorder = self.recorder
            Task.detached {
                let status = keyring.validateCurrent(context: context)
                switch status {
                case .ok:
                    break
                case .mismatch:
                    recorder.record(AuditEvent(type: .securityAlert, result: .info, reason: .auditKeyMismatch))
                    _ = try? keyring.rotate(mode: .passwordOrBiometry)
                case .unusable, .missing:
                    _ = try? keyring.rotate(mode: .passwordOrBiometry)
                }
            }
        }
    }

    public func lock(reason: PanelLockReason) {
        promptLifecycle.didLock(wasAlreadyLocked: isLocked, suppressAutomaticAttempt: reason == .lockNow || reason == .idle)
        lastLockReason = reason
        unlockContext?.invalidate()
        unlockContext = nil
        state = .locked
        NotificationCenter.default.post(name: Self.didLockNotification, object: self)
    }

    public func installSystemEventHandler(monitor: SystemEventMonitoring) {
        monitor.addHandler(id: "panel.lock") { [weak self] in
            Task { @MainActor [weak self] in
                self?.lock(reason: .screenLocked)
            }
        }
    }

    public func noteActivity() {
        lastActivity = now()
    }

    public func tick() {
        guard case .unlocked = state else { return }
        let elapsed = now().timeIntervalSince(lastActivity)
        if elapsed >= Double(idleMinutes * 60) {
            lock(reason: .idle)
        }
    }

    public func setEnabled(_ enabled: Bool, authenticated: Bool = false) async -> Bool {
        if enabled == isEnabled {
            return true
        }
        if enabled {
            isEnabled = true
            lock(reason: .disabledChange)
            return true
        } else {
            if !authenticated {
                do {
                    ClavisLogger.promptDebug("calvis-ui", "PanelLockController: requesting disable lock prompt: \"\(ClavisUIStrings.PanelLock.disableReason)\"")
                    _ = try await authenticator.authenticate(reason: ClavisUIStrings.PanelLock.disableReason)
                } catch {
                    return false
                }
            }
            isEnabled = false
            return true
        }
    }
}
