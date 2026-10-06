import Foundation
@preconcurrency import LocalAuthentication
import ClavisCore

public enum PanelLockReason: String, CaseIterable, Equatable {
    case windowsClosed
    case screenLocked
    case lockNow
    case idle
    case disabledChange
}

public protocol SystemEventMonitoring: AnyObject {
    func addHandler(id: String, handler: @escaping () -> Void)
}

extension SystemEventMonitor: SystemEventMonitoring {}

public protocol PanelAuthenticating {
    /// Evaluates .deviceOwnerAuthentication with a new LAContext and returns it.
    func authenticate(reason: String) async throws -> LAContext
}


public final class LAPanelAuthenticator: PanelAuthenticating {
    public init() {}

    public func authenticate(reason: String) async throws -> LAContext {
        let context = LAContext()
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    continuation.resume(returning: context)
                } else {
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
    public static let idleOptions = [1, 5, 15, 60]

    private let defaults: UserDefaults
    private let authenticator: PanelAuthenticating
    private let keyring: AuditKeyring?
    private let recorder: AuditRecording
    private let now: () -> Date
    private var lastActivity: Date

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

    public nonisolated static func makeDefaultKeyring() -> AuditKeyring? {
        if NSClassFromString("XCTestCase") != nil || ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            return nil
        }
        return KeychainAuditKeyring()
    }

    public init(
        defaults: UserDefaults = .standard,
        authenticator: PanelAuthenticating = LAPanelAuthenticator(),
        keyring: AuditKeyring? = PanelLockController.makeDefaultKeyring(),
        recorder: AuditRecording = AuditRecorder.shared,
        now: @escaping () -> Date = Date.init
    ) {
        self.defaults = defaults
        self.authenticator = authenticator
        self.keyring = keyring
        self.recorder = recorder
        self.now = now
        let currentTime = now()
        self.lastActivity = currentTime

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
        guard isLocked else { return }
        if isUnlocking {
            while isUnlocking {
                await Task.yield()
            }
            return
        }

        isUnlocking = true
        defer { isUnlocking = false }

        do {
            let context = try await authenticator.authenticate(reason: ClavisUIStrings.PanelLock.reason)
            self.unlockContext = context
            let currentTime = now()
            self.state = .unlocked(since: currentTime)
            self.lastActivity = currentTime

            if let keyring = self.keyring {
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
        } catch {
            // Cancelled or failed unlock stays locked without error alert
        }
    }

    public func lock(reason: PanelLockReason) {
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

    public func setEnabled(_ enabled: Bool) async -> Bool {
        if enabled == isEnabled {
            return true
        }
        if enabled {
            isEnabled = true
            lock(reason: .disabledChange)
            return true
        } else {
            do {
                _ = try await authenticator.authenticate(reason: ClavisUIStrings.PanelLock.disableReason)
                isEnabled = false
                return true
            } catch {
                return false
            }
        }
    }
}
