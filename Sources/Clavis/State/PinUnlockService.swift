import Foundation
@preconcurrency import LocalAuthentication
import Security
import ClavisCore

public protocol PanelKeyAuthenticating: Sendable {
    /// D3: new LAContext, setCredential if pin != nil, evaluateAccessControl, then keyring.validateCurrent.
    func authenticate(mode: AuditReadMode, pin: String?, reason: String) async throws -> LAContext
}

public protocol PasswordAuthenticating: Sendable {
    /// D4: authenticate with device password / passcode.
    func authenticateWithPassword(reason: String) async throws -> LAContext
}

public final class PanelKeyAuthenticator: PanelKeyAuthenticating, @unchecked Sendable {
    private let keyring: AuditKeyring

    public init(keyring: AuditKeyring) {
        self.keyring = keyring
    }

    public func authenticate(mode: AuditReadMode, pin: String?, reason: String) async throws -> LAContext {
        let context = LAContext()
        if let pin = pin {
            _ = context.setCredential(Data(pin.utf8), type: .applicationPassword)
        }
        let ac = try keyring.accessControl(for: mode)
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluateAccessControl(ac, operation: .useKeyKeyExchange, localizedReason: reason) { success, error in
                if success {
                    let validation = self.keyring.validateCurrent(context: context)
                    if validation == .ok {
                        continuation.resume(returning: context)
                    } else {
                        continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                    }
                } else {
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }
}

public final class DevicePasswordAuthenticator: PasswordAuthenticating, @unchecked Sendable {
    public init() {}

    public func authenticateWithPassword(reason: String) async throws -> LAContext {
        let context = LAContext()
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .devicePasscode,
            &error
        ) else {
            return try await fallbackDeviceOwnerAuth(context: context, reason: reason)
        }
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluateAccessControl(ac, operation: .useItem, localizedReason: reason) { success, error in
                if success {
                    continuation.resume(returning: context)
                } else {
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }

    private func fallbackDeviceOwnerAuth(context: LAContext, reason: String) async throws -> LAContext {
        try await withCheckedThrowingContinuation { continuation in
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
public final class PinUnlockService: ObservableObject {
    public enum Outcome: Equatable, Sendable {
        case unlocked
        case wrongPIN
        case wait(TimeInterval)
        case passwordRequired
        case cancelled
    }

    private let keyring: AuditKeyring
    private let counter: PinAttemptStoring
    private let keyAuth: PanelKeyAuthenticating
    private let passwordAuth: PasswordAuthenticating
    private let now: () -> Date

    public init(
        keyring: AuditKeyring,
        counter: PinAttemptStoring,
        keyAuth: PanelKeyAuthenticating,
        passwordAuth: PasswordAuthenticating,
        now: @escaping () -> Date = Date.init
    ) {
        self.keyring = keyring
        self.counter = counter
        self.keyAuth = keyAuth
        self.passwordAuth = passwordAuth
        self.now = now
    }

    public func unlock(pin: String?) async -> (Outcome, LAContext?) {
        let currentState = try? counter.load()
        let decision = PinAttemptPolicy.decide(currentState, now: now())
        switch decision {
        case .passwordRequired:
            return (.passwordRequired, nil)
        case .wait(let remaining):
            return (.wait(remaining), nil)
        case .allowed:
            break
        }

        if let pin = pin {
            guard pin.count >= 6 && pin.count <= 64 else {
                return (.wrongPIN, nil)
            }
            let prevAttempts = currentState?.attempts ?? 0
            let nextState = PinAttemptState(attempts: prevAttempts + 1, lastAttemptAt: now().timeIntervalSince1970)
            do {
                try counter.save(nextState)
            } catch {
                return (.passwordRequired, nil)
            }
        }

        let mode = (try? keyring.currentMode()) ?? .biometryOrPIN
        let reason = ClavisUIStrings.PanelLock.reason

        do {
            let context = try await keyAuth.authenticate(mode: mode, pin: pin, reason: reason)
            if pin != nil {
                try? counter.save(PinAttemptState(attempts: 0, lastAttemptAt: now().timeIntervalSince1970))
            }
            return (.unlocked, context)
        } catch let laError as LAError where laError.code == .userCancel || laError.code == .appCancel || laError.code == .systemCancel {
            if pin != nil {
                if let prev = currentState {
                    try? counter.save(prev)
                } else {
                    try? counter.delete()
                }
            }
            return (.cancelled, nil)
        } catch {
            return (.wrongPIN, nil)
        }
    }

    public func unlockWithPassword() async -> (Outcome, LAContext?) {
        let reason = ClavisUIStrings.PanelLock.reason
        do {
            let context = try await passwordAuth.authenticateWithPassword(reason: reason)
            try? counter.save(PinAttemptState(attempts: 0, lastAttemptAt: now().timeIntervalSince1970))
            return (.unlocked, context)
        } catch let laError as LAError where laError.code == .userCancel || laError.code == .appCancel || laError.code == .systemCancel {
            return (.cancelled, nil)
        } catch {
            return (.wrongPIN, nil)
        }
    }
}
