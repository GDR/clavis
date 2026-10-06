import Foundation
@preconcurrency import LocalAuthentication
import Security
import ClavisCore

public struct RewrapReport: Equatable, Sendable {
    public var rewrapped: Int
    public var unreadable: Int

    public init(rewrapped: Int, unreadable: Int) {
        self.rewrapped = rewrapped
        self.unreadable = unreadable
    }
}

@MainActor
public final class PinModeChanger {
    public enum ChangeError: Error, Equatable, Sendable {
        case passwordFailed
        case pinTooShort
        case pinMismatch
        case oldKeyUnavailable
        case keychain
    }

    private let keyring: AuditKeyring
    private let storeFactory: () throws -> AuditStore
    private let counter: PinAttemptStoring
    private let passwordAuth: PasswordAuthenticating
    private let makePINContext: (String) -> LAContext
    private let sleep: (TimeInterval) async -> Void

    public init(
        keyring: AuditKeyring,
        store: @escaping () throws -> AuditStore,
        counter: PinAttemptStoring,
        passwordAuth: PasswordAuthenticating,
        makePINContext: @escaping (String) -> LAContext,
        sleep: @escaping (TimeInterval) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1e9)) }
    ) {
        self.keyring = keyring
        self.storeFactory = store
        self.counter = counter
        self.passwordAuth = passwordAuth
        self.makePINContext = makePINContext
        self.sleep = sleep
    }

    public static func makeDefault(
        keyring: AuditKeyring? = PanelLockController.makeDefaultKeyring(),
        store: @escaping () throws -> AuditStore = { try AuditStore() },
        counter: PinAttemptStoring = KeychainPinAttemptStore(),
        passwordAuth: PasswordAuthenticating = DevicePasswordAuthenticator()
    ) -> PinModeChanger? {
        guard let keyring = keyring else { return nil }
        return PinModeChanger(
            keyring: keyring,
            store: store,
            counter: counter,
            passwordAuth: passwordAuth,
            makePINContext: { pin in
                let ctx = LAContext()
                _ = ctx.setCredential(Data(pin.utf8), type: .applicationPassword)
                return ctx
            }
        )
    }

    public func changeMode(
        to mode: AuditReadMode,
        newPIN: String?,
        confirmPIN: String?,
        oldContext: LAContext?
    ) async throws -> RewrapReport {
        // 1. Password authentication required first (AC5)
        do {
            _ = try await passwordAuth.authenticateWithPassword(reason: ClavisUIStrings.PanelLock.disableReason)
        } catch {
            throw ChangeError.passwordFailed
        }

        // 2. PIN validation if required
        if mode.requiresPIN {
            guard let newPIN = newPIN, let confirmPIN = confirmPIN else {
                throw ChangeError.pinMismatch
            }
            guard newPIN.count >= 6 && newPIN.count <= 64 else {
                throw ChangeError.pinTooShort
            }
            guard newPIN == confirmPIN else {
                throw ChangeError.pinMismatch
            }
        }

        // 3. Old keys and old context check
        let oldIDs = (try? keyring.knownKeyIDs()) ?? []
        if !oldIDs.isEmpty && oldContext == nil {
            throw ChangeError.oldKeyUnavailable
        }

        // 4. Create new key
        let newKeyContext = (mode.requiresPIN && newPIN != nil) ? makePINContext(newPIN!) : nil
        let newKey: AuditReadPublicKey
        do {
            newKey = try keyring.createKey(mode: mode, context: newKeyContext)
        } catch {
            throw ChangeError.keychain
        }

        // 5. Switch current key and wait
        do {
            try keyring.setCurrent(keyID: newKey.keyID)
        } catch {
            throw ChangeError.keychain
        }
        await sleep(2.0)

        // 6. Rewrap epochs for old keys
        var rewrappedCount = 0
        var unreadableCount = 0

        if let oldContext = oldContext, let store = try? storeFactory() {
            let epochs = (try? store.epochs()) ?? []
            for epoch in epochs where oldIDs.contains(epoch.keyID) {
                do {
                    let rewrapped = try AuditCrypto.rewrapDEK(
                        epk: epoch.epk,
                        wrapped: epoch.wrappedDEK,
                        epochID: epoch.epochID,
                        keyID: epoch.keyID,
                        agree: { peerPub in
                            try self.keyring.agree(keyID: epoch.keyID, with: peerPub, context: oldContext)
                        },
                        to: newKey
                    )
                    try store.updateEpochWrap(
                        id: epoch.epochID,
                        keyID: newKey.keyID,
                        epk: rewrapped.epk,
                        wrappedDEK: rewrapped.wrapped
                    )
                    rewrappedCount += 1
                } catch {
                    unreadableCount += 1
                }
            }

            // 7. Delete old key items whose epochs all re-wrapped
            let updatedEpochs = (try? store.epochs()) ?? []
            for oldID in oldIDs {
                let hasUnwrappedEpochs = updatedEpochs.contains { $0.keyID == oldID }
                if !hasUnwrappedEpochs {
                    try? keyring.deleteKey(keyID: oldID)
                }
            }
        }

        // 8. Counter management
        if mode.requiresPIN {
            try? counter.save(PinAttemptState(attempts: 0, lastAttemptAt: Date().timeIntervalSince1970))
        } else {
            try? counter.delete()
        }

        return RewrapReport(rewrapped: rewrappedCount, unreadable: unreadableCount)
    }

    public func resetPIN(newPIN: String, confirmPIN: String) async throws {
        // 1. Password authentication required first (AC5)
        do {
            _ = try await passwordAuth.authenticateWithPassword(reason: ClavisUIStrings.PanelLock.disableReason)
        } catch {
            throw ChangeError.passwordFailed
        }

        // 2. PIN validation
        guard newPIN.count >= 6 && newPIN.count <= 64 else {
            throw ChangeError.pinTooShort
        }
        guard newPIN == confirmPIN else {
            throw ChangeError.pinMismatch
        }

        // 3. Create new key with current mode (or biometryOrPIN)
        let mode = (try? keyring.currentMode()) ?? .biometryOrPIN
        let newKeyContext = makePINContext(newPIN)
        let newKey: AuditReadPublicKey
        do {
            newKey = try keyring.createKey(mode: mode, context: newKeyContext)
        } catch {
            throw ChangeError.keychain
        }

        // 4. Switch current key (old epochs are not re-wrapped -> unreadable, D8)
        do {
            try keyring.setCurrent(keyID: newKey.keyID)
        } catch {
            throw ChangeError.keychain
        }

        // 5. Reset attempt counter
        try? counter.save(PinAttemptState(attempts: 0, lastAttemptAt: Date().timeIntervalSince1970))
    }
}
