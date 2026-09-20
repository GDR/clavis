import Foundation
import LocalAuthentication
import CryptoKit
import CoreFoundation
import AppKit

public enum GitSigningPromptChoice: Equatable {
    case grantFiveMinutes
    case singleShot
    case cancel
}

internal enum GitCachedSigningKey {
    case ed25519(SecureBuffer)
    case p256Software(SecureBuffer)
    case p256SecureEnclave(SecureEnclave.P256.Signing.PrivateKey)

    func wipe() {
        switch self {
        case .ed25519(let buf), .p256Software(let buf):
            buf.wipe()
        case .p256SecureEnclave:
            break
        }
    }

    func signSSH(data: Data) throws -> Data {
        switch self {
        case .ed25519(let buf):
            let signature = try buf.withUnsafeBytes { ptr -> Data in
                let key = try Curve25519.Signing.PrivateKey(rawRepresentation: ptr)
                return try key.signature(for: data)
            }
            guard let sig = signature else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key buffer has been wiped"])
            }
            var blob = Data()
            blob.appendWireString("ssh-ed25519")
            blob.appendWireData(sig)
            return blob

        case .p256Software(let buf):
            let ecdsaSig = try buf.withUnsafeBytes { ptr -> P256.Signing.ECDSASignature in
                let key = try P256.Signing.PrivateKey(rawRepresentation: ptr)
                return try key.signature(for: data)
            }
            guard let sig = ecdsaSig else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key buffer has been wiped"])
            }
            return KeychainManager.formatECDSASignatureBlob(sig)

        case .p256SecureEnclave(let seKey):
            let ecdsaSig = try seKey.signature(for: data)
            return KeychainManager.formatECDSASignatureBlob(ecdsaSig)
        }
    }
}

public final class GitSigningGrant: @unchecked Sendable {
    public let keyLabel: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let deadline: DispatchTime
    private let lock = NSLock()
    private var _remainingOperations: Int
    public private(set) var authorizedContext: LAContext?
    internal private(set) var cachedKey: GitCachedSigningKey?

    public init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        authorizedContext: LAContext? = nil
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self._remainingOperations = maxOperations
        self.authorizedContext = authorizedContext
        self.cachedKey = nil
    }

    internal init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        authorizedContext: LAContext? = nil,
        cachedKey: GitCachedSigningKey? = nil
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self._remainingOperations = maxOperations
        self.authorizedContext = authorizedContext
        self.cachedKey = cachedKey
    }

    public var remainingOperations: Int {
        lock.lock()
        defer { lock.unlock() }
        return _remainingOperations
    }

    public var isValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard _remainingOperations > 0 else { return false }
        return DispatchTime.now() < deadline
    }

    public var remainingSeconds: Int {
        let rem = expiresAt.timeIntervalSinceNow
        return max(0, Int(rem))
    }

    /// Decrements operations counter and returns true if operation is permitted.
    public func consumeOperation() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard _remainingOperations > 0 else { return false }
        guard DispatchTime.now() < deadline else { return false }
        _remainingOperations -= 1
        return true
    }

    public func invalidate() {
        lock.lock()
        _remainingOperations = 0
        let ctx = authorizedContext
        authorizedContext = nil
        let key = cachedKey
        cachedKey = nil
        lock.unlock()

        key?.wipe()
        ctx?.invalidate()
    }
}

public struct GitSigningPromptStrings {
    public var header: String
    public var messageTemplate: (String, String) -> String
    public var allowFiveMinutesButton: String
    public var cancelButton: String
    public var singleShotButton: String

    public static let russian = GitSigningPromptStrings(
        header: "Clavis — Сессия подписи Git",
        messageTemplate: { keyLabel, clientDesc in
            "Обнаружена серия коммитов Git (rebase / cherry-pick) для ключа '\(keyLabel)' от \(clientDesc).\n\nРазрешить автоматическую подпись Git на 5 минут без повторных запросов Touch ID?"
        },
        allowFiveMinutesButton: "Разрешить на 5 минут",
        cancelButton: "Отмена",
        singleShotButton: "Только этот раз"
    )

    public static let english = GitSigningPromptStrings(
        header: "Clavis — Git Signing Session",
        messageTemplate: { keyLabel, clientDesc in
            "Detected a series of Git commits (rebase / cherry-pick) for key '\(keyLabel)' from \(clientDesc).\n\nGrant automatic Git signing for 5 minutes without repeated Touch ID prompts?"
        },
        allowFiveMinutesButton: "Grant 5 Minutes",
        cancelButton: "Cancel",
        singleShotButton: "Sign Once"
    )

    public static var current: GitSigningPromptStrings = .russian
}

public enum GitSigningPrompt {
    public static func displayModal(
        keyLabel: String,
        clientDesc: String,
        timeout: TimeInterval = 30.0
    ) -> GitSigningPromptChoice {
        var responseFlags: CFOptionFlags = 0
        let strings = GitSigningPromptStrings.current
        let header = strings.header as CFString
        let message = strings.messageTemplate(keyLabel, clientDesc) as CFString
        let defaultBtn = strings.allowFiveMinutesButton as CFString
        let alternateBtn = strings.cancelButton as CFString
        let otherBtn = strings.singleShotButton as CFString

        let status = CFUserNotificationDisplayAlert(
            timeout,
            0,
            nil,
            nil,
            nil,
            header,
            message,
            defaultBtn,
            alternateBtn,
            otherBtn,
            &responseFlags
        )

        guard status == 0 else {
            return .cancel
        }

        let response = responseFlags & 0x3
        switch response {
        case CFOptionFlags(kCFUserNotificationDefaultResponse):
            return .grantFiveMinutes
        case CFOptionFlags(kCFUserNotificationAlternateResponse):
            return .cancel
        case CFOptionFlags(kCFUserNotificationOtherResponse):
            return .singleShot
        default:
            return .cancel
        }
    }
}

public final class GitSigningGraceManager: @unchecked Sendable {
    public static let shared = GitSigningGraceManager()

    public static let lockAllNotification = NSNotification.Name("com.clavis.lockAll")
    public static let endGitGraceNotification = NSNotification.Name("com.clavis.endGitGrace")
    public static let gitGraceUpdatedNotification = NSNotification.Name("com.clavis.gitGraceUpdated")
    public static let screenIsLockedNotification = NSNotification.Name("com.apple.screenIsLocked")

    /// Pluggable prompt provider for unit tests and headless environments.
    public static var promptProvider: (String, String) -> GitSigningPromptChoice = { label, clientDesc in
        GitSigningPrompt.displayModal(keyLabel: label, clientDesc: clientDesc)
    }

    private let lock = NSLock()
    private var activeGrant: GitSigningGrant?
    private var recentSignatures: [String: Date] = [:]

    public init(observeSystemEvents: Bool = true) {
        if observeSystemEvents {
            DistributedNotificationCenter.default().addObserver(
                self,
                selector: #selector(handleLockAll),
                name: Self.lockAllNotification,
                object: nil,
                suspensionBehavior: .deliverImmediately
            )
            DistributedNotificationCenter.default().addObserver(
                self,
                selector: #selector(handleEndGitGrace),
                name: Self.endGitGraceNotification,
                object: nil,
                suspensionBehavior: .deliverImmediately
            )
            DistributedNotificationCenter.default().addObserver(
                self,
                selector: #selector(handleScreenLocked),
                name: Self.screenIsLockedNotification,
                object: nil,
                suspensionBehavior: .deliverImmediately
            )
            NSWorkspace.shared.notificationCenter.addObserver(
                self,
                selector: #selector(handleSystemSleep),
                name: NSWorkspace.willSleepNotification,
                object: nil
            )
        }
    }

    deinit {
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
    }

    @objc private func handleLockAll() {
        invalidateAll(broadcast: false)
    }

    @objc private func handleEndGitGrace() {
        invalidateAll(broadcast: false)
    }

    @objc private func handleScreenLocked() {
        invalidateAll(broadcast: true)
    }

    @objc private func handleSystemSleep() {
        invalidateAll(broadcast: true)
    }

    public func getValidGrant(for keyLabel: String) -> GitSigningGrant? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrant, grant.keyLabel == keyLabel else {
            return nil
        }
        if grant.isValid {
            return grant
        } else {
            activeGrant?.invalidate()
            activeGrant = nil
            return nil
        }
    }

    public func consumeGrant(for keyLabel: String) -> GitSigningGrant? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrant, grant.keyLabel == keyLabel else {
            return nil
        }
        if grant.consumeOperation() {
            broadcastUpdate(grant: grant)
            return grant
        } else {
            grant.invalidate()
            activeGrant = nil
            broadcastUpdate(grant: nil)
            return nil
        }
    }

    public func recordGitSignature(for keyLabel: String) {
        lock.lock()
        defer { lock.unlock() }
        recentSignatures[keyLabel] = Date()
    }

    public func hasRecentGitSignature(for keyLabel: String, windowSeconds: TimeInterval = 30.0) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let date = recentSignatures[keyLabel] else { return false }
        return Date().timeIntervalSince(date) <= windowSeconds
    }

    public func clearRecentGitSignature(for keyLabel: String) {
        lock.lock()
        defer { lock.unlock() }
        recentSignatures.removeValue(forKey: keyLabel)
    }

    @discardableResult
    public func recordGrant(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        context: LAContext? = nil
    ) -> GitSigningGrant {
        recordGrant(
            keyLabel: keyLabel,
            duration: duration,
            maxOperations: maxOperations,
            context: context,
            cachedKey: nil
        )
    }

    @discardableResult
    internal func recordGrant(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        context: LAContext? = nil,
        cachedKey: GitCachedSigningKey? = nil
    ) -> GitSigningGrant {
        lock.lock()
        defer { lock.unlock() }
        activeGrant?.invalidate()
        recentSignatures.removeValue(forKey: keyLabel)
        let grant = GitSigningGrant(
            keyLabel: keyLabel,
            duration: duration,
            maxOperations: maxOperations,
            authorizedContext: context,
            cachedKey: cachedKey
        )
        activeGrant = grant
        broadcastUpdate(grant: grant)
        return grant
    }

    public func invalidateAll(broadcast: Bool = true) {
        lock.lock()
        activeGrant?.invalidate()
        activeGrant = nil
        recentSignatures.removeAll()
        lock.unlock()

        if broadcast {
            broadcastUpdate(grant: nil)
            DistributedNotificationCenter.default().postNotificationName(
                Self.endGitGraceNotification,
                object: nil,
                userInfo: nil,
                deliverImmediately: true
            )
        }
    }

    private func broadcastUpdate(grant: GitSigningGrant?) {
        var userInfo: [AnyHashable: Any] = [:]
        if let grant = grant, grant.isValid {
            userInfo["active"] = true
            userInfo["keyLabel"] = grant.keyLabel
            userInfo["remainingSeconds"] = grant.remainingSeconds
            userInfo["remainingOperations"] = grant.remainingOperations
        } else {
            userInfo["active"] = false
        }
        DistributedNotificationCenter.default().postNotificationName(
            Self.gitGraceUpdatedNotification,
            object: nil,
            userInfo: userInfo,
            deliverImmediately: true
        )
    }
}
