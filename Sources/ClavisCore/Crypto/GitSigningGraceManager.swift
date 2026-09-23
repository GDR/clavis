import Foundation
import LocalAuthentication
import CryptoKit
import CoreFoundation
import AppKit
import CoreGraphics

public enum GitSigningPromptChoice: Equatable {
    case grantFiveMinutes
    case singleShot
    case cancel
}

public final class GitSigningGrant: @unchecked Sendable {
    public let keyLabel: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let deadline: DispatchTime
    private let lock = NSLock()
    private var _remainingOperations: Int
    private var authorizedContext: LAContext?
    internal let clientIdentity: String

    public init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        clientIdentity: String = "test-client"
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self._remainingOperations = maxOperations
        self.authorizedContext = nil
        self.clientIdentity = clientIdentity
    }

    internal init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        clientIdentity: String,
        authorizedContext: LAContext
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self._remainingOperations = maxOperations
        self.clientIdentity = clientIdentity
        self.authorizedContext = authorizedContext
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
    internal func consumeOperation(clientIdentity: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard self.clientIdentity == clientIdentity else { return false }
        guard _remainingOperations > 0 else { return false }
        guard DispatchTime.now() < deadline else { return false }
        _remainingOperations -= 1
        return true
    }

    internal func withAuthorizedContext<Result>(
        _ operation: (LAContext) throws -> Result
    ) rethrows -> Result? {
        lock.lock()
        defer { lock.unlock() }
        guard let authorizedContext else { return nil }
        return try operation(authorizedContext)
    }

    public func invalidate() {
        lock.lock()
        _remainingOperations = 0
        let ctx = authorizedContext
        authorizedContext = nil
        lock.unlock()

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

    public static var localized: GitSigningPromptStrings {
        GitSigningPromptStrings(
            header: String(localized: "prompt.git_session_header", defaultValue: "Clavis — Git Signing Session", bundle: .module),
            messageTemplate: { keyLabel, clientDesc in
                String(
                    localized: "prompt.git_session_message",
                    defaultValue: "Обнаружена серия коммитов Git (rebase / cherry-pick) для ключа '\(keyLabel)' от \(clientDesc).\n\nРазрешить автоматическую подпись Git на 5 минут без повторных запросов Touch ID?",
                    bundle: .module
                )
            },
            allowFiveMinutesButton: String(localized: "prompt.allow_five_minutes", defaultValue: "Grant 5 Minutes", bundle: .module),
            cancelButton: String(localized: "prompt.cancel", defaultValue: "Cancel", bundle: .module),
            singleShotButton: String(localized: "prompt.single_shot", defaultValue: "Sign Once", bundle: .module)
        )
    }

    public static var current: GitSigningPromptStrings = .localized
}

public enum GitSigningPrompt {
    public static var isGUISessionActive: Bool {
        guard let sessionDict = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            return false
        }
        return (sessionDict["kCGSSessionOnConsoleKey"] as? Bool) ?? false
    }

    /// Pluggable provider for checking GUI session availability (useful for testing)
    public static var sessionCheckProvider: () -> Bool = { isGUISessionActive }

    public static func displayModal(
        keyLabel: String,
        clientDesc: String,
        timeout: TimeInterval = 30.0
    ) -> GitSigningPromptChoice {
        guard sessionCheckProvider() else {
            ClavisLogger.log("GIT_GRACE", "Headless or non-GUI session detected; bypassing modal alert and defaulting to single-shot signing.")
            return .singleShot
        }

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
    private let timerQueue = DispatchQueue(label: "com.clavis.git-grace.timer", qos: .userInitiated)
    private var expirationTimer: DispatchSourceTimer?

    public init(observeSystemEvents: Bool = true) {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.setEventHandler { [weak self] in
            self?.expireActiveGrant()
        }
        timer.schedule(deadline: .distantFuture)
        timer.resume()
        expirationTimer = timer

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
        expirationTimer?.setEventHandler(handler: nil)
        expirationTimer?.cancel()
        expirationTimer = nil
        activeGrant?.invalidate()
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

    internal func withGrant<Result>(
        for keyLabel: String,
        clientIdentity: String,
        operation: (LAContext) throws -> Result
    ) rethrows -> Result? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrant, grant.keyLabel == keyLabel else {
            return nil
        }
        guard grant.consumeOperation(clientIdentity: clientIdentity) else {
            if !grant.isValid {
                grant.invalidate()
                activeGrant = nil
                expirationTimer?.schedule(deadline: .distantFuture)
                broadcastUpdate(grant: nil)
            }
            return nil
        }
        guard let result = try grant.withAuthorizedContext(operation) else {
            grant.invalidate()
            activeGrant = nil
            expirationTimer?.schedule(deadline: .distantFuture)
            broadcastUpdate(grant: nil)
            return nil
        }
        broadcastUpdate(grant: grant)
        return result
    }

    public func recordGitSignature(for keyLabel: String, clientIdentity: String = "") {
        lock.lock()
        defer { lock.unlock() }
        recentSignatures[recentSignatureKey(label: keyLabel, clientIdentity: clientIdentity)] = Date()
    }

    public func hasRecentGitSignature(for keyLabel: String, clientIdentity: String = "", windowSeconds: TimeInterval = 30.0) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let date = recentSignatures[recentSignatureKey(label: keyLabel, clientIdentity: clientIdentity)] else { return false }
        return Date().timeIntervalSince(date) <= windowSeconds
    }

    public func clearRecentGitSignature(for keyLabel: String, clientIdentity: String = "") {
        lock.lock()
        defer { lock.unlock() }
        recentSignatures.removeValue(forKey: recentSignatureKey(label: keyLabel, clientIdentity: clientIdentity))
    }

    @discardableResult
    internal func recordGrant(
        keyLabel: String,
        clientIdentity: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        context: LAContext
    ) -> GitSigningGrant {
        lock.lock()
        defer { lock.unlock() }
        activeGrant?.invalidate()
        recentSignatures.removeValue(forKey: recentSignatureKey(label: keyLabel, clientIdentity: clientIdentity))
        let grant = GitSigningGrant(
            keyLabel: keyLabel,
            duration: duration,
            maxOperations: maxOperations,
            clientIdentity: clientIdentity,
            authorizedContext: context
        )
        activeGrant = grant
        expirationTimer?.schedule(deadline: grant.deadline)
        broadcastUpdate(grant: grant)
        return grant
    }

    public func invalidateAll(broadcast: Bool = true) {
        lock.lock()
        activeGrant?.invalidate()
        activeGrant = nil
        recentSignatures.removeAll()
        expirationTimer?.schedule(deadline: .distantFuture)
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

    internal func invalidate(keyLabel: String) {
        lock.lock()
        if activeGrant?.keyLabel == keyLabel {
            activeGrant?.invalidate()
            activeGrant = nil
            expirationTimer?.schedule(deadline: .distantFuture)
        }
        let prefix = "\(keyLabel)\u{0}"
        recentSignatures = recentSignatures.filter { !$0.key.hasPrefix(prefix) }
        lock.unlock()
        broadcastUpdate(grant: nil)
    }

    private func expireActiveGrant() {
        lock.lock()
        guard let grant = activeGrant, !grant.isValid else {
            lock.unlock()
            return
        }
        grant.invalidate()
        activeGrant = nil
        expirationTimer?.schedule(deadline: .distantFuture)
        lock.unlock()
        broadcastUpdate(grant: nil)
    }

    private func recentSignatureKey(label: String, clientIdentity: String) -> String {
        "\(label)\u{0}\(clientIdentity)"
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
