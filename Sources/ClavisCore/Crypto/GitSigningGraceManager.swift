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
    /// Set for grants issued to a live peer. Descendants of this process may use the
    /// grant; other processes that share `clientIdentity` may not.
    internal let approvedProcess: GitApprovedProcess?

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
        self.approvedProcess = nil
    }

    internal init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        clientIdentity: String,
        authorizedContext: LAContext,
        approvedProcess: GitApprovedProcess? = nil
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self._remainingOperations = maxOperations
        self.clientIdentity = clientIdentity
        self.authorizedContext = authorizedContext
        self.approvedProcess = approvedProcess
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
    internal func consumeOperation(
        clientIdentity: String,
        peerProcess: GitApprovedProcess? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard allowsClient(clientIdentity: clientIdentity, peerProcess: peerProcess) else { return false }
        guard _remainingOperations > 0 else { return false }
        guard DispatchTime.now() < deadline else { return false }
        _remainingOperations -= 1
        return true
    }

    /// Identity-string grants keep the legacy exact match. A process-bound grant
    /// admits only the approved pid (same start time) and its descendants.
    private func allowsClient(clientIdentity: String, peerProcess: GitApprovedProcess?) -> Bool {
        if let approvedProcess {
            guard let peerProcess else { return false }
            let covered = SSHAgentServer.gitGrantCoversPeer(peer: peerProcess, approved: approvedProcess)
            if !covered {
                ClavisLogger.log(
                    "SECURITY_ALERT",
                    "Rejected Git signing grant for '\(keyLabel)': peer PID \(peerProcess.pid) is outside the approved process tree."
                )
            }
            return covered
        }
        return self.clientIdentity == clientIdentity
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
        // The default button (Return) must be the least privileged way forward. Granting a
        // 5-minute session is an explicit, non-default choice so a stray keypress while the
        // modal appears mid-typing cannot enable unattended signing.
        let defaultBtn = strings.singleShotButton as CFString
        let alternateBtn = strings.cancelButton as CFString
        let otherBtn = strings.allowFiveMinutesButton as CFString

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

        return choice(forResponseFlags: responseFlags)
    }

    /// Maps a `CFUserNotification` response to a choice. Anything unexpected
    /// (including the timeout/cancel response) is `.cancel`.
    ///
    /// Button layout: default = Sign Once, alternate = Cancel, other = Grant 5 Minutes.
    static func choice(forResponseFlags responseFlags: CFOptionFlags) -> GitSigningPromptChoice {
        switch responseFlags & 0x3 {
        case CFOptionFlags(kCFUserNotificationDefaultResponse):
            return .singleShot
        case CFOptionFlags(kCFUserNotificationAlternateResponse):
            return .cancel
        case CFOptionFlags(kCFUserNotificationOtherResponse):
            return .grantFiveMinutes
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
    private let observeSystemEvents: Bool

    public init(observeSystemEvents: Bool = true) {
        self.observeSystemEvents = observeSystemEvents
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.setEventHandler { [weak self] in
            self?.expireActiveGrant()
        }
        timer.schedule(deadline: .distantFuture)
        timer.resume()
        expirationTimer = timer

        if observeSystemEvents {
            SystemEventMonitor.shared.addHandler(id: "GitSigningGraceManager-\(ObjectIdentifier(self))") { [weak self] in
                self?.invalidateAll(broadcast: true)
            }
        }
    }

    deinit {
        if observeSystemEvents {
            SystemEventMonitor.shared.removeHandler(id: "GitSigningGraceManager-\(ObjectIdentifier(self))")
        }
        expirationTimer?.setEventHandler(handler: nil)
        expirationTimer?.cancel()
        expirationTimer = nil
        activeGrant?.invalidate()
    }

    public var currentActiveGrant: GitSigningGrant? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrant else { return nil }
        if grant.isValid {
            return grant
        } else {
            activeGrant?.invalidate()
            activeGrant = nil
            return nil
        }
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
        peerProcess: GitApprovedProcess? = nil,
        operation: (LAContext) throws -> Result
    ) rethrows -> Result? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrant, grant.keyLabel == keyLabel else {
            return nil
        }
        guard grant.consumeOperation(clientIdentity: clientIdentity, peerProcess: peerProcess) else {
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
        context: LAContext,
        approvedProcess: GitApprovedProcess? = nil
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
            authorizedContext: context,
            approvedProcess: approvedProcess
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
