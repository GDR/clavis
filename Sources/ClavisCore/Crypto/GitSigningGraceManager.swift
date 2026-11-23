import Foundation
import LocalAuthentication
import CryptoKit
import CoreFoundation
import CoreGraphics

public enum GitSigningPromptChoice: Equatable, Sendable {
    case grantFiveMinutes
    case grantSession(duration: TimeInterval)
    case singleShot
    case cancel

    public var grantDurationSeconds: TimeInterval? {
        switch self {
        case .grantFiveMinutes:
            return 300.0
        case .grantSession(let duration):
            return duration
        case .singleShot, .cancel:
            return nil
        }
    }
}

public struct AgentActiveGrantSnapshot: Equatable, Sendable {
    public let keyLabel: String
    public let remainingSeconds: Int
    public let remainingOperations: Int
    public let endsAtLock: Bool
    public let callerName: String?

    public init(
        keyLabel: String,
        remainingSeconds: Int,
        remainingOperations: Int,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.remainingSeconds = remainingSeconds
        self.remainingOperations = remainingOperations
        self.endsAtLock = endsAtLock
        self.callerName = callerName
    }
}

public final class GitSigningGrant: @unchecked Sendable {
    public let keyLabel: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let deadline: DispatchTime
    public let endsAtLock: Bool
    public let callerName: String?
    private let lock = NSLock()
    private var _remainingOperations: Int
    private var authorizedContext: LAContext?
    internal let clientIdentity: String
    /// Set for grants issued to a live peer. Descendants of this process may use the
    /// grant; other processes that share `clientIdentity` may not.
    public let approvedProcess: GitApprovedProcess?
    private var hardwareSigner: (@Sendable (Data) throws -> Data)?

    public init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        clientIdentity: String = "test-client",
        approvedProcess: GitApprovedProcess? = nil,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self.endsAtLock = endsAtLock
        self.callerName = callerName
        self._remainingOperations = maxOperations
        self.authorizedContext = nil
        self.clientIdentity = clientIdentity
        self.approvedProcess = approvedProcess
        self.hardwareSigner = nil
    }

    internal init(
        keyLabel: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        clientIdentity: String,
        authorizedContext: LAContext?,
        approvedProcess: GitApprovedProcess? = nil,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self.endsAtLock = endsAtLock
        self.callerName = callerName
        self._remainingOperations = maxOperations
        self.clientIdentity = clientIdentity
        self.authorizedContext = authorizedContext
        self.approvedProcess = approvedProcess
        self.hardwareSigner = hardwareSigner
    }

    public var remainingOperations: Int {
        lock.lock()
        defer { lock.unlock() }
        return _remainingOperations
    }

    public var isValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !SystemEventMonitor.isSessionLockedOrOffConsole() else { return false }
        guard _remainingOperations > 0 else { return false }
        return DispatchTime.now() < deadline
    }

    public func sign(_ data: Data, using keyManager: KeychainManager? = nil, role: AgentSocketRole? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            _remainingOperations = 0
            let ctx = authorizedContext
            authorizedContext = nil
            hardwareSigner = nil
            ctx?.invalidate()
            throw AgentSessionGrantError.grantInvalidated
        }

        guard _remainingOperations > 0, DispatchTime.now() < deadline else {
            throw AgentSessionGrantError.grantInvalidated
        }

        if let hardwareSigner {
            return try hardwareSigner(data)
        }

        guard let ctx = authorizedContext, let keyManager = keyManager else {
            throw AgentSessionGrantError.grantInvalidated
        }
        guard let keyInfo = try keyManager.fetchKeyInfo(label: keyLabel) else {
            throw AgentSessionGrantError.grantInvalidated
        }
        return try keyManager.signSSH(
            key: keyInfo,
            data: data,
            prompt: "",
            useCache: false,
            existingContext: ctx,
            allowedPurposes: role?.allowedPurposes ?? AgentSocketRole.personal.allowedPurposes
        )
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
        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            _remainingOperations = 0
            let ctx = authorizedContext
            authorizedContext = nil
            hardwareSigner = nil
            ctx?.invalidate()
            return false
        }
        guard allowsClient(clientIdentity: clientIdentity, peerProcess: peerProcess) else { return false }
        guard _remainingOperations > 0 else { return false }
        guard DispatchTime.now() < deadline else { return false }
        _remainingOperations -= 1
        return true
    }

    /// Grants are strictly process-bound to an approved process anchor (pid + startTime).
    /// Bare string fallback is removed to prevent same-user process impersonation.
    private func allowsClient(clientIdentity: String, peerProcess: GitApprovedProcess?) -> Bool {
        guard let approvedProcess, let peerProcess else {
            ClavisLogger.log(
                "SECURITY_ALERT",
                "Rejected Git signing grant for '\(keyLabel)': grant requires an approved process anchor and peer process."
            )
            return false
        }
        let covered = SSHAgentServer.gitGrantCoversPeer(peer: peerProcess, approved: approvedProcess)
        if !covered {
            ClavisLogger.log(
                "SECURITY_ALERT",
                "Rejected Git signing grant for '\(keyLabel)': peer PID \(peerProcess.pid) is outside the approved process tree."
            )
        }
        return covered
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
        hardwareSigner = nil
        lock.unlock()

        ctx?.invalidate()
    }

    deinit {
        invalidate()
    }
}

/// Time-limited, app-bound unlock grant for Personal SSH key usage.
/// Reuse is strictly keyed to `(keyLabel, approvalIdentity)` (D-28) and clears on lock/sleep (INV-21).
public final class PersonalUnlockGrant: @unchecked Sendable {
    public let keyLabel: String
    public let approvalIdentity: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let deadline: DispatchTime
    public let allowedCapabilities: KeyCapabilities
    public let endsAtLock: Bool
    public let callerName: String?
    private let lock = NSLock()
    private var _remainingOperations: Int
    private var authorizedContext: LAContext?
    private var hardwareSigner: (@Sendable (Data) throws -> Data)?

    internal init(
        keyLabel: String,
        approvalIdentity: String,
        duration: TimeInterval,
        maxOperations: Int = 200,
        allowedCapabilities: KeyCapabilities = KeyCapabilities(ssh: true, signature: false),
        authorizedContext: LAContext?,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.approvalIdentity = approvalIdentity
        self.grantedAt = Date()
        self.expiresAt = Date().addingTimeInterval(duration)
        self.deadline = DispatchTime.now() + duration
        self.allowedCapabilities = allowedCapabilities
        self.endsAtLock = endsAtLock
        self.callerName = callerName
        self._remainingOperations = maxOperations
        self.authorizedContext = authorizedContext
        self.hardwareSigner = hardwareSigner
    }

    public var remainingOperations: Int {
        lock.lock()
        defer { lock.unlock() }
        return _remainingOperations
    }

    public var remainingSeconds: Int {
        let rem = expiresAt.timeIntervalSinceNow
        return max(0, Int(rem))
    }

    public var isValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !SystemEventMonitor.isSessionLockedOrOffConsole() else { return false }
        guard _remainingOperations > 0 else { return false }
        return DispatchTime.now() < deadline
    }

    public func sign(_ data: Data, using keyManager: KeychainManager? = nil, role: AgentSocketRole? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            _remainingOperations = 0
            let ctx = authorizedContext
            authorizedContext = nil
            hardwareSigner = nil
            ctx?.invalidate()
            throw AgentSessionGrantError.grantInvalidated
        }

        guard _remainingOperations > 0, DispatchTime.now() < deadline else {
            throw AgentSessionGrantError.grantInvalidated
        }

        if let hardwareSigner {
            return try hardwareSigner(data)
        }

        guard let ctx = authorizedContext, let keyManager else {
            throw AgentSessionGrantError.grantInvalidated
        }
        guard let keyInfo = try keyManager.fetchKeyInfo(label: keyLabel) else {
            throw AgentSessionGrantError.grantInvalidated
        }
        return try keyManager.signSSH(
            key: keyInfo,
            data: data,
            prompt: "",
            useCache: false,
            existingContext: ctx,
            allowedPurposes: role?.allowedPurposes ?? AgentSocketRole.personal.allowedPurposes
        )
    }

    internal func consumeOperation(approvalIdentity: String, operation: KeyOperation = .ssh) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            _remainingOperations = 0
            let ctx = authorizedContext
            authorizedContext = nil
            hardwareSigner = nil
            ctx?.invalidate()
            return false
        }
        guard self.approvalIdentity == approvalIdentity else { return false }
        guard allowedCapabilities.permits(operation) else { return false }
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
        hardwareSigner = nil
        lock.unlock()

        ctx?.invalidate()
    }

    deinit {
        invalidate()
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
            header: String(localized: "prompt.git_session_header", defaultValue: "Clavis — Git Signing Session", bundle: .clavisCore),
            messageTemplate: { keyLabel, clientDesc in
                String(
                    localized: "prompt.git_session_message",
                    defaultValue: "Detected a series of Git commits (rebase / cherry-pick) for key '\(keyLabel)' from \(clientDesc).\n\nGrant automatic Git signing for 5 minutes without repeated Touch ID prompts?",
                    bundle: .clavisCore
                )
            },
            allowFiveMinutesButton: String(localized: "prompt.allow_five_minutes", defaultValue: "Grant 5 Minutes", bundle: .clavisCore),
            cancelButton: String(localized: "prompt.cancel", defaultValue: "Cancel", bundle: .clavisCore),
            singleShotButton: String(localized: "prompt.single_shot", defaultValue: "Sign Once", bundle: .clavisCore)
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

        #if DEBUG
        // Tests must inject a presenter instead of displaying an interactive alert.
        guard !ClavisEnvironment.isTesting else { return .cancel }
        #endif
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

public protocol GitSigningGracePresenter: Sendable {
    func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice
}

public extension GitSigningGracePresenter {
    func prompt(keyLabel: String, clientDesc: String) -> GitSigningPromptChoice {
        prompt(keyLabel: keyLabel, clientDesc: clientDesc, timeout: 30.0)
    }
}

public struct CFUserNotificationGitSigningGracePresenter: GitSigningGracePresenter {
    public let defaultTimeout: TimeInterval

    public init(defaultTimeout: TimeInterval = 30.0) {
        self.defaultTimeout = defaultTimeout
    }

    public func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
        GitSigningPrompt.displayModal(keyLabel: keyLabel, clientDesc: clientDesc, timeout: timeout)
    }

    public func prompt(keyLabel: String, clientDesc: String) -> GitSigningPromptChoice {
        prompt(keyLabel: keyLabel, clientDesc: clientDesc, timeout: defaultTimeout)
    }
}

public typealias DefaultGitSigningGracePresenter = CFUserNotificationGitSigningGracePresenter

public struct ClosureGitSigningGracePresenter: GitSigningGracePresenter, @unchecked Sendable {
    public let handler: (String, String) -> GitSigningPromptChoice

    public init(handler: @escaping (String, String) -> GitSigningPromptChoice) {
        self.handler = handler
    }

    public func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
        handler(keyLabel, clientDesc)
    }
}

public final class GitSigningGraceManager: @unchecked Sendable {
    public static let shared = GitSigningGraceManager()

    public static let lockAllNotification = NSNotification.Name("com.clavis.lockAll")
    public static let endGitGraceNotification = NSNotification.Name("com.clavis.endGitGrace")
    public static let gitGraceUpdatedNotification = NSNotification.Name("com.clavis.gitGraceUpdated")
    public static let screenIsLockedNotification = NSNotification.Name("com.apple.screenIsLocked")

    private let lock = NSLock()
    private var presenter: GitSigningGracePresenter
    private var activeGrants: [String: GitSigningGrant] = [:]
    private var personalGrants: [String: PersonalUnlockGrant] = [:]
    private var recentSignatures: [String: Date] = [:]
    private let timerQueue = DispatchQueue(label: "com.clavis.git-grace.timer", qos: .userInitiated)
    private var expirationTimer: DispatchSourceTimer?
    private let observeSystemEvents: Bool

    /// Pluggable prompt provider for unit tests and headless environments (bridged to presenter for backward compatibility).
    public static var promptProvider: (String, String) -> GitSigningPromptChoice {
        get {
            { label, clientDesc in
                GitSigningGraceManager.shared.prompt(keyLabel: label, clientDesc: clientDesc)
            }
        }
        set {
            GitSigningGraceManager.shared.setPresenter(ClosureGitSigningGracePresenter(handler: newValue))
        }
    }

    public func setPresenter(_ presenter: GitSigningGracePresenter) {
        lock.lock()
        self.presenter = presenter
        lock.unlock()
    }

    public init(
        observeSystemEvents: Bool = true,
        presenter: GitSigningGracePresenter = CFUserNotificationGitSigningGracePresenter()
    ) {
        self.observeSystemEvents = observeSystemEvents
        self.presenter = presenter
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.setEventHandler { [weak self] in
            self?.expireActiveGrants()
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

    public func prompt(
        keyLabel: String,
        clientDesc: String,
        timeout: TimeInterval = 30.0
    ) -> GitSigningPromptChoice {
        lock.lock()
        let currentPresenter = presenter
        lock.unlock()
        return currentPresenter.prompt(keyLabel: keyLabel, clientDesc: clientDesc, timeout: timeout)
    }

    deinit {
        if observeSystemEvents {
            SystemEventMonitor.shared.removeHandler(id: "GitSigningGraceManager-\(ObjectIdentifier(self))")
        }
        expirationTimer?.setEventHandler(handler: nil)
        expirationTimer?.cancel()
        expirationTimer = nil
        for grant in activeGrants.values {
            grant.invalidate()
        }
        activeGrants.removeAll()
        for grant in personalGrants.values {
            grant.invalidate()
        }
        personalGrants.removeAll()
    }

    public func allActiveGrants() -> [GitSigningGrant] {
        lock.lock()
        defer { lock.unlock() }
        var valid: [GitSigningGrant] = []
        for (label, grant) in activeGrants {
            if grant.isValid {
                valid.append(grant)
            } else {
                grant.invalidate()
                activeGrants.removeValue(forKey: label)
            }
        }
        return valid.sorted(by: { $0.keyLabel < $1.keyLabel })
    }

    public func allActivePersonalGrants() -> [PersonalUnlockGrant] {
        lock.lock()
        defer { lock.unlock() }
        var valid: [PersonalUnlockGrant] = []
        for (compoundKey, grant) in personalGrants {
            if grant.isValid {
                valid.append(grant)
            } else {
                grant.invalidate()
                personalGrants.removeValue(forKey: compoundKey)
            }
        }
        return valid.sorted(by: { $0.keyLabel < $1.keyLabel })
    }

    public func activeGrantSummary() -> (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? {
        if let gitGrant = allActiveGrants().first {
            return (gitGrant.keyLabel, gitGrant.remainingSeconds, gitGrant.remainingOperations)
        }
        if let sshGrant = allActivePersonalGrants().first {
            return (sshGrant.keyLabel, sshGrant.remainingSeconds, sshGrant.remainingOperations)
        }
        return nil
    }

    public var currentActiveGrant: GitSigningGrant? {
        allActiveGrants().first
    }

    public func queryAllAgentGitGraces() -> [(keyLabel: String, remainingSeconds: Int, remainingOperations: Int)] {
        allActiveGrants().map { ($0.keyLabel, $0.remainingSeconds, $0.remainingOperations) }
    }

    public func allActiveGrantSnapshots() -> [AgentActiveGrantSnapshot] {
        let git = allActiveGrants().map {
            AgentActiveGrantSnapshot(
                keyLabel: $0.keyLabel,
                remainingSeconds: $0.remainingSeconds,
                remainingOperations: $0.remainingOperations,
                endsAtLock: $0.endsAtLock,
                callerName: $0.callerName
            )
        }
        let personal = allActivePersonalGrants().map {
            AgentActiveGrantSnapshot(
                keyLabel: $0.keyLabel,
                remainingSeconds: $0.remainingSeconds,
                remainingOperations: $0.remainingOperations,
                endsAtLock: $0.endsAtLock,
                callerName: $0.callerName
            )
        }
        return (git + personal).sorted {
            let order = $0.keyLabel.localizedStandardCompare($1.keyLabel)
            if order != .orderedSame { return order == .orderedAscending }
            return $0.remainingSeconds > $1.remainingSeconds
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
        guard let grant = activeGrants[keyLabel] else {
            return nil
        }
        if grant.isValid {
            return grant
        } else {
            grant.invalidate()
            activeGrants.removeValue(forKey: keyLabel)
            scheduleNextExpirationTimerLocked()
            return nil
        }
    }

    internal func withGrant<Result>(
        for keyLabel: String,
        clientIdentity: String,
        peerProcess: GitApprovedProcess? = nil,
        operation: (GitSigningGrant) throws -> Result
    ) rethrows -> Result? {
        lock.lock()
        defer { lock.unlock() }
        guard let grant = activeGrants[keyLabel] else {
            return nil
        }
        guard grant.consumeOperation(clientIdentity: clientIdentity, peerProcess: peerProcess) else {
            if !grant.isValid {
                grant.invalidate()
                activeGrants.removeValue(forKey: keyLabel)
                scheduleNextExpirationTimerLocked()
                broadcastUpdate(grant: nil)
            }
            return nil
        }
        let result = try operation(grant)
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
        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            recentSignatures.removeAll()
            return false
        }
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
        approvedProcess: GitApprovedProcess? = nil,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) -> GitSigningGrant {
        lock.lock()
        defer { lock.unlock() }
        activeGrants[keyLabel]?.invalidate()
        recentSignatures.removeValue(forKey: recentSignatureKey(label: keyLabel, clientIdentity: clientIdentity))
        let grant = GitSigningGrant(
            keyLabel: keyLabel,
            duration: duration,
            maxOperations: maxOperations,
            clientIdentity: clientIdentity,
            authorizedContext: context,
            approvedProcess: approvedProcess,
            hardwareSigner: hardwareSigner,
            endsAtLock: endsAtLock,
            callerName: callerName
        )
        activeGrants[keyLabel] = grant
        scheduleNextExpirationTimerLocked()
        broadcastUpdate(grant: grant)
        return grant
    }

    @discardableResult
    internal func recordPersonalSSHGrant(
        keyLabel: String,
        approvalIdentity: String,
        duration: TimeInterval,
        maxOperations: Int = 200,
        allowedCapabilities: KeyCapabilities = KeyCapabilities(ssh: true, signature: false),
        context: LAContext,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil,
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) -> PersonalUnlockGrant {
        lock.lock()
        let compoundKey = personalGrantKey(label: keyLabel, approvalIdentity: approvalIdentity)
        personalGrants[compoundKey]?.invalidate()
        let grant = PersonalUnlockGrant(
            keyLabel: keyLabel,
            approvalIdentity: approvalIdentity,
            duration: max(1.0, duration),
            maxOperations: maxOperations,
            allowedCapabilities: allowedCapabilities,
            authorizedContext: context,
            hardwareSigner: hardwareSigner,
            endsAtLock: endsAtLock,
            callerName: callerName
        )
        personalGrants[compoundKey] = grant
        scheduleNextExpirationTimerLocked()
        let activeGit = activeGrants[keyLabel]
        lock.unlock()
        broadcastUpdate(grant: activeGit, summary: (keyLabel, grant.remainingSeconds, grant.remainingOperations))
        return grant
    }

    internal func withPersonalSSHGrant<Result>(
        for keyLabel: String,
        approvalIdentity: String,
        operationType: KeyOperation = .ssh,
        operation: (PersonalUnlockGrant) throws -> Result
    ) rethrows -> Result? {
        lock.lock()
        let compoundKey = personalGrantKey(label: keyLabel, approvalIdentity: approvalIdentity)
        guard let grant = personalGrants[compoundKey] else {
            lock.unlock()
            return nil
        }
        guard grant.consumeOperation(approvalIdentity: approvalIdentity, operation: operationType) else {
            if !grant.isValid {
                grant.invalidate()
                personalGrants.removeValue(forKey: compoundKey)
                scheduleNextExpirationTimerLocked()
                lock.unlock()
                broadcastUpdate(grant: nil)
                return nil
            }
            lock.unlock()
            return nil
        }
        let summary = (grant.keyLabel, grant.remainingSeconds, grant.remainingOperations)
        lock.unlock()
        let result = try operation(grant)
        broadcastUpdate(grant: nil, summary: summary)
        return result
    }

    internal func invalidatePersonalSSHGrant(keyLabel: String, approvalIdentity: String, broadcast: Bool = true) {
        lock.lock()
        let compoundKey = personalGrantKey(label: keyLabel, approvalIdentity: approvalIdentity)
        let removed = personalGrants.removeValue(forKey: compoundKey)
        removed?.invalidate()
        scheduleNextExpirationTimerLocked()
        lock.unlock()

        if broadcast {
            broadcastUpdate(grant: nil)
        }
    }

    public func invalidateAll(broadcast: Bool = true) {
        lock.lock()
        for grant in activeGrants.values {
            grant.invalidate()
        }
        activeGrants.removeAll()
        for grant in personalGrants.values {
            grant.invalidate()
        }
        personalGrants.removeAll()
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

    public func invalidate(keyLabel: String, broadcast: Bool = true) {
        lock.lock()
        if let grant = activeGrants.removeValue(forKey: keyLabel) {
            grant.invalidate()
        }
        let prefix = "\(keyLabel)\u{0}"
        for (compoundKey, grant) in personalGrants where compoundKey.hasPrefix(prefix) {
            grant.invalidate()
            personalGrants.removeValue(forKey: compoundKey)
        }
        recentSignatures = recentSignatures.filter { !$0.key.hasPrefix(prefix) }
        scheduleNextExpirationTimerLocked()
        lock.unlock()

        if broadcast {
            broadcastUpdate(grant: nil)
        }
    }

    public func invalidate(keyLabel: String) {
        invalidate(keyLabel: keyLabel, broadcast: true)
    }

    private func expireActiveGrants() {
        lock.lock()
        var expiredAny = false
        for (label, grant) in activeGrants {
            if !grant.isValid {
                grant.invalidate()
                activeGrants.removeValue(forKey: label)
                expiredAny = true
            }
        }
        for (compoundKey, grant) in personalGrants {
            if !grant.isValid {
                grant.invalidate()
                personalGrants.removeValue(forKey: compoundKey)
                expiredAny = true
            }
        }
        scheduleNextExpirationTimerLocked()
        lock.unlock()
        if expiredAny {
            broadcastUpdate(grant: nil)
        }
    }

    private func scheduleNextExpirationTimerLocked() {
        let gitDeadlines = activeGrants.values.compactMap { $0.isValid ? $0.deadline : nil }
        let sshDeadlines = personalGrants.values.compactMap { $0.isValid ? $0.deadline : nil }
        guard let earliest = (gitDeadlines + sshDeadlines).min() else {
            expirationTimer?.schedule(deadline: .distantFuture)
            return
        }
        expirationTimer?.schedule(deadline: earliest)
    }

    private func recentSignatureKey(label: String, clientIdentity: String) -> String {
        "\(label)\u{0}\(clientIdentity)"
    }

    private func personalGrantKey(label: String, approvalIdentity: String) -> String {
        "\(label)\u{0}\(approvalIdentity)"
    }

    private func broadcastUpdate(
        grant: GitSigningGrant?,
        summary: (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? = nil
    ) {
        var userInfo: [AnyHashable: Any] = [:]
        if let grant = grant, grant.isValid {
            userInfo["active"] = true
            userInfo["keyLabel"] = grant.keyLabel
            userInfo["remainingSeconds"] = grant.remainingSeconds
            userInfo["remainingOperations"] = grant.remainingOperations
        } else if let summary {
            userInfo["active"] = true
            userInfo["keyLabel"] = summary.keyLabel
            userInfo["remainingSeconds"] = summary.remainingSeconds
            userInfo["remainingOperations"] = summary.remainingOperations
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
