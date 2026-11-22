import SwiftUI
import Observation
import ClavisCore
import UserNotifications

@Observable
@MainActor
public class AgentSessionViewModel {
    public var agentSessions: [AgentSessionSummary] = []
    public var notificationAuthorizationStatus: UNAuthorizationStatus = .notDetermined
    public var isNotificationPermissionDenied: Bool = false

    nonisolated public static let defaultSignedCooldownInterval: TimeInterval = 10.0
    nonisolated public static let defaultRateLimitedCooldownInterval: TimeInterval = 5.0

    @ObservationIgnored public var signedCooldownInterval: TimeInterval
    @ObservationIgnored public var rateLimitedCooldownInterval: TimeInterval

    @ObservationIgnored private var lastSignedNotificationTimeBySession: [String: Date] = [:]
    @ObservationIgnored private var lastRateLimitedNotificationTimeBySession: [String: Date] = [:]
    @ObservationIgnored internal var dateProvider: () -> Date = { Date() }

    /// Global test override for notification authorization status.
    nonisolated(unsafe) public static var testAuthorizationStatusOverride: UNAuthorizationStatus? = nil
    /// Instance-specific test override for notification authorization status.
    @ObservationIgnored public var authorizationStatusOverride: UNAuthorizationStatus? = nil
    @ObservationIgnored private let customAuthorizationStatusProvider: (@Sendable () async -> UNAuthorizationStatus)?

    @ObservationIgnored internal var onAgentNotificationPosted: ((_ title: String, _ body: String) -> Void)?
    @ObservationIgnored private var notificationObservers: [NSObjectProtocol] = []

    @ObservationIgnored private let agentLifecycle: any AgentControlling
    @ObservationIgnored private let keysProvider: () -> [SSHKeyInfo]
    @ObservationIgnored private let notificationCenter: UNUserNotificationCenter?
    @ObservationIgnored public private(set) var registeredNotificationCenterDelegate: (any UNUserNotificationCenterDelegate)?

    public init(
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared,
        keysProvider: @escaping () -> [SSHKeyInfo] = { [] },
        notificationCenter: UNUserNotificationCenter? = nil,
        notificationCenterDelegate: (any UNUserNotificationCenterDelegate)? = ClavisNotificationCenterDelegate.shared,
        signedCooldownInterval: TimeInterval = AgentSessionViewModel.defaultSignedCooldownInterval,
        rateLimitedCooldownInterval: TimeInterval = AgentSessionViewModel.defaultRateLimitedCooldownInterval,
        authorizationStatusProvider: (@Sendable () async -> UNAuthorizationStatus)? = nil
    ) {
        self.agentLifecycle = agentLifecycle
        self.keysProvider = keysProvider
        self.registeredNotificationCenterDelegate = notificationCenterDelegate
        self.signedCooldownInterval = signedCooldownInterval
        self.rateLimitedCooldownInterval = rateLimitedCooldownInterval
        self.customAuthorizationStatusProvider = authorizationStatusProvider

        let unCenter = notificationCenter ?? (Self.isRealAppBundle ? UNUserNotificationCenter.current() : nil)
        self.notificationCenter = unCenter
        if let delegate = notificationCenterDelegate {
            unCenter?.delegate = delegate
        }

        if !Self.isRunningUnderXCTest {
            let center = DistributedNotificationCenter.default()

            let obsSessionsChanged = center.addObserver(
                forName: AgentSessionRegistry.agentSessionsChangedNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in
                    self.refreshAgentSessions()
                }
            }

            let obsSigned = center.addObserver(
                forName: NSNotification.Name("com.clavis.agentSigned"),
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self else { return }
                Task { @MainActor in
                    self.handleAgentSignedNotification(note)
                }
            }

            let obsRateLimited = center.addObserver(
                forName: NSNotification.Name("com.clavis.agentRateLimited"),
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self else { return }
                Task { @MainActor in
                    self.handleAgentRateLimitedNotification(note)
                }
            }

            self.notificationObservers = [obsSessionsChanged, obsSigned, obsRateLimited]
        }
        refreshAgentSessions()
    }

    deinit {
        let center = DistributedNotificationCenter.default()
        for observer in notificationObservers {
            center.removeObserver(observer)
        }
    }

    public func refreshAgentSessions() {
        let lifecycle = self.agentLifecycle
        Task.detached { [weak self] in
            let sessions = lifecycle.listAgentSessions()
            await MainActor.run { [weak self] in
                self?.agentSessions = sessions
            }
        }
    }

    public func endAgentSession(id: String) {
        let lifecycle = self.agentLifecycle
        Task.detached { [weak self] in
            _ = lifecycle.endAgentSession(id: id)
            let sessions = lifecycle.listAgentSessions()
            await MainActor.run { [weak self] in
                self?.agentSessions = sessions
            }
        }
    }

    @discardableResult
    public nonisolated func revokeAllAgentSessions() -> Int {
        let count = agentLifecycle.revokeAllAgentSessions()
        Task { @MainActor in
            self.refreshAgentSessions()
        }
        return count
    }

    @discardableResult
    public nonisolated func extendAgentSession(id: String, minutes: Int) -> Date? {
        let date = agentLifecycle.extendAgentSession(id: id, minutes: minutes)
        Task { @MainActor in
            self.refreshAgentSessions()
        }
        return date
    }

    @MainActor
    public func handleAgentSignedNotification(_ note: Notification) {
        guard let sessionID = note.userInfo?["sessionID"] as? String else { return }
        let now = dateProvider()
        if let last = lastSignedNotificationTimeBySession[sessionID], now.timeIntervalSince(last) < signedCooldownInterval {
            return
        }
        lastSignedNotificationTimeBySession[sessionID] = now
        postAgentNotification(
            title: ClavisUIStrings.AgentSession.notificationSignedTitle,
            sessionID: sessionID,
            fingerprint: note.userInfo?["fingerprint"] as? String
        )
    }

    @MainActor
    public func handleAgentRateLimitedNotification(_ note: Notification) {
        guard let sessionID = note.userInfo?["sessionID"] as? String else { return }
        let now = dateProvider()
        if let last = lastRateLimitedNotificationTimeBySession[sessionID], now.timeIntervalSince(last) < rateLimitedCooldownInterval {
            return
        }
        lastRateLimitedNotificationTimeBySession[sessionID] = now
        postAgentNotification(
            title: ClavisUIStrings.AgentSession.notificationRateLimitedTitle,
            sessionID: sessionID,
            fingerprint: note.userInfo?["fingerprint"] as? String
        )
    }

    private func postAgentNotification(title: String, sessionID: String, fingerprint: String?) {
        let body: String
        let currentKeys = keysProvider()
        if let session = agentSessions.first(where: { $0.id == sessionID }) {
            body = "\(session.toolName) · \(session.keyLabel)"
        } else if let fp = fingerprint, let key = currentKeys.first(where: { $0.fingerprint == fp }) {
            body = key.label
        } else {
            body = sessionID
        }
        onAgentNotificationPosted?(title, body)
        guard Self.isRealAppBundle else { return }
        let center = notificationCenter ?? UNUserNotificationCenter.current()
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        center.add(request) { _ in }
    }

    /// Checks notification authorization status and updates published properties.
    /// Honors test overrides (`authorizationStatusOverride`, `testAuthorizationStatusOverride`, or `customAuthorizationStatusProvider`)
    /// before querying `UNUserNotificationCenter.notificationSettings()`.
    @discardableResult
    public func checkNotificationAuthorizationStatus() async -> UNAuthorizationStatus {
        let status: UNAuthorizationStatus
        if let override = authorizationStatusOverride ?? Self.testAuthorizationStatusOverride {
            status = override
        } else if let provider = customAuthorizationStatusProvider {
            status = await provider()
        } else if let center = notificationCenter ?? (Self.isRealAppBundle ? UNUserNotificationCenter.current() : nil) {
            let settings = await center.notificationSettings()
            status = settings.authorizationStatus
        } else {
            status = .notDetermined
        }

        self.notificationAuthorizationStatus = status
        self.isNotificationPermissionDenied = (status == .denied)
        return status
    }

    /// Convenience async permission check triggering background Task on MainActor.
    public func checkNotificationPermissions() {
        Task { @MainActor in
            await self.checkNotificationAuthorizationStatus()
        }
    }

    /// Registers the UNUserNotificationCenter delegate.
    public static func registerNotificationCenterDelegate(
        _ delegate: any UNUserNotificationCenterDelegate = ClavisNotificationCenterDelegate.shared,
        center: UNUserNotificationCenter? = nil
    ) {
        let targetCenter = center ?? (isRealAppBundle ? UNUserNotificationCenter.current() : nil)
        targetCenter?.delegate = delegate
    }

    /// Reset any static test overrides.
    nonisolated public static func resetTestOverrides() {
        testAuthorizationStatusOverride = nil
    }

    private static var isRunningUnderXCTest: Bool {
        ClavisEnvironment.isTesting
    }

    private static var isRealAppBundle: Bool {
        !isRunningUnderXCTest &&
        Bundle.main.bundleURL.pathExtension == "app"
    }
}
