import SwiftUI
import Combine
import ClavisCore
import UserNotifications

@MainActor
public class AgentSessionViewModel: ObservableObject {
    @Published public var agentSessions: [AgentSessionSummary] = []

    private var lastSignedNotificationTimeBySession: [String: Date] = [:]
    internal var onAgentNotificationPosted: ((_ title: String, _ body: String) -> Void)?
    private var notificationObservers: [NSObjectProtocol] = []

    private let agentLifecycle: any AgentControlling
    private let keysProvider: () -> [SSHKeyInfo]

    public init(
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared,
        keysProvider: @escaping () -> [SSHKeyInfo] = { [] }
    ) {
        self.agentLifecycle = agentLifecycle
        self.keysProvider = keysProvider

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
        let now = Date()
        if let last = lastSignedNotificationTimeBySession[sessionID], now.timeIntervalSince(last) < 10.0 {
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
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { _ in }
    }

    private static var isRealAppBundle: Bool {
        NSClassFromString("XCTestCase") == nil &&
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil &&
        Bundle.main.bundleURL.pathExtension == "app"
    }
}
