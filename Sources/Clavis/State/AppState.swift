import SwiftUI
import Combine
import ClavisCore
import UserNotifications

public enum KeyManagerSheet: String, Identifiable {
    case create
    case importKey

    public var id: String { rawValue }
}

public struct ActiveGitGraceInfo: Equatable {
    public let keyLabel: String
    public let remainingSeconds: Int
    public let remainingOperations: Int

    public var formattedRemainingTime: String {
        let mins = remainingSeconds / 60
        let secs = remainingSeconds % 60
        return String(format: "%d:%02d", mins, secs)
    }
}

@MainActor
public class AppState: ObservableObject {
    public static let shared = AppState()

    @Published public var keys: [Ed25519KeyInfo] = []
    @Published public var isSocketActive: Bool = false
    @Published public var agentPID: pid_t? = nil
    @Published public var selectedTimeout: SessionTimeout = .never
    @Published public var cachedKeysCount: Int = 0
    @Published public var activeGitGrace: ActiveGitGraceInfo? = nil
    @Published public var agentSessions: [AgentSessionSummary] = []
    @Published public var errorMessage: String? = nil
    @Published public var isDaemonMode: Bool = false
    @Published public var launchAtLogin: Bool = false
    @Published public var showingSettings: Bool = false
    @Published public var activeSheet: KeyManagerSheet? = nil

    private var lockCancellable: AnyCancellable?
    private var lastSignedNotificationTimeBySession: [String: Date] = [:]
    internal var onAgentNotificationPosted: ((_ title: String, _ body: String) -> Void)?

    private let keyManager: KeychainManager
    private let sessionCache: SessionCacheManager
    private let sshAgentServer: SSHAgentServer
    private let agentLifecycle: AgentLifecycleManager
    private let terminationAgentStop: () -> Bool

    init(
        keyManager: KeychainManager = .shared,
        sessionCache: SessionCacheManager = .shared,
        sshAgentServer: SSHAgentServer = .shared,
        agentLifecycle: AgentLifecycleManager = .shared,
        terminationAgentStop: (() -> Bool)? = nil
    ) {
        self.keyManager = keyManager
        self.sessionCache = sessionCache
        self.sshAgentServer = sshAgentServer
        self.agentLifecycle = agentLifecycle
        self.terminationAgentStop = terminationAgentStop ?? { agentLifecycle.stopAgent() }
        self.isDaemonMode = CommandLine.arguments.contains("--daemon")

        if Self.isRealAppBundle {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }

        DistributedNotificationCenter.default().addObserver(
            forName: GitSigningGraceManager.gitGraceUpdatedNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.updateGitGraceState()
            }
        }

        DistributedNotificationCenter.default().addObserver(
            forName: AgentSessionRegistry.agentSessionsChangedNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.refreshAgentSessions()
            }
        }

        DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let self else { return }
            Task { @MainActor in
                self.handleAgentSignedNotification(note)
            }
        }

        DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let self else { return }
            Task { @MainActor in
                self.handleAgentRateLimitedNotification(note)
            }
        }

        lockCancellable = PanelLockController.shared.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in
                if state == .locked {
                    self?.activeSheet = nil
                    self?.showingSettings = false
                }
            }

        refresh()
    }

    @MainActor
    public func updateGitGraceState() {
        if let localGrant = GitSigningGraceManager.shared.currentActiveGrant {
            self.activeGitGrace = ActiveGitGraceInfo(
                keyLabel: localGrant.keyLabel,
                remainingSeconds: localGrant.remainingSeconds,
                remainingOperations: localGrant.remainingOperations
            )
            return
        }
        let lifecycle = self.agentLifecycle
        Task.detached { [weak self] in
            let remote = lifecycle.queryAgentGitGrace()
            await MainActor.run { [weak self] in
                guard let self = self else { return }
                if let remote = remote {
                    self.activeGitGrace = ActiveGitGraceInfo(
                        keyLabel: remote.keyLabel,
                        remainingSeconds: remote.remainingSeconds,
                        remainingOperations: remote.remainingOperations
                    )
                } else {
                    self.activeGitGrace = nil
                }
            }
        }
    }

    public func refresh() {
        do {
            keys = try keyManager.listKeys()
            isSocketActive = agentLifecycle.isAgentRunning || sshAgentServer.isSocketActive
            agentPID = agentLifecycle.agentPID
            cachedKeysCount = sessionCache.cachedCount
            selectedTimeout = sessionCache.currentTimeout
            launchAtLogin = LaunchAtLoginManager.shared.isEnabled
            errorMessage = nil
            updateGitGraceState()
            refreshAgentSessions()
        } catch {
            errorMessage = error.localizedDescription
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

    public func endGitSigningSession() {
        do {
            try agentLifecycle.sendLockAllToAgent()
            GitSigningGraceManager.shared.invalidateAll()
            activeGitGrace = nil
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func startAgent() {
        do {
            try agentLifecycle.startAgent()
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func stopAgent() {
        _ = agentLifecycle.stopAgent()
        refresh()
    }

    /// Performs the security-sensitive shutdown sequence shared by every GUI
    /// termination path (menu action, Cmd+Q, Dock, logout, or system shutdown).
    public func shutdownForTermination() {
        sessionCache.clearCache()
        GitSigningGraceManager.shared.invalidateAll()
        sshAgentServer.stop()
        _ = terminationAgentStop()
        activeGitGrace = nil
        cachedKeysCount = 0
        isSocketActive = false
        agentPID = nil
    }

    public func restartAgent() {
        do {
            try agentLifecycle.restartAgent()
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        LaunchAtLoginManager.shared.setLaunchAtLogin(enabled: enabled)
        launchAtLogin = enabled
    }

    public func setTimeout(_ timeout: SessionTimeout) {
        sessionCache.currentTimeout = timeout
        selectedTimeout = timeout
        refresh()
    }

    public func lockNow() {
        sessionCache.clearCache()
        cachedKeysCount = sessionCache.cachedCount
        endGitSigningSession()
        PanelLockController.shared.lock(reason: .lockNow)
    }

    public func isKeyUnlocked(label: String) -> Bool {
        sessionCache.isKeyUnlocked(label: label)
    }

    public func remainingTimeFormatted(label: String) -> String? {
        guard let remaining = sessionCache.remainingTime(label: label) else { return nil }
        let mins = max(1, Int(ceil(remaining / 60)))
        return ClavisUIStrings.Common.minRemaining(mins)
    }

    public func generateKey(
        label: String,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        let info = try keyManager.generateKey(
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: biometricPolicy,
            keyPurpose: keyPurpose
        )
        refresh()
        return info
    }

    public func importKey(
        label: String,
        consuming seedData: inout Data,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        let info = try keyManager.importKey(
            label: label,
            consuming: &seedData,
            algorithm: algorithm,
            storageType: storageType,
            keyPurpose: keyPurpose
        )
        refresh()
        return info
    }

    public func deleteKey(label: String) throws {
        try keyManager.deleteKey(label: label)
        refresh()
    }

    public func changeKind(label: String, to newPurpose: KeyPurpose) throws {
        try keyManager.changeKind(label: label, to: newPurpose)
        refresh()
    }

    public func lockKey(label: String) throws {
        try keyManager.lockKey(label: label)
        refresh()
    }

    public func clearError() {
        errorMessage = nil
    }

    public func getAgentPolicy(fingerprint: String) -> AgentKeyPolicy? {
        guard let json = agentLifecycle.getAgentPolicy(target: fingerprint),
              let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(AgentKeyPolicy.self, from: data)
    }

    public func setAgentPolicy(_ policy: AgentKeyPolicy, fingerprint: String) throws {
        try policy.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        guard let json = String(data: try encoder.encode(policy), encoding: .utf8),
              agentLifecycle.setAgentPolicy(target: fingerprint, policyJson: json) else {
            throw AgentPolicyError.policyUnavailable
        }
    }

    public func getGlobalPolicy() -> AgentGlobalPolicy? {
        guard let json = agentLifecycle.getAgentPolicy(target: "global"),
              let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(AgentGlobalPolicy.self, from: data)
    }

    public func setGlobalPolicy(_ global: AgentGlobalPolicy) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        guard let json = String(data: try encoder.encode(global), encoding: .utf8),
              agentLifecycle.setAgentPolicy(target: "global", policyJson: json) else {
            throw AgentPolicyError.policyUnavailable
        }
    }

    @MainActor
    internal func handleAgentSignedNotification(_ note: Notification) {
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
    internal func handleAgentRateLimitedNotification(_ note: Notification) {
        guard let sessionID = note.userInfo?["sessionID"] as? String else { return }
        postAgentNotification(
            title: ClavisUIStrings.AgentSession.notificationRateLimitedTitle,
            sessionID: sessionID,
            fingerprint: note.userInfo?["fingerprint"] as? String
        )
    }

    private func postAgentNotification(title: String, sessionID: String, fingerprint: String?) {
        let body: String
        if let session = agentSessions.first(where: { $0.id == sessionID }) {
            body = "\(session.toolName) · \(session.keyLabel)"
        } else if let fp = fingerprint, let key = keys.first(where: { $0.fingerprint == fp }) {
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
