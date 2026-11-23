import SwiftUI
import Observation
import ClavisCore
import UserNotifications

public enum KeyManagerSheet: String, Identifiable {
    case create
    case settings
    case connect

    public var id: String { rawValue }
}

public enum MainWindowPane: String, Equatable, Sendable {
    case keys
    case history
}

public struct ActiveGitGraceInfo: Equatable, Identifiable, Sendable {
    public var id: String { keyLabel }
    public let keyLabel: String
    public let remainingSeconds: Int
    public let remainingOperations: Int
    public let expiresAt: Date
    public let endsAtLock: Bool
    public let callerName: String?

    public var formattedRemainingTime: String {
        let mins = remainingSeconds / 60
        let secs = remainingSeconds % 60
        return String(format: "%d:%02d", mins, secs)
    }

    public init(
        keyLabel: String,
        remainingSeconds: Int,
        remainingOperations: Int,
        observedAt: Date = Date(),
        endsAtLock: Bool = false,
        callerName: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.remainingSeconds = remainingSeconds
        self.remainingOperations = remainingOperations
        self.endsAtLock = endsAtLock
        self.callerName = callerName
        self.expiresAt = observedAt.addingTimeInterval(TimeInterval(max(0, remainingSeconds)))
    }
}

@Observable
@MainActor
public class AppState {
    public static let shared = AppState()

    // MARK: - Child-Backed Forwarding Properties

    public var keys: [SSHKeyInfo] {
        get { keyManagementViewModel.keys }
        set { keyManagementViewModel.keys = newValue }
    }

    public var isSocketActive: Bool {
        get { settingsViewModel.isSocketActive }
        set { settingsViewModel.isSocketActive = newValue }
    }

    public var agentPID: pid_t? {
        get { settingsViewModel.agentPID }
        set { settingsViewModel.agentPID = newValue }
    }

    public var activeGitGraces: [ActiveGitGraceInfo] {
        get { settingsViewModel.activeGitGraces }
        set { settingsViewModel.activeGitGraces = newValue }
    }

    public var activeGitGrace: ActiveGitGraceInfo? {
        get { settingsViewModel.activeGitGrace }
        set { settingsViewModel.activeGitGrace = newValue }
    }

    public var vaultSyncReport: VaultSyncReport? {
        get { keyManagementViewModel.vaultSyncReport }
        set { keyManagementViewModel.vaultSyncReport = newValue }
    }

    public var agentSessions: [AgentSessionSummary] {
        get { agentSessionViewModel.agentSessions }
        set { agentSessionViewModel.agentSessions = newValue }
    }

    public var errorMessage: String? {
        get {
            directErrorMessage
                ?? settingsViewModel.errorMessage
                ?? keyManagementViewModel.errorMessage
                ?? requestPolicy.errorMessage
        }
        set {
            if let newValue {
                directErrorMessage = newValue
            } else {
                directErrorMessage = nil
                keyManagementViewModel.errorMessage = nil
                settingsViewModel.errorMessage = nil
                requestPolicy.clearError()
            }
        }
    }

    public var isDaemonMode: Bool {
        get { settingsViewModel.isDaemonMode }
        set { settingsViewModel.isDaemonMode = newValue }
    }

    public var launchAtLogin: Bool {
        get { settingsViewModel.launchAtLogin }
        set { settingsViewModel.launchAtLogin = newValue }
    }

    public var showingSettings: Bool {
        get { settingsViewModel.showingSettings }
        set { settingsViewModel.showingSettings = newValue }
    }

    /// Key targeted by the Connect & Test sheet (S-05), set by the ⋯ menu / post-create flow.
    public var connectTarget: SSHKeyInfo? = nil
    public var activeSheet: KeyManagerSheet? {
        get { settingsViewModel.activeSheet }
        set { settingsViewModel.activeSheet = newValue }
    }

    public var activeMainPane: MainWindowPane = .keys
    /// One-shot request for the key History should open scoped to. The committed filter state
    /// (including the sidebar selection derived from it) lives in `HistoryViewModel`.
    public var historyFilterKeyFingerprint: String? = nil
    /// Bumped on every open request so re-opening for another key works while History is showing.
    public private(set) var historyOpenRequestID: Int = 0
    private var directErrorMessage: String? = nil

    public func openHistoryPane(forKeyFingerprint fingerprint: String? = nil) {
        self.historyFilterKeyFingerprint = fingerprint
        self.historyOpenRequestID &+= 1
        self.activeMainPane = .history
    }

    // MARK: - Focused Child ViewModels

    public let keyManagementViewModel: KeyManagementViewModel
    public let agentSessionViewModel: AgentSessionViewModel
    public let settingsViewModel: SettingsViewModel
    public let requestPolicy: RequestPauseModel

    /// The single in-window authenticated settings request (variant 07 tile).
    public let policyMutations = PolicyMutationCoordinator()

    // MARK: - Notifications and Callbacks

    public var onAgentNotificationPosted: ((_ title: String, _ body: String) -> Void)? {
        get { agentSessionViewModel.onAgentNotificationPosted }
        set { agentSessionViewModel.onAgentNotificationPosted = newValue }
    }

    // MARK: - Initializer

    public init(
        keyManager: KeychainManager = .shared,
        sshAgentServer: SSHAgentServer = .shared,
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared,
        isDaemonMode: Bool? = nil,
        terminationAgentStop: (() -> Bool)? = nil,
        keyManagementViewModel: KeyManagementViewModel? = nil,
        agentSessionViewModel: AgentSessionViewModel? = nil,
        settingsViewModel: SettingsViewModel? = nil
    ) {
        let isDaemon = isDaemonMode ?? CommandLine.arguments.contains("--daemon")

        let keyVM = keyManagementViewModel ?? KeyManagementViewModel(
            keyManager: keyManager,
            agentLifecycle: agentLifecycle
        )
        self.keyManagementViewModel = keyVM

        let sessionVM = agentSessionViewModel ?? AgentSessionViewModel(
            agentLifecycle: agentLifecycle,
            keysProvider: { [weak keyVM] in keyVM?.keys ?? [] }
        )
        self.agentSessionViewModel = sessionVM

        let settingsVM = settingsViewModel ?? SettingsViewModel(
            agentLifecycle: agentLifecycle,
            sshAgentServer: sshAgentServer,
            isDaemonMode: isDaemon,
            terminationAgentStop: terminationAgentStop
        )
        if isDaemonMode != nil && settingsViewModel != nil {
            settingsVM.isDaemonMode = isDaemon
        }
        self.settingsViewModel = settingsVM
        self.requestPolicy = RequestPauseModel(agent: agentLifecycle)

        if Self.isRealAppBundle {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
    }

    // MARK: - Forwarding Public Methods

    @MainActor
    public func updateGitGraceState() {
        settingsViewModel.updateGitGraceState()
    }

    public func refresh() {
        directErrorMessage = nil
        keyManagementViewModel.refresh()
        settingsViewModel.refresh()
        agentSessionViewModel.refreshAgentSessions()
    }

    public func refreshAgentSessions() {
        agentSessionViewModel.refreshAgentSessions()
    }

    public func endAgentSession(id: String) {
        agentSessionViewModel.endAgentSession(id: id)
    }

    @discardableResult
    public nonisolated func revokeAllAgentSessions() -> Int {
        agentSessionViewModel.revokeAllAgentSessions()
    }

    public func revokeAllAgentSessionsAsync() {
        agentSessionViewModel.revokeAllAgentSessionsAsync()
    }

    @discardableResult
    public nonisolated func extendAgentSession(id: String, minutes: Int) -> Date? {
        agentSessionViewModel.extendAgentSession(id: id, minutes: minutes)
    }

    public func setRequestsPaused(_ paused: Bool) async {
        _ = await requestPolicy.setPaused(paused)
        refreshAgentSessions()
        updateGitGraceState()
    }

    public func endGitSigningSession() {
        settingsViewModel.endGitSigningSession()
    }

    public func revokeGitGrace(for keyLabel: String) {
        settingsViewModel.revokeGitGrace(for: keyLabel)
    }

    public func revokeGitGrace(keyLabel: String) {
        revokeGitGrace(for: keyLabel)
    }

    @discardableResult
    public func syncVault(repair: Bool = false) throws -> VaultSyncReport {
        try keyManagementViewModel.syncVault(repair: repair)
    }

    public func startAgent() {
        settingsViewModel.startAgent()
    }

    public func stopAgent() {
        settingsViewModel.stopAgent()
    }

    public func shutdownForTermination() {
        settingsViewModel.shutdownForTermination()
    }

    public func restartAgent() {
        settingsViewModel.restartAgent()
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        settingsViewModel.setLaunchAtLogin(enabled)
    }

    public func lockNow() {
        settingsViewModel.lockNow()
    }

    public func generateKey(
        label: String,
        algorithm: String = "ECDSA P-256",
        storageType: KeyStorageType = .secureEnclave,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general,
        accessProfile: KeyAccessProfile? = nil,
        unlockedTimeout: KeyGracePeriod? = nil
    ) throws -> SSHKeyInfo {
        let info = try keyManagementViewModel.generateKey(
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: biometricPolicy,
            keyPurpose: keyPurpose,
            accessProfile: accessProfile,
            unlockedTimeout: unlockedTimeout
        )
        // Generating a key already authenticates the user; transition the panel out
        // of its initial locked state so leaving empty-vault bypass does not lock the window.
        if !PanelLockController.shared.currentMode.requiresPIN && PanelLockController.shared.state == .locked {
            PanelLockController.shared.applyUnlock(context: nil)
        }
        return info
    }

    public func deleteKey(label: String) throws {
        try keyManagementViewModel.deleteKey(label: label)
    }

    @discardableResult
    public func renameKey(from oldLabel: String, to newLabel: String) throws -> SSHKeyInfo {
        try keyManagementViewModel.renameKey(from: oldLabel, to: newLabel)
    }

    public func changeKeyKind(label: String, to newPurpose: KeyPurpose) throws {
        try keyManagementViewModel.changeKeyKind(label: label, to: newPurpose)
    }

    public func changeKind(label: String, to newPurpose: KeyPurpose) throws {
        try changeKeyKind(label: label, to: newPurpose)
    }

    public func changeAccessProfile(label: String, type: KeyType? = nil, capabilities: KeyCapabilities? = nil) throws {
        defer {
            refreshAgentSessions()
            updateGitGraceState()
        }
        try keyManagementViewModel.changeAccessProfile(label: label, type: type, capabilities: capabilities)
    }

    public func changeAccessProfile(
        label: String,
        type: KeyType? = nil,
        capabilities: KeyCapabilities? = nil,
        unlockedTimeout: KeyGracePeriod? = nil,
        expectedCurrent: KeyAccessProfile?,
        expectedTimeout: KeyGracePeriod? = nil,
        authenticator: any AsyncUserAuthenticating
    ) async throws {
        defer {
            settingsViewModel.activeGitGraces.removeAll { $0.keyLabel == label }
            settingsViewModel.activeGitGrace = settingsViewModel.activeGitGraces.first
            refreshAgentSessions()
            updateGitGraceState()
        }
        try await keyManagementViewModel.changeAccessProfile(
            label: label, type: type, capabilities: capabilities,
            unlockedTimeout: unlockedTimeout,
            expectedCurrent: expectedCurrent, expectedTimeout: expectedTimeout,
            authenticator: authenticator
        )
    }

    public func lockKey(label: String) throws {
        try keyManagementViewModel.lockKey(label: label)
    }

    public func gracePeriod(for key: SSHKeyInfo) -> KeyGracePeriod {
        keyManagementViewModel.gracePeriod(for: key)
    }

    public func setGracePeriod(_ period: KeyGracePeriod, for key: SSHKeyInfo) {
        keyManagementViewModel.setGracePeriod(period, for: key)
        revokeGitGrace(for: key.label)
        for session in agentSessions where session.keyFingerprint == key.fingerprint {
            endAgentSession(id: session.id)
        }
    }

    public func isKeyUnlocked(_ key: SSHKeyInfo) -> Bool {
        let now = Date()
        let hasActiveGrace = activeGitGraces.contains { $0.keyLabel == key.label && $0.remainingSeconds > 0 }
        let hasActiveSession = agentSessions.contains { $0.keyFingerprint == key.fingerprint && $0.expiresAt > now }
        return hasActiveGrace || hasActiveSession
    }

    public func lastActivityDate(for key: SSHKeyInfo) -> Date? {
        var query = AuditQuery()
        query.keyFingerprint = key.fingerprint
        query.limit = 1
        return (try? AuditStore().query(query).first)?.event.time
    }

    public func clearError() {
        errorMessage = nil
    }

    public func getAgentPolicy(fingerprint: String) -> AgentKeyPolicy? {
        keyManagementViewModel.getAgentPolicy(fingerprint: fingerprint)
    }

    public func setAgentPolicy(_ policy: AgentKeyPolicy, fingerprint: String) throws {
        try keyManagementViewModel.setAgentPolicy(policy, fingerprint: fingerprint)
    }

    public func getGlobalPolicy() -> AgentGlobalPolicy? {
        keyManagementViewModel.getGlobalPolicy()
    }

    public func setGlobalPolicy(_ global: AgentGlobalPolicy) throws {
        try keyManagementViewModel.setGlobalPolicy(global)
    }

    @MainActor
    internal func handleAgentSignedNotification(_ note: Notification) {
        agentSessionViewModel.handleAgentSignedNotification(note)
    }

    @MainActor
    internal func handleAgentRateLimitedNotification(_ note: Notification) {
        agentSessionViewModel.handleAgentRateLimitedNotification(note)
    }

    private static var isRunningUnderXCTest: Bool {
        ClavisEnvironment.isTesting
    }

    private static var isRealAppBundle: Bool {
        !isRunningUnderXCTest &&
        Bundle.main.bundleURL.pathExtension == "app"
    }
}
