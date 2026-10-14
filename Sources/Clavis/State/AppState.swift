import SwiftUI
import Combine
import ClavisCore
import UserNotifications

public enum KeyManagerSheet: String, Identifiable {
    case create

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

    public init(keyLabel: String, remainingSeconds: Int, remainingOperations: Int) {
        self.keyLabel = keyLabel
        self.remainingSeconds = remainingSeconds
        self.remainingOperations = remainingOperations
    }
}

@MainActor
public class AppState: ObservableObject {
    public static let shared = AppState()

    // MARK: - Stored @Published Properties for View & Test Compatibility

    @Published public var keys: [SSHKeyInfo] = [] {
        didSet {
            if keyManagementViewModel.keys != keys {
                keyManagementViewModel.keys = keys
            }
        }
    }

    @Published public var isSocketActive: Bool = false {
        didSet {
            if settingsViewModel.isSocketActive != isSocketActive {
                settingsViewModel.isSocketActive = isSocketActive
            }
        }
    }

    @Published public var agentPID: pid_t? = nil {
        didSet {
            if settingsViewModel.agentPID != agentPID {
                settingsViewModel.agentPID = agentPID
            }
        }
    }

    @Published public var activeGitGrace: ActiveGitGraceInfo? = nil {
        didSet {
            if settingsViewModel.activeGitGrace != activeGitGrace {
                settingsViewModel.activeGitGrace = activeGitGrace
            }
        }
    }

    @Published public var agentSessions: [AgentSessionSummary] = [] {
        didSet {
            if agentSessionViewModel.agentSessions != agentSessions {
                agentSessionViewModel.agentSessions = agentSessions
            }
        }
    }

    @Published public var errorMessage: String? = nil {
        didSet {
            if keyManagementViewModel.errorMessage != errorMessage {
                keyManagementViewModel.errorMessage = errorMessage
            }
            if settingsViewModel.errorMessage != errorMessage {
                settingsViewModel.errorMessage = errorMessage
            }
        }
    }

    @Published public var isDaemonMode: Bool = false {
        didSet {
            if settingsViewModel.isDaemonMode != isDaemonMode {
                settingsViewModel.isDaemonMode = isDaemonMode
            }
        }
    }

    @Published public var launchAtLogin: Bool = false {
        didSet {
            if settingsViewModel.launchAtLogin != launchAtLogin {
                settingsViewModel.launchAtLogin = launchAtLogin
            }
        }
    }

    @Published public var showingSettings: Bool = false {
        didSet {
            if settingsViewModel.showingSettings != showingSettings {
                settingsViewModel.showingSettings = showingSettings
            }
        }
    }

    @Published public var activeSheet: KeyManagerSheet? = nil {
        didSet {
            if settingsViewModel.activeSheet != activeSheet {
                settingsViewModel.activeSheet = activeSheet
            }
        }
    }

    // MARK: - Focused Child ViewModels

    public let keyManagementViewModel: KeyManagementViewModel
    public let agentSessionViewModel: AgentSessionViewModel
    public let settingsViewModel: SettingsViewModel

    private var cancellables = Set<AnyCancellable>()

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
        self.isDaemonMode = isDaemon

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
        self.settingsViewModel = settingsVM

        // Initialize stored properties from child viewmodels
        self.keys = keyVM.keys
        self.isSocketActive = settingsVM.isSocketActive
        self.agentPID = settingsVM.agentPID
        self.activeGitGrace = settingsVM.activeGitGrace
        self.agentSessions = sessionVM.agentSessions
        self.errorMessage = settingsVM.errorMessage ?? keyVM.errorMessage
        self.launchAtLogin = settingsVM.launchAtLogin
        self.showingSettings = settingsVM.showingSettings
        self.activeSheet = settingsVM.activeSheet

        if Self.isRealAppBundle {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }

        // Combine Upward Synchronization: Child -> AppState
        keyVM.$keys
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newKeys in
                guard let self else { return }
                if self.keys != newKeys {
                    self.keys = newKeys
                }
            }
            .store(in: &cancellables)

        keyVM.$errorMessage
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newErr in
                guard let self else { return }
                if self.errorMessage != newErr {
                    self.errorMessage = newErr
                }
            }
            .store(in: &cancellables)

        sessionVM.$agentSessions
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newSessions in
                guard let self else { return }
                if self.agentSessions != newSessions {
                    self.agentSessions = newSessions
                }
            }
            .store(in: &cancellables)

        settingsVM.$isSocketActive
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newSocketActive in
                guard let self else { return }
                if self.isSocketActive != newSocketActive {
                    self.isSocketActive = newSocketActive
                }
            }
            .store(in: &cancellables)

        settingsVM.$agentPID
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newPID in
                guard let self else { return }
                if self.agentPID != newPID {
                    self.agentPID = newPID
                }
            }
            .store(in: &cancellables)

        settingsVM.$activeGitGrace
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newGrace in
                guard let self else { return }
                if self.activeGitGrace != newGrace {
                    self.activeGitGrace = newGrace
                }
            }
            .store(in: &cancellables)

        settingsVM.$errorMessage
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newErr in
                guard let self else { return }
                if self.errorMessage != newErr {
                    self.errorMessage = newErr
                }
            }
            .store(in: &cancellables)

        settingsVM.$isDaemonMode
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newDaemon in
                guard let self else { return }
                if self.isDaemonMode != newDaemon {
                    self.isDaemonMode = newDaemon
                }
            }
            .store(in: &cancellables)

        settingsVM.$launchAtLogin
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newLaunch in
                guard let self else { return }
                if self.launchAtLogin != newLaunch {
                    self.launchAtLogin = newLaunch
                }
            }
            .store(in: &cancellables)

        settingsVM.$showingSettings
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newShowing in
                guard let self else { return }
                if self.showingSettings != newShowing {
                    self.showingSettings = newShowing
                }
            }
            .store(in: &cancellables)

        settingsVM.$activeSheet
            .dropFirst()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newSheet in
                guard let self else { return }
                if self.activeSheet != newSheet {
                    self.activeSheet = newSheet
                }
            }
            .store(in: &cancellables)
    }

    // MARK: - Forwarding Public Methods

    @MainActor
    public func updateGitGraceState() {
        settingsViewModel.updateGitGraceState()
        self.activeGitGrace = settingsViewModel.activeGitGrace
    }

    public func refresh() {
        keyManagementViewModel.refresh()
        settingsViewModel.refresh()
        agentSessionViewModel.refreshAgentSessions()

        self.keys = keyManagementViewModel.keys
        self.isSocketActive = settingsViewModel.isSocketActive
        self.agentPID = settingsViewModel.agentPID
        self.launchAtLogin = settingsViewModel.launchAtLogin
        self.errorMessage = settingsViewModel.errorMessage ?? keyManagementViewModel.errorMessage
        self.activeGitGrace = settingsViewModel.activeGitGrace
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

    @discardableResult
    public nonisolated func extendAgentSession(id: String, minutes: Int) -> Date? {
        agentSessionViewModel.extendAgentSession(id: id, minutes: minutes)
    }

    public func endGitSigningSession() {
        settingsViewModel.endGitSigningSession()
        self.errorMessage = settingsViewModel.errorMessage
        self.activeGitGrace = settingsViewModel.activeGitGrace
    }

    public func startAgent() {
        settingsViewModel.startAgent()
        self.errorMessage = settingsViewModel.errorMessage
        self.isSocketActive = settingsViewModel.isSocketActive
        self.agentPID = settingsViewModel.agentPID
    }

    public func stopAgent() {
        settingsViewModel.stopAgent()
        self.isSocketActive = settingsViewModel.isSocketActive
        self.agentPID = settingsViewModel.agentPID
    }

    public func shutdownForTermination() {
        settingsViewModel.shutdownForTermination()
        self.activeGitGrace = settingsViewModel.activeGitGrace
        self.isSocketActive = settingsViewModel.isSocketActive
        self.agentPID = settingsViewModel.agentPID
    }

    public func restartAgent() {
        settingsViewModel.restartAgent()
        self.errorMessage = settingsViewModel.errorMessage
        self.isSocketActive = settingsViewModel.isSocketActive
        self.agentPID = settingsViewModel.agentPID
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        settingsViewModel.setLaunchAtLogin(enabled)
        self.launchAtLogin = settingsViewModel.launchAtLogin
    }

    public func lockNow() {
        settingsViewModel.lockNow()
        self.errorMessage = settingsViewModel.errorMessage
        self.activeGitGrace = settingsViewModel.activeGitGrace
    }

    public func generateKey(
        label: String,
        algorithm: String = "ECDSA P-256",
        storageType: KeyStorageType = .secureEnclave,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general
    ) throws -> SSHKeyInfo {
        defer {
            self.keys = keyManagementViewModel.keys
            self.errorMessage = keyManagementViewModel.errorMessage
        }
        return try keyManagementViewModel.generateKey(
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: biometricPolicy,
            keyPurpose: keyPurpose
        )
    }

    public func deleteKey(label: String) throws {
        defer {
            self.keys = keyManagementViewModel.keys
            self.errorMessage = keyManagementViewModel.errorMessage
        }
        try keyManagementViewModel.deleteKey(label: label)
    }

    public func changeKeyKind(label: String, to newPurpose: KeyPurpose) throws {
        defer {
            self.keys = keyManagementViewModel.keys
            self.errorMessage = keyManagementViewModel.errorMessage
        }
        try keyManagementViewModel.changeKeyKind(label: label, to: newPurpose)
    }

    public func changeKind(label: String, to newPurpose: KeyPurpose) throws {
        try changeKeyKind(label: label, to: newPurpose)
    }

    public func lockKey(label: String) throws {
        defer {
            self.keys = keyManagementViewModel.keys
            self.errorMessage = keyManagementViewModel.errorMessage
        }
        try keyManagementViewModel.lockKey(label: label)
    }

    public func clearError() {
        keyManagementViewModel.clearError()
        settingsViewModel.clearError()
        self.errorMessage = nil
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
        #if DEBUG
        NSClassFromString("XCTestCase") != nil ||
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
        #else
        false
        #endif
    }

    private static var isRealAppBundle: Bool {
        !isRunningUnderXCTest &&
        Bundle.main.bundleURL.pathExtension == "app"
    }
}
