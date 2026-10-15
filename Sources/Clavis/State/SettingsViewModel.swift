import SwiftUI
import Combine
import ClavisCore

@MainActor
public class SettingsViewModel: ObservableObject {
    @Published public var isSocketActive: Bool = false
    @Published public var agentPID: pid_t? = nil
    @Published public var activeGitGraces: [ActiveGitGraceInfo] = []
    @Published public var activeGitGrace: ActiveGitGraceInfo? = nil
    @Published public var isDaemonMode: Bool = false
    @Published public var launchAtLogin: Bool = false
    @Published public var showingSettings: Bool = false
    @Published public var activeSheet: KeyManagerSheet? = nil
    @Published public var errorMessage: String? = nil

    private var lockCancellable: AnyCancellable?
    private var notificationObservers: [NSObjectProtocol] = []

    private let agentLifecycle: any AgentControlling
    private let sshAgentServer: SSHAgentServer
    private let terminationAgentStop: () -> Bool

    public init(
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared,
        sshAgentServer: SSHAgentServer = .shared,
        isDaemonMode: Bool = CommandLine.arguments.contains("--daemon"),
        terminationAgentStop: (() -> Bool)? = nil
    ) {
        self.agentLifecycle = agentLifecycle
        self.sshAgentServer = sshAgentServer
        self.isDaemonMode = isDaemonMode
        self.terminationAgentStop = terminationAgentStop ?? { agentLifecycle.stopAgent() }

        let center = DistributedNotificationCenter.default()
        let obsGrace = center.addObserver(
            forName: GitSigningGraceManager.gitGraceUpdatedNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.updateGitGraceState()
            }
        }
        self.notificationObservers = [obsGrace]

        self.lockCancellable = PanelLockController.shared.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in
                if state == .locked {
                    self?.activeSheet = nil
                    self?.showingSettings = false
                }
            }

        refresh()
    }

    deinit {
        let center = DistributedNotificationCenter.default()
        for observer in notificationObservers {
            center.removeObserver(observer)
        }
    }

    public func refresh() {
        isSocketActive = agentLifecycle.isAgentRunning || sshAgentServer.isSocketActive
        agentPID = agentLifecycle.agentPID
        launchAtLogin = LaunchAtLoginManager.shared.isEnabled
        errorMessage = nil
        updateGitGraceState()
    }

    @MainActor
    public func updateGitGraceState() {
        if isDaemonMode || sshAgentServer.isSocketActive {
            let grants = GitSigningGraceManager.shared.allActiveGrants()
            self.activeGitGraces = grants.map {
                ActiveGitGraceInfo(
                    keyLabel: $0.keyLabel,
                    remainingSeconds: $0.remainingSeconds,
                    remainingOperations: $0.remainingOperations
                )
            }
            self.activeGitGrace = self.activeGitGraces.first
            return
        }
        let lifecycle = self.agentLifecycle
        Task.detached { [weak self] in
            let remotes = lifecycle.queryAllAgentGitGraces()
            await MainActor.run { [weak self] in
                guard let self = self else { return }
                self.activeGitGraces = remotes.map {
                    ActiveGitGraceInfo(
                        keyLabel: $0.keyLabel,
                        remainingSeconds: $0.remainingSeconds,
                        remainingOperations: $0.remainingOperations
                    )
                }
                self.activeGitGrace = self.activeGitGraces.first
            }
        }
    }

    public func endGitSigningSession() {
        do {
            try agentLifecycle.sendLockAllToAgent()
            GitSigningGraceManager.shared.invalidateAll()
            activeGracesClear()
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func revokeGitGrace(for keyLabel: String) {
        do {
            try agentLifecycle.invalidateAgentGrant(label: keyLabel)
            GitSigningGraceManager.shared.invalidate(keyLabel: keyLabel)
            activeGitGraces.removeAll(where: { $0.keyLabel == keyLabel })
            activeGitGrace = activeGitGraces.first
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func revokeGitGrace(keyLabel: String) {
        revokeGitGrace(for: keyLabel)
    }

    private func activeGracesClear() {
        activeGitGraces = []
        activeGitGrace = nil
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

    public func restartAgent() {
        do {
            try agentLifecycle.restartAgent()
            refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func shutdownForTermination() {
        GitSigningGraceManager.shared.invalidateAll()
        if isDaemonMode || sshAgentServer.isSocketActive {
            sshAgentServer.stop()
        }
        _ = terminationAgentStop()
        activeGitGraces = []
        activeGitGrace = nil
        isSocketActive = false
        agentPID = nil
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        LaunchAtLoginManager.shared.setLaunchAtLogin(enabled: enabled)
        launchAtLogin = enabled
    }

    public func lockNow() {
        endGitSigningSession()
        PanelLockController.shared.lock(reason: .lockNow)
    }

    public func clearError() {
        errorMessage = nil
    }
}
