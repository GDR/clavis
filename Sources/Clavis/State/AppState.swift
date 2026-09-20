import SwiftUI
import ClavisCore

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
    @Published public var errorMessage: String? = nil
    @Published public var isDaemonMode: Bool = false
    @Published public var launchAtLogin: Bool = false
    @Published public var showingSettings: Bool = false
    @Published public var activeSheet: KeyManagerSheet? = nil

    private let keyManager: KeychainManager
    private let sessionCache: SessionCacheManager
    private let sshAgentServer: SSHAgentServer
    private let agentLifecycle: AgentLifecycleManager

    init(
        keyManager: KeychainManager = .shared,
        sessionCache: SessionCacheManager = .shared,
        sshAgentServer: SSHAgentServer = .sharedInstance,
        agentLifecycle: AgentLifecycleManager = .shared
    ) {
        self.keyManager = keyManager
        self.sessionCache = sessionCache
        self.sshAgentServer = sshAgentServer
        self.agentLifecycle = agentLifecycle
        self.isDaemonMode = CommandLine.arguments.contains("--daemon")

        DistributedNotificationCenter.default().addObserver(
            forName: GitSigningGraceManager.gitGraceUpdatedNotification,
            object: nil,
            queue: .main
        ) { [weak self] notif in
            Task { @MainActor in
                guard let self = self else { return }
                if let active = notif.userInfo?["active"] as? Bool, active,
                   let label = notif.userInfo?["keyLabel"] as? String,
                   let sec = notif.userInfo?["remainingSeconds"] as? Int,
                   let ops = notif.userInfo?["remainingOperations"] as? Int {
                    self.activeGitGrace = ActiveGitGraceInfo(
                        keyLabel: label,
                        remainingSeconds: sec,
                        remainingOperations: ops
                    )
                } else {
                    self.activeGitGrace = nil
                }
            }
        }

        refresh()
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
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func endGitSigningSession() {
        GitSigningGraceManager.shared.invalidateAll()
        activeGitGrace = nil
        refresh()
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
        endGitSigningSession()
        refresh()
    }

    public func isKeyUnlocked(label: String) -> Bool {
        sessionCache.isKeyUnlocked(label: label)
    }

    public func remainingTimeFormatted(label: String) -> String? {
        guard let remaining = sessionCache.remainingTime(label: label) else { return nil }
        let mins = max(1, Int(ceil(remaining / 60)))
        return "\(mins) min remaining"
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

    public func lockKey(label: String) {
        keyManager.lockKey(label: label)
        refresh()
    }

    public func unlockKey(label: String) async throws {
        try await keyManager.unlock(label: label)
        refresh()
    }

    public func clearError() {
        errorMessage = nil
    }
}

public extension SSHAgentServer {
    static let sharedInstance = SSHAgentServer()
}
