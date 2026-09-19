import SwiftUI
import ClavisCore

@MainActor
public class AppState: ObservableObject {
    public static let shared = AppState()

    @Published public var keys: [Ed25519KeyInfo] = []
    @Published public var isSocketActive: Bool = false
    @Published public var selectedTimeout: SessionTimeout = .never
    @Published public var cachedKeysCount: Int = 0
    @Published public var errorMessage: String? = nil
    @Published public var isDaemonMode: Bool = false
    @Published public var launchAtLogin: Bool = false
    @Published public var showingSettings: Bool = false

    private let keyManager: KeychainManager
    private let sessionCache: SessionCacheManager
    private let sshAgentServer: SSHAgentServer

    init(
        keyManager: KeychainManager = .shared,
        sessionCache: SessionCacheManager = .shared,
        sshAgentServer: SSHAgentServer = .sharedInstance
    ) {
        self.keyManager = keyManager
        self.sessionCache = sessionCache
        self.sshAgentServer = sshAgentServer
        self.isDaemonMode = CommandLine.arguments.contains("--daemon")
        refresh()
    }

    public func refresh() {
        do {
            keys = try keyManager.listKeys()
            isSocketActive = sshAgentServer.isSocketActive
            cachedKeysCount = sessionCache.cachedCount
            selectedTimeout = sessionCache.currentTimeout
            launchAtLogin = LaunchAtLoginManager.shared.isEnabled
            errorMessage = nil
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

    public func clearError() {
        errorMessage = nil
    }
}

public extension SSHAgentServer {
    static let sharedInstance = SSHAgentServer()
}
