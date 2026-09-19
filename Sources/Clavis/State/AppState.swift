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

    private init() {
        self.isDaemonMode = CommandLine.arguments.contains("--daemon")
        refresh()
    }

    public func refresh() {
        do {
            keys = try KeychainManager.shared.listKeys()
            isSocketActive = SSHAgentServer.sharedInstance.isSocketActive
            cachedKeysCount = SessionCacheManager.shared.cachedCount
            selectedTimeout = SessionCacheManager.shared.currentTimeout
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
        SessionCacheManager.shared.currentTimeout = timeout
        selectedTimeout = timeout
        refresh()
    }

    public func lockNow() {
        SessionCacheManager.shared.clearCache()
        refresh()
    }

    public func isKeyUnlocked(label: String) -> Bool {
        SessionCacheManager.shared.isKeyUnlocked(label: label)
    }

    public func remainingTimeFormatted(label: String) -> String? {
        guard let remaining = SessionCacheManager.shared.remainingTime(label: label) else { return nil }
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
