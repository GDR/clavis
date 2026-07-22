import SwiftUI
import ClavisCore

@main
struct ClavisApp: App {
    @StateObject private var appState = AppState.shared

    init() {
        do {
            try SSHAgentServer.sharedInstance.start()
        } catch {
            print("Failed to start SSH agent server: \(error)")
        }
    }

    var body: some Scene {
        MenuBarExtra("Clavis", systemImage: appState.isSocketActive ? "key.fill" : "key") {
            MenuBarView()
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.window)

        WindowGroup("Clavis Key Manager") {
            KeyListView()
                .environmentObject(appState)
                .frame(minWidth: 650, minHeight: 450)
        }
    }
}

public class AppState: ObservableObject {
    public static let shared = AppState()

    @Published public var keys: [Ed25519KeyInfo] = []
    @Published public var isSocketActive: Bool = false
    @Published public var selectedTimeout: SessionTimeout = .never
    @Published public var cachedKeysCount: Int = 0
    @Published public var errorMessage: String? = nil

    private init() {
        refresh()
    }

    public func refresh() {
        do {
            keys = try KeychainManager.shared.listKeys()
            isSocketActive = SSHAgentServer.sharedInstance.isSocketActive
            cachedKeysCount = SessionCacheManager.shared.cachedCount
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func lockNow() {
        SessionCacheManager.shared.clearCache()
        refresh()
    }
}

public extension SSHAgentServer {
    static let sharedInstance = SSHAgentServer()
}
