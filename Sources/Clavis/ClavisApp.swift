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
    }
}

public class WindowManager: NSObject, NSWindowDelegate {
    public static let shared = WindowManager()
    private var keyManagerWindow: NSWindow?

    public func openKeyManager() {
        NSApp.setActivationPolicy(.regular)

        if let window = keyManagerWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let keyListView = KeyListView().environmentObject(AppState.shared)
        let hostingController = NSHostingController(rootView: keyListView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 500),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Clavis Key Manager"
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.keyManagerWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func windowWillClose(_ notification: Notification) {
        keyManagerWindow = nil
        NSApp.setActivationPolicy(.accessory)
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
