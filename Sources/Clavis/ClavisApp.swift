import SwiftUI
import ClavisCore

@main
@MainActor
struct ClavisApp: App {
    @StateObject private var appState = AppState.shared

    init() {
        let isDaemon = CommandLine.arguments.contains("--daemon")
        if isDaemon {
            DispatchQueue.main.async {
                NSApp.setActivationPolicy(.accessory)
            }
        }
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

@MainActor
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

@MainActor
public class AppState: ObservableObject {
    public static let shared = AppState()

    @Published public var keys: [Ed25519KeyInfo] = []
    @Published public var isSocketActive: Bool = false
    @Published public var selectedTimeout: SessionTimeout = .never
    @Published public var cachedKeysCount: Int = 0
    @Published public var errorMessage: String? = nil
    @Published public var isDaemonMode: Bool = false

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
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
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

    public func clearError() {
        errorMessage = nil
    }
}

public extension SSHAgentServer {
    static let sharedInstance = SSHAgentServer()
}

