import SwiftUI
import ClavisCore

@main
@MainActor
struct ClavisApp: App {
    @StateObject private var appState = AppState.shared

    init() {
        guard SingleInstanceLock.shared.acquire() else {
            ClavisLogger.log("APP_START", "Another instance of Clavis is already running. Exiting duplicate process.")
            exit(0)
        }

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

        // Bring Key Manager window to front when a subsequent launch is attempted
        DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.clavis.openKeyManager"),
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor in
                WindowManager.shared.openKeyManager()
            }
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
