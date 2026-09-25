import SwiftUI
import AppKit
import ClavisCore

@MainActor
final class ClavisApplicationDelegate: NSObject, NSApplicationDelegate {
    private var didShutdown = false
    private let shutdownHandler: () -> Void

    override convenience init() {
        self.init {
            AppState.shared.shutdownForTermination()
            SingleInstanceLock.gui.release()
        }
    }

    init(shutdownHandler: @escaping () -> Void) {
        self.shutdownHandler = shutdownHandler
        super.init()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        shutdownOnce()
        return .terminateNow
    }

    func applicationWillTerminate(_ notification: Notification) {
        shutdownOnce()
    }

    private func shutdownOnce() {
        guard !didShutdown else { return }
        didShutdown = true
        shutdownHandler()
    }
}

@main
@MainActor
struct ClavisApp: App {
    @NSApplicationDelegateAdaptor(ClavisApplicationDelegate.self) private var appDelegate
    @StateObject private var appState = AppState.shared

    init() {
        guard PlatformSupport.hasSecureEnclave else {
            let alert = NSAlert()
            alert.messageText = "Clavis cannot run on this Mac"
            alert.informativeText = PlatformSupport.unsupportedMessage
            alert.alertStyle = .critical
            alert.runModal()
            exit(1)
        }
        guard SingleInstanceLock.gui.acquire() else {
            ClavisLogger.log("APP_START", "Another instance of Clavis GUI is already running. Exiting duplicate process.")
            exit(0)
        }

        let isDaemon = CommandLine.arguments.contains("--daemon")
        if isDaemon {
            DispatchQueue.main.async {
                NSApp.setActivationPolicy(.accessory)
            }
        }

        // Ensure the background agent daemon is running
        AgentLifecycleManager.shared.ensureAgentRunning()

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
