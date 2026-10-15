import SwiftUI
import AppKit
import ClavisCore

@MainActor
final class ClavisApplicationDelegate: NSObject, NSApplicationDelegate {
    private var didShutdown = false
    private let shutdownHandler: () -> Void
    private let activeWindowsCheck: () -> Bool
    private let confirmationPrompt: () -> Bool

    override convenience init() {
        self.init(
            activeWindowsCheck: { WindowManager.shared.hasActiveWindows },
            confirmationPrompt: { ClavisApplicationDelegate.runDefaultConfirmationPrompt() },
            shutdownHandler: {
                AppState.shared.shutdownForTermination()
                SingleInstanceLock.gui.release()
            }
        )
    }

    convenience init(shutdownHandler: @escaping () -> Void) {
        self.init(
            activeWindowsCheck: { WindowManager.shared.hasActiveWindows },
            confirmationPrompt: { ClavisApplicationDelegate.runDefaultConfirmationPrompt() },
            shutdownHandler: shutdownHandler
        )
    }

    init(
        activeWindowsCheck: @escaping () -> Bool,
        confirmationPrompt: @escaping () -> Bool,
        shutdownHandler: @escaping () -> Void
    ) {
        self.activeWindowsCheck = activeWindowsCheck
        self.confirmationPrompt = confirmationPrompt
        self.shutdownHandler = shutdownHandler
        super.init()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if activeWindowsCheck() {
            guard confirmationPrompt() else {
                return .terminateCancel
            }
        }
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

    private static func runDefaultConfirmationPrompt() -> Bool {
        let alert = NSAlert()
        alert.messageText = ClavisUIStrings.MenuBar.quitConfirmationTitle
        alert.informativeText = AppState.shared.isSocketActive
            ? ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent
            : ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple
        alert.alertStyle = .warning
        alert.addButton(withTitle: ClavisUIStrings.MenuBar.quit)
        alert.addButton(withTitle: ClavisUIStrings.Common.cancel)
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }
}

@main
@MainActor
struct ClavisApp: App {
    @NSApplicationDelegateAdaptor(ClavisApplicationDelegate.self) private var appDelegate
    @StateObject private var appState = AppState.shared

    init() {
        // Wire AppKit adapters for ClavisCore decoupled hooks
        SingleInstanceLock.processActivator = AppKitProcessActivator.activate
        SystemEventMonitor.defaultSleepObserverFactory = { AppKitSleepObserver() }
        SystemEventMonitor.shared.setSleepObserver(AppKitSleepObserver())
        GitSigningGraceManager.shared.setPresenter(AppKitGitSigningGracePresenter())

        guard PlatformSupport.hasSecureEnclave else {
            let alert = NSAlert()
            alert.messageText = ClavisUIStrings.App.unsupportedTitle
            alert.informativeText = ClavisUIStrings.App.unsupportedMessage
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

        // Wire panel lock triggers
        PanelLockController.shared.installSystemEventHandler(monitor: SystemEventMonitor.shared)

        NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel, .mouseMoved]) { event in
            PanelLockController.shared.noteActivity()
            return event
        }

        Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { _ in
            Task { @MainActor in
                PanelLockController.shared.tick()
            }
        }
    }

    private var closeWindowCommandTitle: String {
        let preferred = Locale.preferredLanguages.first?.lowercased() ?? ""
        if preferred.hasPrefix("ru") {
            return "Закрыть окно"
        }
        return "Close Window"
    }

    var body: some Scene {
        MenuBarExtra(ClavisUIStrings.Common.appName, systemImage: appState.isSocketActive ? "key.fill" : "key") {
            MenuBarView()
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.window)
        .commands {
            CommandGroup(replacing: .appSettings) {
                Button(ClavisUIStrings.MenuBar.settings) {
                    WindowManager.shared.openSettings()
                }
                .keyboardShortcut(",", modifiers: .command)
            }
            CommandGroup(replacing: .newItem) {
                Button(ClavisUIStrings.MenuBar.newKey) {
                    WindowManager.shared.openKeyManager(sheet: .create)
                }
                .keyboardShortcut("n", modifiers: .command)
            }
            CommandGroup(replacing: .saveItem) {
                Button(closeWindowCommandTitle) {
                    WindowManager.shared.closeActiveWindow()
                }
                .keyboardShortcut("w", modifiers: .command)
            }
            TextEditingCommands()
        }
    }
}
