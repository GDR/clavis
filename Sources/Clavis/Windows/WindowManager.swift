import SwiftUI
import AppKit
import ClavisCore

@MainActor
public class WindowManager: NSObject, NSWindowDelegate {
    public static let shared = WindowManager()
    internal var keyManagerWindow: NSWindow?
    internal var settingsWindow: NSWindow?
    internal var historyWindow: NSWindow?
    internal var historyViewModel: HistoryViewModel?
    public weak var menuBarWindow: NSWindow?

    public override init() {
        super.init()
    }

    /// Returns true if any standard GUI management window is currently open and visible.
    public var hasActiveWindows: Bool {
        (keyManagerWindow?.isVisible == true) ||
        (settingsWindow?.isVisible == true) ||
        (historyWindow?.isVisible == true)
    }

    /// Closes the frontmost active window.
    public func closeActiveWindow() {
        if let keyWindow = NSApp.keyWindow {
            keyWindow.performClose(nil)
        } else if let mainWindow = NSApp.mainWindow {
            mainWindow.performClose(nil)
        } else if let window = [keyManagerWindow, settingsWindow, historyWindow].compactMap({ $0 }).first(where: { $0.isVisible }) {
            window.performClose(nil)
        }
    }

    public func dismissMenuBarExtra() {
        for window in NSApp.windows {
            if let button = findStatusBarButton(in: window.contentView), button.state == .on {
                button.performClick(nil)
                return
            }
        }
        menuBarWindow?.orderOut(nil)
    }

    private func findStatusBarButton(in view: NSView?) -> NSStatusBarButton? {
        guard let view else { return nil }
        if let button = view as? NSStatusBarButton {
            return button
        }
        for subview in view.subviews {
            if let found = findStatusBarButton(in: subview) {
                return found
            }
        }
        return nil
    }

    public static let defaultWindowSize = NSSize(width: 911, height: 724)
    public static let minimumWindowSize = NSSize(width: 620, height: 530)

    public func openKeyManager(sheet: KeyManagerSheet? = nil) {
        dismissMenuBarExtra()
        NSApp.setActivationPolicy(.regular)
        if let sheet {
            AppState.shared.activeSheet = sheet
        }

        if let window = keyManagerWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let keyListView = PanelLockGate(showsEmptyState: false) {
            KeyListView().environmentObject(AppState.shared)
        }
        let hostingController = NSHostingController(rootView: keyListView)

        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: Self.defaultWindowSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = ClavisUIStrings.Common.appName
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.titlebarSeparatorStyle = .none
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isMovableByWindowBackground = true

        hostingController.view.wantsLayer = true
        hostingController.view.layer?.backgroundColor = NSColor.clear.cgColor

        window.minSize = Self.minimumWindowSize
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.keyManagerWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func openSettings() {
        openKeyManager(sheet: .settings)
    }

    public func openHistory(keyFingerprint: String? = nil) {
        AppState.shared.openHistoryPane(forKeyFingerprint: keyFingerprint)
        if let historyViewModel {
            historyViewModel.query.keyFingerprint = keyFingerprint
            historyViewModel.reload()
        }
        openKeyManager()
    }

    public func windowWillClose(_ notification: Notification) {
        if let closedWindow = notification.object as? NSWindow {
            if closedWindow === keyManagerWindow {
                closedWindow.contentViewController = nil
                keyManagerWindow = nil
            } else if closedWindow === settingsWindow {
                closedWindow.contentViewController = nil
                settingsWindow = nil
            } else if closedWindow === historyWindow {
                closedWindow.contentViewController = nil
                historyWindow = nil
                historyViewModel = nil
            }
        }
        if keyManagerWindow == nil && settingsWindow == nil && historyWindow == nil {
            NSApp.setActivationPolicy(.accessory)
            PanelLockController.shared.lock(reason: .windowsClosed)
        }
    }
}
