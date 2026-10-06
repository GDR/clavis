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

    public func openKeyManager(sheet: KeyManagerSheet? = nil) {
        dismissMenuBarExtra()
        NSApp.setActivationPolicy(.regular)
        AppState.shared.activeSheet = sheet

        if let window = keyManagerWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let keyListView = PanelLockGate {
            KeyListView().environmentObject(AppState.shared)
        }
        let hostingController = NSHostingController(rootView: keyListView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 880, height: 720),
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

        window.minSize = NSSize(width: 820, height: 640)
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.keyManagerWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func openSettings() {
        dismissMenuBarExtra()
        NSApp.setActivationPolicy(.regular)

        if let window = settingsWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let settingsView = PanelLockGate {
            SettingsView().environmentObject(AppState.shared)
        }
        let hostingController = NSHostingController(rootView: settingsView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 520),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = ClavisUIStrings.Settings.windowTitle
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.settingsWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func openHistory(keyFingerprint: String? = nil) {
        dismissMenuBarExtra()
        NSApp.setActivationPolicy(.regular)

        if let window = historyWindow {
            if let keyFingerprint {
                historyViewModel?.query.keyFingerprint = keyFingerprint
                historyViewModel?.reload()
            }
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let viewModel = HistoryViewModel(initialKeyFingerprint: keyFingerprint)
        self.historyViewModel = viewModel
        let historyView = PanelLockGate {
            HistoryView(viewModel: viewModel)
        }
        let hostingController = NSHostingController(rootView: historyView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = ClavisUIStrings.History.windowTitle
        window.minSize = NSSize(width: 750, height: 500)
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.historyWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func windowWillClose(_ notification: Notification) {
        if let closedWindow = notification.object as? NSWindow {
            if closedWindow === keyManagerWindow {
                keyManagerWindow = nil
            } else if closedWindow === settingsWindow {
                settingsWindow = nil
            } else if closedWindow === historyWindow {
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
