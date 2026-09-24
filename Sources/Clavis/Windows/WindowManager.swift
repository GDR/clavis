import SwiftUI
import AppKit

@MainActor
public class WindowManager: NSObject, NSWindowDelegate {
    public static let shared = WindowManager()
    internal var keyManagerWindow: NSWindow?
    internal var settingsWindow: NSWindow?
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

        let keyListView = KeyListView().environmentObject(AppState.shared)
        let hostingController = NSHostingController(rootView: keyListView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 880, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Clavis"
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

        let settingsView = SettingsView().environmentObject(AppState.shared)
        let hostingController = NSHostingController(rootView: settingsView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 320),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Settings"
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self

        self.settingsWindow = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func windowWillClose(_ notification: Notification) {
        if let closedWindow = notification.object as? NSWindow {
            if closedWindow === keyManagerWindow {
                keyManagerWindow = nil
            } else if closedWindow === settingsWindow {
                settingsWindow = nil
            }
        }
        if keyManagerWindow == nil && settingsWindow == nil {
            NSApp.setActivationPolicy(.accessory)
        }
    }
}
