import SwiftUI
import AppKit

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
        openKeyManager()
        AppState.shared.showingSettings = true
    }

    public func windowWillClose(_ notification: Notification) {
        keyManagerWindow = nil
        NSApp.setActivationPolicy(.accessory)
    }
}
