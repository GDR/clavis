import AppKit
import SwiftUI
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite(.enabled(if: LiveUITestGate.isEnabled, LiveUITestGate.reason)) @MainActor struct CreateKeyRenderingTests {
    /// Compact FormStyle.grouped sheet (S-04, revised D-39): 460pt wide, plain title,
    /// three grouped cards with single-line footnotes, single "?" reference trigger, capsule footer.
    @Test(arguments: [0, 1])
    func createKeySheetRenders(appearance: Int) async throws {
        let dark = appearance & 1 != 0
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let state = AppState(keyManager: manager)
            let root = CreateKeySheet(appState: state)
                .environment(\.colorScheme, dark ? .dark : .light)
            let view = NSHostingView(rootView: root)
            view.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 560), styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            try await Task.sleep(nanoseconds: 200_000_000)
            view.layoutSubtreeIfNeeded()
            #expect(view.bounds.width == 460)
            let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            #expect(png.count > 5_000)
            if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
                let path = ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW_DIR"] ?? "/private/tmp/clavis-create-key-review"
                let directory = URL(fileURLWithPath: path)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try png.write(to: directory.appendingPathComponent("create-key-\(dark ? "dark" : "light").png"))
            }
        }
    }

    /// Reference help popover renders without crashing.
    @Test
    func referencePopoverRenders() async throws {
        let root = CreateKeyReferencePopover(onClose: {})
        let view = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 380, height: 340), styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = view
        window.orderFront(nil)
        defer { window.orderOut(nil) }
        try await Task.sleep(nanoseconds: 80_000_000)
        view.layoutSubtreeIfNeeded()
        let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let png = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(png.count > 1_000)
        if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
            let path = ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW_DIR"] ?? "/private/tmp/clavis-create-key-review"
            let directory = URL(fileURLWithPath: path)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try png.write(to: directory.appendingPathComponent("create-key-reference.png"))
        }
    }

    @Test
    func popupControlsSpanFullPillBounds() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let state = AppState(keyManager: manager)
            let root = CreateKeySheet(appState: state)
            let view = NSHostingView(rootView: root)
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 460, height: 560),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            try await Task.sleep(nanoseconds: 200_000_000)
            view.layoutSubtreeIfNeeded()

            @MainActor func descendants(of rootView: NSView) -> [NSView] {
                var result = [rootView]
                for subview in rootView.subviews {
                    result.append(contentsOf: descendants(of: subview))
                }
                return result
            }

            let allViews = descendants(of: view)
            let collapsedPopups = allViews.filter { subview in
                String(describing: type(of: subview)).contains("SwiftUIPopupButton") && subview.frame.width < 20
            }
            #expect(collapsedPopups.isEmpty)

            let pillProxies = allViews.filter { subview in
                let className = String(describing: type(of: subview))
                return (className.contains("KeyViewProxy") || className.contains("_FocusRingView"))
                    && subview.frame.width >= 160
                    && subview.frame.height >= 24
            }
            #expect(pillProxies.count >= 2)
        }
    }
}
