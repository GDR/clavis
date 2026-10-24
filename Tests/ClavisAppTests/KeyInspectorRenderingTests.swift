import AppKit
import SwiftUI
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor struct KeyInspectorRenderingTests {
    @Test(arguments: KeyType.allCases, [false, true])
    func inspectorRendersLongNamesAndIndependentCapabilities(type: KeyType, dark: Bool) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let agent = MockAgentController()
            let state = AppState(keyManager: manager, sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: manager), agentLifecycle: agent)
            let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: true, signature: false))
            let key = try state.generateKey(label: "Long project key name that should remain on one line", accessProfile: profile)
            #expect(state.keys.first?.effectiveAccessProfile == profile)
            let root = KeyDetailInspectorView(key: key, appState: state, onDelete: {})
                .environment(\.colorScheme, dark ? .dark : .light)
                .background(Color(nsColor: .windowBackgroundColor))
            let view = NSHostingView(rootView: root)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 650, height: 760), styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            try await Task.sleep(nanoseconds: 150_000_000)
            view.layoutSubtreeIfNeeded()
            let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            #expect(png.count > 5000)
            if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
                let directory = URL(fileURLWithPath: "/private/tmp/clavis-inspector-review")
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try png.write(to: directory.appendingPathComponent("\(type.rawValue)-\(dark ? "dark" : "light").png"))
            }
            try state.changeAccessProfile(label: key.label, type: type == .bot ? .personal : .bot)
            #expect(state.keys.first?.effectiveAccessProfile.capabilities == profile.capabilities)
        }
    }
}
