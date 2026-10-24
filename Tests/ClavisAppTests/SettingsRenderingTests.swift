import AppKit
import SwiftUI
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor struct SettingsRenderingTests {
    @Test(arguments: ["General", "Bots"], [false, true])
    func modalRendersWithFloatingNavigation(tab: String, dark: Bool) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let suite = "clavis.settings.render.\(UUID().uuidString)"
            let defaults = try #require(UserDefaults(suiteName: suite))
            defer { defaults.removePersistentDomain(forName: suite) }
            defaults.set(tab, forKey: "clavis.settings.tab")
            let agent = MockAgentController()
            agent.stubbedApplicationRegistry = ApplicationRegistrySnapshot(applications: try [
                "Claude Code", "Codex", "Antigravity", "OpenCode"
            ].map { name in
                RegisteredApplication(identity: try .init(kind: .designatedRequirement, value: name), name: name, path: "/Applications/\(name).app", classification: .bot)
            })
            let lock = PanelLockController(defaults: defaults, authenticator: FakePanelAuthenticator(), keyring: nil, recorder: InMemoryAuditRecorder(), vaultKeyCount: { 1 })
            let manager = fixture.makeKeyManager()
            let state = AppState(keyManager: manager, sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: manager), agentLifecycle: agent)
            let root = SettingsView(lock: lock, isSettingsAuthenticated: true, applicationAgent: agent)
                .environmentObject(state)
                .defaultAppStorage(defaults)
                .environment(\.colorScheme, dark ? .dark : .light)
            let view = NSHostingView(rootView: root)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 580, height: 680), styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            try await Task.sleep(nanoseconds: 150_000_000)
            view.layoutSubtreeIfNeeded()
            let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            #expect(view.bounds.width == 580)
            #expect(view.bounds.height == 680)
            #expect(png.count > 5_000)
            if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
                let directory = URL(fileURLWithPath: "/private/tmp/clavis-settings-review")
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try png.write(to: directory.appendingPathComponent("\(tab.lowercased())-\(dark ? "dark" : "light").png"))
            }
        }
    }
}
