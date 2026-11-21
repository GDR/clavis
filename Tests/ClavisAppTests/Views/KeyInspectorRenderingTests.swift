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
            agent.stubbedApplicationRegistry = ApplicationRegistrySnapshot(applications: [
                try RegisteredApplication(
                    identity: .init(kind: .designatedRequirement, value: "com.anthropic.claudecode"),
                    name: "Claude Code",
                    path: "/Applications/Claude Code.app",
                    classification: .bot
                ),
                try RegisteredApplication(
                    identity: .init(kind: .designatedRequirement, value: "com.google.antigravity"),
                    name: "Antigravity",
                    path: "/Applications/Antigravity.app",
                    classification: .block
                )
            ])
            let state = AppState(keyManager: manager, sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: manager), agentLifecycle: agent)
            let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: true, signature: false))
            let key = try state.generateKey(label: "Long project key name that should remain on one line", accessProfile: profile)
            #expect(state.keys.first?.effectiveAccessProfile == profile)
            let root = KeyDetailInspectorView(key: key, appState: state, onDelete: {}, applicationAgent: agent)
                .environment(\.colorScheme, dark ? .dark : .light)
                .background(Color(nsColor: .windowBackgroundColor))
            let view = NSHostingView(rootView: root)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 650, height: 760), styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            view.layoutSubtreeIfNeeded()
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

    @Test
    func unlockedTimeoutAndPolicyMenusHaveFullHitTargets() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let agent = MockAgentController()
            let state = AppState(
                keyManager: manager,
                sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), keyManager: manager),
                agentLifecycle: agent
            )
            let profile = KeyAccessProfile(type: .personal, capabilities: .init(ssh: true, signature: true))
            let key = try state.generateKey(label: "github-test", accessProfile: profile)

            let root = KeyDetailInspectorView(key: key, appState: state, onDelete: {}, applicationAgent: agent)
                .background(Color(nsColor: .windowBackgroundColor))
            let view = NSHostingView(rootView: root)
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 650, height: 760),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.contentView = view
            window.orderFront(nil)
            defer { window.orderOut(nil) }
            view.layoutSubtreeIfNeeded()
            try await Task.sleep(nanoseconds: 150_000_000)
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

            let interactiveProxies = allViews.filter { subview in
                let className = String(describing: type(of: subview))
                return (className.contains("KeyViewProxy") || className.contains("_FocusRingView"))
                    && subview.frame.width >= 40
                    && subview.frame.height >= 16
            }
            #expect(interactiveProxies.count >= 2)

            state.setGracePeriod(.fifteenMinutes, for: key)
            #expect(state.gracePeriod(for: key) == .fifteenMinutes)
            state.setGracePeriod(.always, for: key)
            #expect(state.gracePeriod(for: key) == .always)
        }
    }
}
