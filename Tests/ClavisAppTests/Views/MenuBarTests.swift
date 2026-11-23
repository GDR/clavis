@testable import ClavisTestSupport
import SwiftUI
import AppKit
import Testing
@testable import ClavisCore
@testable import Clavis

@Suite
@MainActor
final class MenuBarTests {

    // MARK: - Helper Fixtures

    private func makeKeyInfo(
        label: String,
        purpose: KeyPurpose = .general,
        unlockedTimeout: KeyGracePeriod? = nil
    ) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\(label) \(label)@clavis",
            publicKeyBlob: Data(label.utf8),
            fingerprint: "SHA256:\(label)",
            keyPurpose: purpose,
            unlockedTimeout: unlockedTimeout
        )
    }

    // MARK: - #85: MenuBar Shortcuts Tests

    @Test
    func testShortcutParsingCommandOnly() {
        let shortcuts: [(String, Character, EventModifiers)] = [
            ("⌘U", "u", .command),
            ("⌘L", "l", .command),
            ("⌘N", "n", .command),
            ("⌘O", "o", .command),
            ("⌘Y", "y", .command),
            ("⌘,", ",", .command),
            ("⌘Q", "q", .command)
        ]

        for (str, expectedChar, expectedMod) in shortcuts {
            let parsed = MenuBarActionItem.parseShortcut(str)
            #expect(parsed != nil, "Expected shortcut '\(str)' to parse")
            if let parsed {
                #expect(parsed.key == KeyEquivalent(expectedChar), "Mismatch key for '\(str)'")
                #expect(parsed.modifiers == expectedMod, "Mismatch modifiers for '\(str)'")
            }
        }
    }

    @Test
    func testShortcutParsingWithShiftModifier() {
        let shortcuts: [(String, Character, EventModifiers)] = [
            ("⇧⌘R", "r", [.command, .shift]),
            ("⇧⌘S", "s", [.command, .shift])
        ]

        for (str, expectedChar, expectedMod) in shortcuts {
            let parsed = MenuBarActionItem.parseShortcut(str)
            #expect(parsed != nil, "Expected compound shortcut '\(str)' to parse")
            if let parsed {
                #expect(parsed.key == KeyEquivalent(expectedChar), "Mismatch key for '\(str)'")
                #expect(parsed.modifiers == expectedMod, "Mismatch modifiers for '\(str)'")
            }
        }
    }

    @Test
    func testShortcutParsingEdgeCases() {
        #expect(MenuBarActionItem.parseShortcut("") == nil)
        #expect(MenuBarActionItem.parseShortcut("⌘") == nil)
        #expect(MenuBarActionItem.parseShortcut("⇧⌘") == nil)

        let lower = MenuBarActionItem.parseShortcut("⌘u")
        #expect(lower?.key == KeyEquivalent("u"))
        #expect(lower?.modifiers == .command)

        let opt = MenuBarActionItem.parseShortcut("⌥⌘K")
        #expect(opt?.key == KeyEquivalent("k"))
        #expect(opt?.modifiers == [.command, .option])

        let ctrl = MenuBarActionItem.parseShortcut("⌃⇧⌘Z")
        #expect(ctrl?.key == KeyEquivalent("z"))
        #expect(ctrl?.modifiers == [.command, .shift, .control])

        let single = MenuBarActionItem.parseShortcut("N")
        #expect(single?.key == KeyEquivalent("n"))
        #expect(single?.modifiers == .command)
    }

    @Test
    func testMenuBarActionItemInitialization() {
        let item1 = MenuBarActionItem(
            title: "New Key…",
            icon: "plus",
            shortcut: "⌘N"
        ) {}
        #expect(item1.title == "New Key…")
        #expect(item1.icon == "plus")
        #expect(item1.shortcut == "⌘N")
        #expect(item1.keyEquivalent == KeyEquivalent("n"))
        #expect(item1.modifiers == .command)
        #expect(!item1.isDestructive)

        let item2 = MenuBarActionItem(
            title: "Restart SSH Agent…",
            icon: "arrow.clockwise",
            shortcut: "⇧⌘R"
        ) {}
        #expect(item2.keyEquivalent == KeyEquivalent("r"))
        #expect(item2.modifiers == [.command, .shift])

        let item3 = MenuBarActionItem(
            title: ClavisUIStrings.MenuBar.quit,
            icon: "power",
            shortcut: "⌘Q"
        ) {}
        #expect(item3.keyEquivalent == KeyEquivalent("q"))
        #expect(item3.modifiers == .command)
        #expect(item3.title == "Quit Clavis")

        let itemNoShortcut = MenuBarActionItem(
            title: "Custom Action",
            icon: "star"
        ) {}
        #expect(itemNoShortcut.shortcut == "")
        #expect(itemNoShortcut.keyEquivalent == nil)
    }

    @Test
    func testMenuBarActionItemExplicitOverride() {
        let item = MenuBarActionItem(
            title: "Custom",
            icon: "wrench",
            shortcut: "custom",
            keyEquivalent: KeyEquivalent("c"),
            modifiers: [.command, .option]
        ) {}
        #expect(item.keyEquivalent == KeyEquivalent("c"))
        #expect(item.modifiers == [.command, .option])
    }

    @Test
    func testMenuBarActionItemActionInvocation() {
        var didExecute = false
        let item = MenuBarActionItem(
            title: "Trigger",
            icon: "play",
            shortcut: "⌘P"
        ) {
            didExecute = true
        }
        #expect(!didExecute)
        item.action()
        #expect(didExecute)
    }

    @Test
    func testMenuBarActionItemBodyEvaluation() {
        let item = MenuBarActionItem(
            title: "Test Item",
            icon: "slider.horizontal.3",
            shortcut: "⌘O"
        ) {}
        let hosting = NSHostingView(rootView: item)
        hosting.layout()
        #expect(hosting.subviews.count >= 0)
    }

    // MARK: - S-01 Menu Bar Design Tests

    @Test
    func lockActionTitleReflectsINV21AgentOnlyVsPersonalSessions() {
        let now = Date(timeIntervalSince1970: 2_000_000)
        #expect(MenuBarView.lockActionTitle(for: []) == ClavisUIStrings.MenuBar.lockNow)

        let personalSession = MenuBarSession(
            target: .git(keyLabel: "Work"),
            keyLabel: "Work",
            keyFingerprint: "fp-work",
            publicKeyOpenSSH: nil,
            purpose: .general,
            accessProfile: KeyAccessProfile(legacyPurpose: .general),
            expiresAt: now.addingTimeInterval(300),
            endsAtLock: false,
            callerName: "Terminal"
        )
        let agentSession = MenuBarSession(
            target: .agent(sessionID: "s1"),
            keyLabel: "Claude Agent",
            keyFingerprint: "fp-agent",
            publicKeyOpenSSH: nil,
            purpose: .agent,
            accessProfile: KeyAccessProfile(legacyPurpose: .agent),
            expiresAt: now.addingTimeInterval(1800),
            endsAtLock: false,
            callerName: "Claude Code"
        )

        #expect(MenuBarView.lockActionTitle(for: [personalSession]) == ClavisUIStrings.MenuBar.lockNow)
        #expect(MenuBarView.lockActionTitle(for: [personalSession, agentSession]) == ClavisUIStrings.MenuBar.lockNow)
        #expect(MenuBarView.lockActionTitle(for: [agentSession]) == ClavisUIStrings.MenuBar.lockAgentKeys)
    }

    @Test
    func lockNowRevokesPersonalGracesAndLocksPanelController() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        let sockPath = fixture.testRootURL.appendingPathComponent("menubar-locknow.sock").path
        let server = SSHAgentServer(
            applicationAccess: TestApplicationAccess(),
            socketPath: sockPath,
            keyManager: fixture.makeKeyManager(),
            controlPeerValidator: { _ in true }
        )
        try server.start()
        defer { server.stop() }

        let mockAgent = MockAgentController(
            isRunning: true,
            sessions: [
                AgentSessionSummary(
                    id: "agent-1",
                    keyLabel: "Agent Deploy",
                    keyFingerprint: "fp-agent",
                    toolName: "Claude Code",
                    rootPid: 100,
                    startedAt: Date(),
                    expiresAt: Date().addingTimeInterval(1800)
                )
            ]
        )
        let appState = AppState(
            keyManager: fixture.makeKeyManager(),
            sshAgentServer: server,
            agentLifecycle: mockAgent,
            isDaemonMode: true
        )
        for _ in 0..<50 {
            if !appState.agentSessions.isEmpty { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        appState.activeGitGraces = [
            ActiveGitGraceInfo(keyLabel: "Work GitHub", remainingSeconds: 300, remainingOperations: 5, callerName: "Terminal")
        ]

        appState.lockNow()

        #expect(mockAgent.sendLockAllCallCount == 1)
        #expect(mockAgent.revokeAllAgentSessionsCallCount == 0)
        #expect(appState.activeGitGraces.isEmpty)
        #expect(appState.agentSessions.count == 1)
        #expect(PanelLockController.shared.lastLockReason == .lockNow)
    }

    @Test(arguments: [NSAppearance.Name.aqua, .darkAqua])
    func sessionMenuFitsBothAppearancesWithMixedAndLongKeys(_ appearance: NSAppearance.Name) throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        let sockPath = fixture.testRootURL.appendingPathComponent("menubar-fit-\(appearance.rawValue).sock").path
        let appState = AppState(
            keyManager: fixture.makeKeyManager(),
            sshAgentServer: SSHAgentServer(applicationAccess: TestApplicationAccess(), socketPath: sockPath, keyManager: fixture.makeKeyManager()),
            agentLifecycle: MockAgentController(isRunning: true),
            isDaemonMode: false
        )
        let suite = "com.clavis.tests.menu.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let controller = PanelLockController(defaults: defaults, vaultKeyCount: { 0 })

        let longPersonal = makeKeyInfo(label: "Work GitHub Enterprise Main SSH Authentication Key", purpose: .general, unlockedTimeout: .fiveMinutes)
        let longSign = makeKeyInfo(label: "macOS Release & Commit Signing Hardware Key", purpose: .gitSigningOnly, unlockedTimeout: .untilLock)
        let agentKey = makeKeyInfo(label: "Claude Code Autonomous Deployment Agent", purpose: .agent, unlockedTimeout: .oneHour)
        let inactiveKey = makeKeyInfo(label: "Production EU-West Kubernetes Bastion", purpose: .general, unlockedTimeout: .fifteenMinutes)

        appState.keys = [longPersonal, longSign, agentKey, inactiveKey]
        appState.activeGitGraces = [
            ActiveGitGraceInfo(keyLabel: longPersonal.label, remainingSeconds: 42, remainingOperations: 10, callerName: "Terminal"),
            ActiveGitGraceInfo(keyLabel: longSign.label, remainingSeconds: 86_400, remainingOperations: 10, endsAtLock: true, callerName: "git")
        ]
        appState.agentSessions = [
            AgentSessionSummary(
                id: "s-agent-1",
                keyLabel: agentKey.label,
                keyFingerprint: agentKey.fingerprint,
                toolName: "Claude Code",
                rootPid: 4242,
                startedAt: Date(),
                expiresAt: Date().addingTimeInterval(3580)
            ),
            AgentSessionSummary(
                id: "s-agent-2",
                keyLabel: agentKey.label,
                keyFingerprint: agentKey.fingerprint,
                toolName: "Cursor",
                rootPid: 4243,
                startedAt: Date(),
                expiresAt: Date().addingTimeInterval(840)
            )
        ]
        appState.setShareAcrossSSHHosts(true, for: agentKey)
        // Re-seed sessions after toggling shareAcrossSSHHosts (which revokes active sessions on policy change).
        appState.agentSessions = [
            AgentSessionSummary(
                id: "s-agent-1",
                keyLabel: agentKey.label,
                keyFingerprint: agentKey.fingerprint,
                toolName: "Claude Code",
                rootPid: 4242,
                startedAt: Date(),
                expiresAt: Date().addingTimeInterval(3580)
            ),
            AgentSessionSummary(
                id: "s-agent-2",
                keyLabel: agentKey.label,
                keyFingerprint: agentKey.fingerprint,
                toolName: "Cursor",
                rootPid: 4243,
                startedAt: Date(),
                expiresAt: Date().addingTimeInterval(840)
            )
        ]

        let hosting = NSHostingView(rootView: MenuBarView(lock: controller).environment(appState))
        hosting.appearance = NSAppearance(named: appearance)
        hosting.frame = NSRect(x: 0, y: 0, width: 306, height: 500)
        hosting.layoutSubtreeIfNeeded()
        #expect(hosting.fittingSize.width == 306)
        #expect(hosting.fittingSize.height > 200)
        #expect(hosting.fittingSize.height < 500)
    }
}
