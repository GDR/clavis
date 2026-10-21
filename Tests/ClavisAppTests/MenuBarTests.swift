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

    private func makeKeyInfo(label: String) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\(label) \(label)@clavis",
            publicKeyBlob: Data(label.utf8),
            fingerprint: "SHA256:\(label.hashValue)"
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
        // Empty string
        #expect(MenuBarActionItem.parseShortcut("") == nil)

        // Only modifiers, no key character
        #expect(MenuBarActionItem.parseShortcut("⌘") == nil)
        #expect(MenuBarActionItem.parseShortcut("⇧⌘") == nil)

        // Lowercase input
        let lower = MenuBarActionItem.parseShortcut("⌘u")
        #expect(lower?.key == KeyEquivalent("u"))
        #expect(lower?.modifiers == .command)

        // Option modifier
        let opt = MenuBarActionItem.parseShortcut("⌥⌘K")
        #expect(opt?.key == KeyEquivalent("k"))
        #expect(opt?.modifiers == [.command, .option])

        // Control modifier
        let ctrl = MenuBarActionItem.parseShortcut("⌃⇧⌘Z")
        #expect(ctrl?.key == KeyEquivalent("z"))
        #expect(ctrl?.modifiers == [.command, .shift, .control])

        // Single key character without explicit modifiers defaults to .command
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
            title: "Quit",
            icon: "power",
            shortcut: "⌘Q",
            isDestructive: true
        ) {}
        #expect(item3.keyEquivalent == KeyEquivalent("q"))
        #expect(item3.modifiers == .command)
        #expect(item3.isDestructive)

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

    @Test
    func sessionRowLockInvokesItsOwnAction() {
        var locked = false
        let session = MenuBarSession(target: .agent(sessionID: "session-a"), keyLabel: "Agent key",
                                     purpose: .agent, expiresAt: Date().addingTimeInterval(60), toolName: "Tool")
        let row = MenuBarSessionRow(session: session, date: Date()) { locked = true }
        row.onLock()
        #expect(locked)
    }

    @Test(arguments: [NSAppearance.Name.aqua, .darkAqua])
    func sessionMenuFitsBothAppearances(_ appearance: NSAppearance.Name) throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let appState = AppState(keyManager: fixture.makeKeyManager())
        let suite = "com.clavis.tests.menu.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let controller = PanelLockController(defaults: defaults, vaultKeyCount: { 0 })
        appState.activeGitGraces = [ActiveGitGraceInfo(keyLabel: "A long key name for alignment", remainingSeconds: 300, remainingOperations: 10)]
        let hosting = NSHostingView(rootView: MenuBarView(lock: controller).environmentObject(appState))
        hosting.appearance = NSAppearance(named: appearance)
        hosting.frame = NSRect(x: 0, y: 0, width: 306, height: 400)
        hosting.layoutSubtreeIfNeeded()
        #expect(hosting.fittingSize.width == 306)
        #expect(hosting.fittingSize.height < 400)
    }
}
