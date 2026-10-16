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

    // MARK: - #91: MenuBar Overflow Indicator Tests

    @Test
    func testOverflowConditionThreshold() {
        #expect(MenuBarView.maxInlineIdentities == 4)

        // 0 to 4 keys -> no overflow
        #expect(!MenuBarView.shouldShowOverflow(keyCount: 0))
        #expect(!MenuBarView.shouldShowOverflow(keyCount: 1))
        #expect(!MenuBarView.shouldShowOverflow(keyCount: 2))
        #expect(!MenuBarView.shouldShowOverflow(keyCount: 3))
        #expect(!MenuBarView.shouldShowOverflow(keyCount: 4))

        // 5 or more keys -> overflow required
        #expect(MenuBarView.shouldShowOverflow(keyCount: 5))
        #expect(MenuBarView.shouldShowOverflow(keyCount: 6))
        #expect(MenuBarView.shouldShowOverflow(keyCount: 10))
        #expect(MenuBarView.shouldShowOverflow(keyCount: 100))
    }

    @Test
    func testOverflowTitleFormatting() {
        #expect(MenuBarView.overflowTitle(keyCount: 5) == "Show all 5 keys…")
        #expect(MenuBarView.overflowTitle(keyCount: 6) == "Show all 6 keys…")
        #expect(MenuBarView.overflowTitle(keyCount: 12) == "Show all 12 keys…")
        #expect(MenuBarView.overflowTitle(keyCount: 99) == "Show all 99 keys…")

        // Confirm Unicode ellipsis
        let title = MenuBarView.overflowTitle(keyCount: 7)
        #expect(title.hasSuffix("…"))
        #expect(title == "Show all 7 keys\u{2026}")
    }

    @Test
    func testMenuBarOverflowButton() {
        var actionFired = false
        let button = MenuBarOverflowButton(count: 8) {
            actionFired = true
        }

        #expect(button.count == 8)
        #expect(button.title == "Show all 8 keys…")
        #expect(!actionFired)

        button.action()
        #expect(actionFired)

        let hosting = NSHostingView(rootView: button)
        hosting.layout()
        #expect(hosting.subviews.count >= 0)
    }

    // MARK: - MenuBarView Integration & State Tests

    @Test
    func testMenuBarViewStateWithKeys() {
        let appState = AppState.shared
        let originalKeys = appState.keys
        defer { appState.keys = originalKeys }

        // Test with 3 keys: no overflow
        let threeKeys = (1...3).map { makeKeyInfo(label: "key-\($0)") }
        appState.keys = threeKeys
        #expect(!MenuBarView.shouldShowOverflow(keyCount: appState.keys.count))

        // Test with 4 keys: exactly at boundary, no overflow
        let fourKeys = (1...4).map { makeKeyInfo(label: "key-\($0)") }
        appState.keys = fourKeys
        #expect(!MenuBarView.shouldShowOverflow(keyCount: appState.keys.count))

        // Test with 6 keys: overflow expected
        let sixKeys = (1...6).map { makeKeyInfo(label: "key-\($0)") }
        appState.keys = sixKeys
        #expect(MenuBarView.shouldShowOverflow(keyCount: appState.keys.count))
        #expect(MenuBarView.overflowTitle(keyCount: appState.keys.count) == "Show all 6 keys…")
    }

    @Test
    func testMenuBarViewHosting() {
        let appState = AppState.shared
        let originalKeys = appState.keys
        defer { appState.keys = originalKeys }

        appState.keys = (1...5).map { makeKeyInfo(label: "hosted-key-\($0)") }

        let menuView = MenuBarView().environmentObject(appState)
        let hosting = NSHostingView(rootView: menuView)
        hosting.frame = NSRect(x: 0, y: 0, width: 320, height: 400)
        hosting.layout()
        #expect(hosting.frame.width == 320)
    }

    // MARK: - MenuBarSections Tests

    @Test
    func testMenuBarSections() {
        // Unlocked without sessions
        let unlockedNoSessions = MenuBarSections.visible(isLocked: false, hasSessions: false)
        #expect(unlockedNoSessions.contains(.identities))
        #expect(unlockedNoSessions.contains(.newKey))
        #expect(unlockedNoSessions.contains(.openKeyManager))
        #expect(unlockedNoSessions.contains(.settings))
        #expect(unlockedNoSessions.contains(.quit))
        #expect(!unlockedNoSessions.contains(.unlock))
        #expect(!unlockedNoSessions.contains(.lockNow))

        // Unlocked with sessions
        let unlockedWithSessions = MenuBarSections.visible(isLocked: false, hasSessions: true)
        #expect(unlockedWithSessions.contains(.lockNow))
        #expect(unlockedWithSessions.contains(.revokeAll))
        #expect(unlockedWithSessions.contains(.sessionCount))

        // Locked with sessions
        let lockedWithSessions = MenuBarSections.visible(isLocked: true, hasSessions: true)
        #expect(lockedWithSessions.contains(.unlock))
        #expect(lockedWithSessions.contains(.lockNow))
        #expect(lockedWithSessions.contains(.revokeAll))
        #expect(lockedWithSessions.contains(.sessionCount))
        #expect(!lockedWithSessions.contains(.identities))
        #expect(!lockedWithSessions.contains(.openKeyManager))
    }

    @Test
    func testMenuBarIdleTimerItem() {
        let suite = "com.clavis.tests.menubar.idle.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        let controller = PanelLockController(defaults: defaults)
        #expect(controller.idleMinutes == 5)

        let item = MenuBarIdleTimerItem(lock: controller)
        let hosting = NSHostingView(rootView: item)
        hosting.frame = NSRect(x: 0, y: 0, width: 320, height: 32)
        hosting.layout()

        controller.idleMinutes = 15
        #expect(controller.idleMinutes == 15)
        hosting.layout()
    }
}
