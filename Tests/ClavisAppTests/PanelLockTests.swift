@testable import ClavisTestSupport
import Testing
import SwiftUI
import AppKit
@testable import Clavis
@testable import ClavisCore

@Suite @MainActor
final class PanelLockTests {
    private let suiteName: String
    nonisolated(unsafe) private let testDefaults: UserDefaults

    init() {
        let suite = "com.clavis.tests.panelLockTests.\(UUID().uuidString)"
        self.suiteName = suite
        self.testDefaults = UserDefaults(suiteName: suite)!
    }

    deinit {
        testDefaults.removePersistentDomain(forName: suiteName)
    }

    // MARK: - #87: Empty-Vault Lock Bypass

    @Test func test_emptyVault_bypassesLock_whenNoCustomPIN() {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            vaultKeyCount: { 0 }
        )

        // Fresh install with 0 keys and default mode (password/biometry, no PIN)
        #expect(!controller.currentMode.requiresPIN)
        #expect(controller.shouldBypassLock, "Lock should be bypassed when vault has 0 keys and no PIN is set")
        #expect(controller.isBypassed)
        #expect(!controller.isEffectivelyLocked)
        #expect(controller.isLocked, "Controller state remains locked internally, but gate is bypassed")

        // PanelLockGate with showsEmptyState=false should directly build content without requiring unlock
        var buildCount = 0
        let gate = PanelLockGate(lock: controller, showsEmptyState: false) {
            buildCount += 1
            return Text("Unlocked Content")
        }

        _ = gate.body
        #expect(buildCount >= 1, "Content must be built when empty vault bypass is active")
    }

    @Test func test_emptyVault_surfacesOnboardingView_whenShowsEmptyStateTrue() {
        let controller = PanelLockController(
            defaults: testDefaults,
            vaultKeyCount: { 0 }
        )

        #expect(controller.shouldBypassLock)

        let gate = PanelLockGate(lock: controller, showsEmptyState: true) {
            Text("Inner Content")
        }

        #expect(gate.showsEmptyState)
        _ = gate.body
    }

    @Test func test_vaultWithKeys_doesNotBypassLock() {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            vaultKeyCount: { 1 }
        )

        #expect(!controller.shouldBypassLock, "Lock must not be bypassed when vault has keys")
        #expect(!controller.isBypassed)
        #expect(controller.isEffectivelyLocked)
        #expect(controller.isLocked)

        var buildCount = 0
        let gate = PanelLockGate(lock: controller, showsEmptyState: false) {
            buildCount += 1
            return Text("Protected Content")
        }

        _ = gate.body
        #expect(buildCount == 0, "Protected content must NOT be built when vault has keys and lock is active")
    }

    @Test func test_emptyVault_withCustomPIN_doesNotBypassLock() {
        let fakeAuth = FakePanelAuthenticator()
        let keyring = SoftwareAuditKeyring(requireContext: false)
        _ = try? keyring.rotate(mode: .biometryOrPIN)

        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            keyring: keyring,
            vaultKeyCount: { 0 }
        )

        #expect(controller.currentMode.requiresPIN, "Keyring mode requires PIN")
        #expect(!controller.shouldBypassLock, "Lock must NOT be bypassed when a custom PIN is configured")
        #expect(!controller.isBypassed)
        #expect(controller.isEffectivelyLocked)
        #expect(controller.isLocked)

        var buildCount = 0
        let gate = PanelLockGate(lock: controller, showsEmptyState: false) {
            buildCount += 1
            return Text("Protected Content")
        }

        _ = gate.body
        #expect(buildCount == 0, "Protected content must NOT be built when custom PIN is configured")
    }

    @Test func test_dynamicallyUpdatingKeyCount_updatesBypassState() {
        var keysInVault = 0
        let controller = PanelLockController(
            defaults: testDefaults,
            vaultKeyCount: { keysInVault }
        )

        #expect(controller.shouldBypassLock)
        #expect(controller.isBypassed)

        // Key is added to vault
        keysInVault = 1
        #expect(!controller.shouldBypassLock)
        #expect(!controller.isBypassed)
        #expect(controller.isEffectivelyLocked)

        // Setter method also works dynamically
        controller.setVaultKeyCountProvider { 0 }
        #expect(controller.shouldBypassLock)
    }

    // MARK: - #87: Onboarding Snippets & Copy Actions

    @Test func test_emptyVaultOnboardingView_snippetsAndCopyActions() {
        let onboarding = EmptyVaultOnboardingView()

        #expect(EmptyVaultOnboardingView.sshAuthSockCommand == "export SSH_AUTH_SOCK=~/.ssh/clavis.sock")
        #expect(EmptyVaultOnboardingView.identityAgentConfig.contains("IdentityAgent ~/.ssh/clavis.sock"))
        #expect(EmptyVaultOnboardingView.gitSigningCommand == "git config --global gpg.format ssh")

        // Test copy to clipboard
        onboarding.copyToClipboard(EmptyVaultOnboardingView.sshAuthSockCommand, snippetId: "sock")
        #expect(NSPasteboard.general.string(forType: .string) == "export SSH_AUTH_SOCK=~/.ssh/clavis.sock")

        onboarding.copyToClipboard(EmptyVaultOnboardingView.identityAgentConfig, snippetId: "agent")
        #expect(NSPasteboard.general.string(forType: .string) == EmptyVaultOnboardingView.identityAgentConfig)

        onboarding.copyToClipboard(EmptyVaultOnboardingView.gitSigningCommand, snippetId: "git")
        #expect(NSPasteboard.general.string(forType: .string) == "git config --global gpg.format ssh")
    }

    // MARK: - #93: Lock Clarity

    @Test func test_lockedPlaceholderView_clarificationNotice() {
        let notice = LockedPlaceholderView.clarificationNotice
        #expect(notice.contains("Locking the control panel does not disable background SSH signing"))
        #expect(notice.contains("SSH") && notice.contains("Git"))

        let placeholder = LockedPlaceholderView()
        _ = placeholder.body
    }

    // MARK: - #99: PIN Masking & Default Action

    @Test func test_pinEntryView_masksDigitsWithBullets() {
        #expect(PinEntryView.maskPIN("") == "")
        #expect(PinEntryView.maskPIN("1") == "•")
        #expect(PinEntryView.maskPIN("123") == "•••")
        #expect(PinEntryView.maskPIN("123456") == "••••••")
        #expect(PinEntryView.maskPIN("secret_pin_99") == "•••••••••••••")

        let pinView = PinEntryView()
        #expect(pinView.maskedPin == "")
    }

    @Test func test_panelLockGate_rendersViews() {
        let controller = PanelLockController(defaults: testDefaults)
        let placeholder = LockedPlaceholderView(lock: controller)
        _ = placeholder.body

        let pinView = PinEntryView(lock: controller)
        _ = pinView.body

        let onboardingView = EmptyVaultOnboardingView(lock: controller)
        _ = onboardingView.body
    }

    @Test func test_idleLock_doesNotAutoPromptAuthentication() async {
        let fakeAuth = FakePanelAuthenticator()
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            now: { currentTime },
            vaultKeyCount: { 1 }
        )

        await controller.unlock()
        #expect(fakeAuth.authCount == 1)
        #expect(!controller.isEffectivelyLocked)

        let gate = PanelLockGate(lock: controller) {
            Text("Protected Content")
        }
        let hosting = NSHostingView(rootView: gate)
        hosting.frame = NSRect(x: 0, y: 0, width: 400, height: 300)
        hosting.layout()

        // Advance past idleMinutes so tick() locks the controller
        currentTime += Double(controller.idleMinutes * 60 + 1)
        controller.tick()
        #expect(controller.isEffectivelyLocked)

        hosting.layout()
        try? await Task.sleep(nanoseconds: 20_000_000)

        #expect(fakeAuth.authCount == 1, "Locking on idle must not automatically re-prompt authentication")
        #expect(controller.isEffectivelyLocked)
    }

    @Test func test_windowWillClose_clearsContentViewController() {
        let wm = WindowManager()
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 200),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.contentViewController = NSHostingController(rootView: Text("Test"))
        wm.keyManagerWindow = window

        wm.windowWillClose(Notification(name: NSWindow.willCloseNotification, object: window))

        #expect(wm.keyManagerWindow == nil)
        #expect(window.contentViewController == nil)
    }

    @Test func test_lockedPlaceholderAndWindowDimensions() {
        #expect(LockedPlaceholderView.subtitleText == "Unlock to manage your keys and security settings.")
        #expect(LockedPlaceholderView.bottomContinuationNotice == "SSH and Git signing continue while the panel is locked.")
        #expect(WindowManager.defaultWindowSize == NSSize(width: 958, height: 724))
        #expect(WindowManager.minimumWindowSize == NSSize(width: 713, height: 610))

        let button = CircularGlassIconButton(
            icon: "lock",
            size: 33,
            iconSize: 14,
            isActive: false,
            helpText: "Lock control panel (⌘L)",
            action: {}
        )
        _ = button.body
    }

    @Test func test_lockedWindow_autoPromptsTouchIDOnOpen() async {
        let fakeAuth = FakePanelAuthenticator()
        fakeAuth.shouldFail = true
        var currentTime = Date(timeIntervalSince1970: 1000)
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            now: { currentTime },
            vaultKeyCount: { 1 }
        )

        #expect(controller.isEffectivelyLocked)

        let gate = PanelLockGate(lock: controller, showsEmptyState: false) {
            Text("Protected Key List")
        }
        let hosting = NSHostingView(rootView: gate)
        hosting.frame = NSRect(x: 0, y: 0, width: 911, height: 724)
        hosting.layout()
        for _ in 0..<20 {
            if fakeAuth.authCount >= 1 && !controller.isUnlocking { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(fakeAuth.authCount == 1, "Opening Clavis window while locked must immediately prompt for Touch ID")
        #expect(controller.isEffectivelyLocked, "Cancelling the Touch ID prompt keeps the window on the locked screen")

        // Immediate window focus event after prompt dismissal must not re-trigger an infinite loop
        await controller.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(fakeAuth.authCount == 1)

        // Focusing the locked window again after cooldown prompts Touch ID and unlocks when approved
        currentTime += 2.0
        fakeAuth.shouldFail = false
        await controller.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true)
        #expect(fakeAuth.authCount == 2)
        #expect(!controller.isEffectivelyLocked)
    }

    @Test func test_liquidGlassModifiersAndContainer_renderCleanly() {
        let container = AdaptiveGlassEffectContainer(spacing: 8) {
            Text("Button A").liquidGlassControl(cornerRadius: 8, isFocused: true, isSelected: true)
            Text("Button B").liquidGlassCapsuleControl(isFocused: false)
            Button("Action") {}.liquidGlassButton(prominent: true)
            Button("Secondary") {}.liquidGlassButton(prominent: false)
        }
        let hosting = NSHostingView(rootView: container)
        hosting.frame = NSRect(x: 0, y: 0, width: 320, height: 80)
        hosting.layout()
        #expect(hosting.bounds.width == 320)
    }

    @Test func test_settingsView_isAlreadyUnlockedWhenClavisUnlocked_withoutPromptingTouchID() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let appState = AppState(keyManager: fixture.makeKeyManager())
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            vaultKeyCount: { 1 }
        )

        // 1. Before Clavis is unlocked, Settings is locked and does not auto-prompt
        let lockedSettings = SettingsView(lock: controller)
        #expect(!lockedSettings.isUnlocked)
        #expect(fakeAuth.authCount == 0)

        // 2. Unlock Clavis once
        await controller.unlock()
        #expect(fakeAuth.authCount == 1)
        #expect(!controller.isEffectivelyLocked)

        //Even an already-created SettingsView immediately reflects unlocked state
        #expect(lockedSettings.isUnlocked)

        // 3. Opening Settings when Clavis is already unlocked must be unlocked immediately with 0 extra Touch ID prompts
        let unlockedSettings = SettingsView(lock: controller)
        #expect(unlockedSettings.isUnlocked)
        let hosting = NSHostingView(rootView: unlockedSettings.environmentObject(appState))
        hosting.frame = NSRect(x: 0, y: 0, width: 480, height: 600)
        hosting.layout()
        try? await Task.sleep(nanoseconds: 20_000_000)

        #expect(fakeAuth.authCount == 1, "Settings must not prompt for Touch ID again when Clavis is already unlocked")
    }

    @Test func test_lockedPlaceholderView_macLoginPasswordUnlock() async {
        let fakeAuth = FakePanelAuthenticator()
        let controller = PanelLockController(
            defaults: testDefaults,
            authenticator: fakeAuth,
            vaultKeyCount: { 1 },
            loginPasswordVerifier: { candidate in
                candidate == "correct-mac-password"
            }
        )

        #expect(controller.isEffectivelyLocked)
        #expect(LockedPlaceholderView.passwordFieldLabel == "Mac login password")
        #expect(LockedPlaceholderView.passwordFieldPlaceholder == "Enter password")

        // Wrong password keeps panel locked
        let wrongResult = await controller.unlockWithLoginPassword("wrong-password")
        #expect(!wrongResult)
        #expect(controller.isEffectivelyLocked)
        #expect(fakeAuth.authCount == 0)

        // Empty password rejected without calling verifier
        let emptyResult = await controller.unlockWithLoginPassword("")
        #expect(!emptyResult)
        #expect(controller.isEffectivelyLocked)

        // Correct Mac login password unlocks panel without prompting Touch ID
        let okResult = await controller.unlockWithLoginPassword("correct-mac-password")
        #expect(okResult)
        #expect(!controller.isEffectivelyLocked)
        #expect(fakeAuth.authCount == 0)
    }
}
