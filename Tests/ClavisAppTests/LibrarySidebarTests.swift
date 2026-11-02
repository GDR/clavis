import AppKit
import SwiftUI
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite @MainActor
struct LibrarySidebarTests {
    @Test func legacySigningOnlyDoesNotAdvertiseSSH() {
        let presentation = LibraryKeyPresentation(purpose: .gitSigningOnly)
        #expect(presentation.typeTitle == "Personal")
        #expect(presentation.capabilities == ["SSHSIG"])
    }

    @Test func generalAndBotCapabilitiesRemainDistinctFromType() {
        let personal = LibraryKeyPresentation(purpose: .general)
        let bot = LibraryKeyPresentation(purpose: .agent)
        #expect(personal.typeTitle == "Personal")
        #expect(bot.typeTitle == "Bot")
        #expect(personal.capabilities == ["SSH", "SSHSIG"])
        #expect(bot.capabilities == ["SSH"])
        #expect(bot.accessibilitySummary == "Bot, SSH")
        #expect(personal.tileSymbol == "person.fill")
        #expect(bot.tileSymbol == "cpu")
        #expect(personal.purposeSummary == "SSH & Git signing")
        #expect(bot.purposeSummary == "SSH authentication")
        #expect(!personal.isDisabled)
        #expect(!bot.isDisabled)
    }

    @Test func purposeSummaryAndDisabledStateReflectCapabilities() {
        let gitOnly = LibraryKeyPresentation(
            profile: KeyAccessProfile(type: .personal, capabilities: KeyCapabilities(ssh: false, signature: true))
        )
        #expect(gitOnly.purposeSummary == "Git signing")
        #expect(!gitOnly.isDisabled)

        let disabled = LibraryKeyPresentation(
            profile: KeyAccessProfile(type: .bot, capabilities: KeyCapabilities(ssh: false, signature: false))
        )
        #expect(disabled.purposeSummary == "Disabled")
        #expect(disabled.isDisabled)
    }

    @Test func agentStatusFooterLabelsAndActions() {
        let activeFooter = LibraryAgentStatus(active: true, requestState: .accepting)
        #expect(activeFooter.statusLabel == "Clavis active")

        let pausedFooter = LibraryAgentStatus(active: true, requestState: .paused)
        #expect(pausedFooter.statusLabel == "Clavis paused")

        let offlineFooter = LibraryAgentStatus(active: false, requestState: .accepting)
        #expect(offlineFooter.statusLabel == "Agent offline")

        var settingsOpened = false
        let interactiveFooter = LibraryAgentStatus(
            active: true,
            requestState: .accepting,
            onTogglePause: {},
            onLock: {},
            onOpenSettings: { settingsOpened = true }
        )
        _ = interactiveFooter.body
        interactiveFooter.onOpenSettings?()
        #expect(settingsOpened)
    }

    @Test func nativeSearchUpdatesBindingAndCancelClearsBeforeBlurring() {
        var value = "github"
        var focus = true
        let view = LibrarySearchField(
            text: Binding(get: { value }, set: { value = $0 }),
            focused: Binding(get: { focus }, set: { focus = $0 })
        )
        let delegate = view.makeCoordinator()
        let field = NSSearchField()
        field.stringValue = "production"
        delegate.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: field))
        #expect(value == "production")
        let cancel = #selector(NSResponder.cancelOperation(_:))
        #expect(delegate.control(field, textView: NSTextView(), doCommandBy: cancel))
        #expect(value.isEmpty)
        #expect(focus)
        #expect(delegate.control(field, textView: NSTextView(), doCommandBy: cancel))
        #expect(!focus)
    }
}
