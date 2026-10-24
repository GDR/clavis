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
