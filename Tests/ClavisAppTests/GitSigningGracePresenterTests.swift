import Foundation
import Testing
import CoreFoundation
@testable import ClavisCore
@testable import Clavis

@Suite
struct GitSigningGracePresenterTests {

    @Test func testCFUserNotificationPresenterConformsToProtocol() {
        let presenter: any GitSigningGracePresenter = CFUserNotificationGitSigningGracePresenter(defaultTimeout: 15.0)
        #expect((presenter as? CFUserNotificationGitSigningGracePresenter)?.defaultTimeout == 15.0)

        // Verify DefaultGitSigningGracePresenter typealias
        let defaultPresenter = DefaultGitSigningGracePresenter(defaultTimeout: 25.0)
        #expect(defaultPresenter.defaultTimeout == 25.0)
        #expect(type(of: defaultPresenter) == CFUserNotificationGitSigningGracePresenter.self)
    }

    @Test func testClosurePresenterRoutesPrompt() {
        var capturedKeyLabel: String?
        var capturedClientDesc: String?
        let presenter = ClosureGitSigningGracePresenter { keyLabel, clientDesc in
            capturedKeyLabel = keyLabel
            capturedClientDesc = clientDesc
            return .grantFiveMinutes
        }

        let choice = presenter.prompt(keyLabel: "test-key-id", clientDesc: "git (pid 4567)")
        #expect(choice == .grantFiveMinutes)
        #expect(capturedKeyLabel == "test-key-id")
        #expect(capturedClientDesc == "git (pid 4567)")
    }

    @Test func testGitSigningGraceManager_setPresenter_usesConfiguredPresenter() {
        let initialPresenter = ClosureGitSigningGracePresenter { _, _ in .singleShot }
        let manager = GitSigningGraceManager(observeSystemEvents: false, presenter: initialPresenter)

        let initialChoice = manager.prompt(keyLabel: "k1", clientDesc: "d1")
        #expect(initialChoice == .singleShot)

        let secondaryPresenter = ClosureGitSigningGracePresenter { _, _ in .grantFiveMinutes }
        manager.setPresenter(secondaryPresenter)

        let secondaryChoice = manager.prompt(keyLabel: "k1", clientDesc: "d1")
        #expect(secondaryChoice == .grantFiveMinutes)
    }

    @Test func testAppKitGitSigningGracePresenter() {
        let presenter = AppKitGitSigningGracePresenter(defaultTimeout: 42.0)
        #expect(presenter.defaultTimeout == 42.0)
        let anyPresenter: any GitSigningGracePresenter = presenter
        _ = anyPresenter
    }

    @Test func testChoiceForResponseFlagsMapping() {
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse)) ==
            .singleShot
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationAlternateResponse)) ==
            .cancel
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationOtherResponse)) ==
            .grantFiveMinutes
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationCancelResponse)) ==
            .cancel
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: 0xFF) ==
            .cancel
        )
    }

    @Test func testPromptWithHeadlessSessionFallback() {
        let previousProvider = GitSigningPrompt.sessionCheckProvider
        defer {
            GitSigningPrompt.sessionCheckProvider = previousProvider
        }

        GitSigningPrompt.sessionCheckProvider = { false }

        let presenter = CFUserNotificationGitSigningGracePresenter()
        let result = presenter.prompt(keyLabel: "headless-key", clientDesc: "headless-client")
        #expect(result == .singleShot, "Headless non-GUI sessions must safely fall back to single-shot without modal dialog")
    }
}
