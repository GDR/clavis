import XCTest
import CoreFoundation
@testable import ClavisCore
@testable import Clavis

final class GitSigningGracePresenterTests: ClavisBaseTestCase {

    func testCFUserNotificationPresenterConformsToProtocol() {
        let presenter: any GitSigningGracePresenter = CFUserNotificationGitSigningGracePresenter(defaultTimeout: 15.0)
        XCTAssertNotNil(presenter)
        XCTAssertEqual((presenter as? CFUserNotificationGitSigningGracePresenter)?.defaultTimeout, 15.0)

        // Verify DefaultGitSigningGracePresenter typealias
        let defaultPresenter = DefaultGitSigningGracePresenter(defaultTimeout: 25.0)
        XCTAssertEqual(defaultPresenter.defaultTimeout, 25.0)
        XCTAssertTrue(type(of: defaultPresenter) == CFUserNotificationGitSigningGracePresenter.self)
    }

    func testClosurePresenterRoutesPrompt() {
        var capturedKeyLabel: String?
        var capturedClientDesc: String?
        let presenter = ClosureGitSigningGracePresenter { keyLabel, clientDesc in
            capturedKeyLabel = keyLabel
            capturedClientDesc = clientDesc
            return .grantFiveMinutes
        }

        let choice = presenter.prompt(keyLabel: "test-key-id", clientDesc: "git (pid 4567)")
        XCTAssertEqual(choice, .grantFiveMinutes)
        XCTAssertEqual(capturedKeyLabel, "test-key-id")
        XCTAssertEqual(capturedClientDesc, "git (pid 4567)")
    }

    func testGitSigningGraceManager_setPresenter_usesConfiguredPresenter() {
        let initialPresenter = ClosureGitSigningGracePresenter { _, _ in .singleShot }
        let manager = GitSigningGraceManager(observeSystemEvents: false, presenter: initialPresenter)

        let initialChoice = manager.prompt(keyLabel: "k1", clientDesc: "d1")
        XCTAssertEqual(initialChoice, .singleShot)

        let secondaryPresenter = ClosureGitSigningGracePresenter { _, _ in .grantFiveMinutes }
        manager.setPresenter(secondaryPresenter)

        let secondaryChoice = manager.prompt(keyLabel: "k1", clientDesc: "d1")
        XCTAssertEqual(secondaryChoice, .grantFiveMinutes)
    }

    func testAppKitGitSigningGracePresenter() {
        let presenter = AppKitGitSigningGracePresenter(defaultTimeout: 42.0)
        XCTAssertEqual(presenter.defaultTimeout, 42.0)
        let anyPresenter: any GitSigningGracePresenter = presenter
        XCTAssertNotNil(anyPresenter)
    }

    func testChoiceForResponseFlagsMapping() {
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse)),
            .singleShot
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationAlternateResponse)),
            .cancel
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationOtherResponse)),
            .grantFiveMinutes
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationCancelResponse)),
            .cancel
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: 0xFF),
            .cancel
        )
    }

    func testPromptWithHeadlessSessionFallback() {
        let previousProvider = GitSigningPrompt.sessionCheckProvider
        defer {
            GitSigningPrompt.sessionCheckProvider = previousProvider
        }

        GitSigningPrompt.sessionCheckProvider = { false }

        let presenter = CFUserNotificationGitSigningGracePresenter()
        let result = presenter.prompt(keyLabel: "headless-key", clientDesc: "headless-client")
        XCTAssertEqual(result, .singleShot, "Headless non-GUI sessions must safely fall back to single-shot without modal dialog")
    }
}
