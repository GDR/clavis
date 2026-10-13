import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

final class CLIServiceTests: ClavisBaseTestCase {

    func testCLIServiceHelpCommand() {
        let keyManager = makeKeyManager()
        let resHelp = CLIService.handle(args: ["clavis", "help"], keyManager: keyManager)
        XCTAssertNotNil(resHelp)
        XCTAssertEqual(resHelp?.exitCode, 0)
        XCTAssertTrue(resHelp?.output.contains("Clavis") ?? false)

        let resDashH = CLIService.handle(args: ["clavis", "-h"], keyManager: keyManager)
        XCTAssertEqual(resDashH?.exitCode, 0)

        let resNoArgs = CLIService.handle(args: ["clavis"], keyManager: keyManager)
        XCTAssertNil(resNoArgs)
    }


    func testCLIServiceMissingGenerateArgs() {
        let keyManager = makeKeyManager()
        let missingArgsRes = CLIService.handle(args: ["clavis", "generate"], keyManager: keyManager)
        XCTAssertEqual(missingArgsRes?.exitCode, 1)
        XCTAssertEqual(missingArgsRes?.error, CLIMessages.usage(for: .generate))
    }

    func testCLIDeleteRequiresYesAndFreshAuthentication() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let manager = KeychainManager(
            authenticator: authenticator,
            privateKeyStore: store,
            agentGrantRevoker: { _ in }
        )
        let label = "delete-auth-\(UUID().uuidString)"
        _ = try manager.generateKey(label: label)

        let refused = CLIService.handle(
            args: ["clavis", "delete", label],
            keyManager: manager
        )
        XCTAssertEqual(refused?.exitCode, 1)
        XCTAssertEqual(refused?.error, "Usage: clavis delete <label> --yes")
        XCTAssertEqual(authenticator.authenticationCount, 0)
        XCTAssertTrue(store.contains(label: label))

        let deleted = CLIService.handle(
            args: ["clavis", "delete", label, "--yes"],
            keyManager: manager
        )
        XCTAssertEqual(deleted?.exitCode, 0)
        XCTAssertEqual(authenticator.authenticationCount, 1)
        XCTAssertFalse(store.contains(label: label))
    }
}
