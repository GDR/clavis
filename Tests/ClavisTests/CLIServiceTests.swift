import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
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


    func testCLIServiceImportValidation() {
        let keyManager = makeKeyManager()
        let invalidSeedRes = CLIService.handle(
            args: ["clavis", "import", "mykey", "--stdin"],
            seedDataProvider: { Data([0x01]) },
            keyManager: keyManager
        )
        XCTAssertNotNil(invalidSeedRes)
        XCTAssertEqual(invalidSeedRes?.exitCode, 1)
        XCTAssertEqual(invalidSeedRes?.error, "Invalid hex seed string (must be 64 hex characters / 32 bytes).")

        let missingArgsRes = CLIService.handle(args: ["clavis", "generate"], keyManager: keyManager)
        XCTAssertEqual(missingArgsRes?.exitCode, 1)
        XCTAssertEqual(missingArgsRes?.error, "Usage: clavis generate <label>")
    }


    func testCLIServiceImportViaStdin() throws {
        let keyManager = makeKeyManager()
        let label = "stdin_key_\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }

        let res = CLIService.handle(
            args: ["clavis", "import", label, "--stdin"],
            seedDataProvider: { Data(repeating: 0xab, count: 32) },
            keyManager: keyManager
        )

        XCTAssertNotNil(res)
        XCTAssertEqual(res?.exitCode, 0)
        XCTAssertTrue(res?.output.contains("Successfully imported") ?? false)
        XCTAssertFalse(res?.output.contains("SECURITY WARNING") ?? true)

        let loaded = try keyManager.fetchKeyInfo(label: label)
        XCTAssertNotNil(loaded)
    }


    func testCLIServiceRejectsImportViaArgv() throws {
        let keyManager = makeKeyManager()
        let label = "argv_key_\(UUID().uuidString)"

        let validHexSeed = String(repeating: "cd", count: 32)
        let res = CLIService.handle(
            args: ["clavis", "import", label, validHexSeed],
            keyManager: keyManager
        )

        XCTAssertNotNil(res)
        XCTAssertEqual(res?.exitCode, 1)
        XCTAssertEqual(
            res?.error,
            "Refusing private seed in command arguments. Use interactive input or --stdin."
        )

        let loaded = try keyManager.fetchKeyInfo(label: label)
        XCTAssertNil(loaded)
    }


}
