import XCTest
@testable import ClavisCore

final class ClavisLoggerTests: ClavisBaseTestCase {

    func test_002_T8_securityLogIsNoLongerWritten() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let customLogURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customLogFileURL = customLogURL

        ClavisLogger.log(.securityAlert, "SECURITY_CANARY_ALERT_\(UUID().uuidString)")
        ClavisLogger.flush()

        let generalContent = try String(contentsOf: customLogURL, encoding: .utf8)
        XCTAssertTrue(generalContent.contains("SECURITY_CANARY_ALERT"))

        let expectedSecurityLogURL = tempDir.appendingPathComponent("clavis.security.log")
        XCTAssertFalse(FileManager.default.fileExists(atPath: expectedSecurityLogURL.path), "clavis.security.log must no longer be written")
    }

    func test_promptDebug_loggedWhenDebugEnabled() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let customLogURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customLogFileURL = customLogURL
        ClavisLogger.customDebug = true
        defer {
            ClavisLogger.customDebug = nil
            ClavisLogger.customLogFileURL = nil
        }

        ClavisLogger.promptDebug("clavis-code", "UserAuthenticator: prompting system authentication")
        ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: displaying delete alert")
        ClavisLogger.promptDebug("clavis-cli", "CLIService: displaying terminal seed prompt")
        ClavisLogger.promptDebug("generic prompt debug message")
        ClavisLogger.flush()

        let content = try String(contentsOf: customLogURL, encoding: .utf8)
        XCTAssertTrue(content.contains("[PROMPT_DEBUG] [clavis-code] UserAuthenticator: prompting system authentication"))
        XCTAssertTrue(content.contains("[PROMPT_DEBUG] [calvis-ui] KeyDetailInspectorView: displaying delete alert"))
        XCTAssertTrue(content.contains("[PROMPT_DEBUG] [clavis-cli] CLIService: displaying terminal seed prompt"))
        XCTAssertTrue(content.contains("[PROMPT_DEBUG] generic prompt debug message"))
    }

    func test_promptDebug_droppedWhenDebugDisabled() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let customLogURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customLogFileURL = customLogURL
        ClavisLogger.customDebug = false
        defer {
            ClavisLogger.customDebug = nil
            ClavisLogger.customLogFileURL = nil
        }

        ClavisLogger.promptDebug("clavis-code", "should be dropped when debug is false")
        ClavisLogger.flush()

        if FileManager.default.fileExists(atPath: customLogURL.path) {
            let content = try String(contentsOf: customLogURL, encoding: .utf8)
            XCTAssertFalse(content.contains("should be dropped when debug is false"))
        }
    }
}
