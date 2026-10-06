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
}
