import XCTest
@testable import ClavisCore

final class ClavisLoggerTests: ClavisBaseTestCase {

    func testSecurityLogRetentionAgainstUnauthenticatedNoiseAndRepeatedEvents() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-tests", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let customLogURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customLogFileURL = customLogURL
        ClavisLogger.customMaximumLogFileSize = 4096

        let canaryMessage = "SECURITY_CANARY_ALERT_\(UUID().uuidString)"
        ClavisLogger.log(.securityAlert, canaryMessage)

        for _ in 0..<5000 {
            ClavisLogger.log("SSH_AGENT_REJECT", "Failed to parse sign request wire payload.")
        }

        let repeatedMessage = "Repeated security event payload"
        for _ in 0..<5000 {
            ClavisLogger.log(.securityAlert, repeatedMessage)
        }

        ClavisLogger.flush()

        let securityFiles = ClavisLogger.rotatedSecurityLogFiles()
        let allSecurityContent = securityFiles
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }
            .joined()

        XCTAssertTrue(allSecurityContent.contains(canaryMessage), "Canary line should remain in retained security log files")

        // Retention budget check: at most 1 active + 10 rotated files, each bounded by max size
        XCTAssertLessThanOrEqual(securityFiles.count, 11)
        for file in securityFiles {
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            let size = attrs[.size] as? UInt64 ?? 0
            XCTAssertLessThanOrEqual(size, 4096 + 8192)
        }

        let summaryPattern = #"\.\.\. \(repeated \d+ times\)"#
        let regex = try NSRegularExpression(pattern: summaryPattern)
        let matches = regex.matches(in: allSecurityContent, range: NSRange(allSecurityContent.startIndex..., in: allSecurityContent))
        XCTAssertEqual(matches.count, 1, "Collapse summary '... (repeated N times)' should appear once")
    }

    func testUnauthenticatedSignErrorsAreNotMirroredToSecurityLog() throws {
        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let secURL = ClavisLogger.securityLogFileURL

        ClavisLogger.log("SSH_AGENT_REJECT", "Failed to parse sign request wire payload.")
        ClavisLogger.log("SSH_AGENT_REJECT", "No matching key found for requested public key blob.")
        ClavisLogger.log("SSH_AGENT_REJECT", "Rejected signing request because peer process attribution was unavailable.")
        ClavisLogger.log("SSH_AGENT_SIGN", "Arbitrary unauthenticated noise line.")
        ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key 'test-key' requested by test-proc (PID 123)...")
        ClavisLogger.log("SSH_AGENT_SIGN", "Signature completed successfully for 'test-key' (test-proc (PID 123)).")
        ClavisLogger.flush()

        let generalContent = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
        let securityContent = (try? String(contentsOf: secURL, encoding: .utf8)) ?? ""

        // General log receives all entries
        XCTAssertTrue(generalContent.contains("Failed to parse sign request wire payload."))
        XCTAssertTrue(generalContent.contains("No matching key found for requested public key blob."))
        XCTAssertTrue(generalContent.contains("Rejected signing request because peer process attribution was unavailable."))
        XCTAssertTrue(generalContent.contains("Arbitrary unauthenticated noise line."))
        XCTAssertTrue(generalContent.contains("Initiating signature for key 'test-key'"))
        XCTAssertTrue(generalContent.contains("Signature completed successfully for 'test-key'"))

        // Security log only mirrors legitimate authorized signature steps, not unauthenticated noise
        XCTAssertFalse(securityContent.contains("Failed to parse sign request wire payload."))
        XCTAssertFalse(securityContent.contains("No matching key found for requested public key blob."))
        XCTAssertFalse(securityContent.contains("Rejected signing request because peer process attribution was unavailable."))
        XCTAssertFalse(securityContent.contains("Arbitrary unauthenticated noise line."))
        XCTAssertTrue(securityContent.contains("Initiating signature for key 'test-key'"))
        XCTAssertTrue(securityContent.contains("Signature completed successfully for 'test-key'"))
    }

    func testCollapseOnRepeatEmitsSummaryWhenNextDifferentLineArrives() throws {
        let secURL = ClavisLogger.securityLogFileURL

        for _ in 0..<10 {
            ClavisLogger.log(.securityAlert, "Repeated threat detected")
        }
        ClavisLogger.log(.securityAlert, "Subsequent distinct threat")
        ClavisLogger.flush()

        let securityContent = (try? String(contentsOf: secURL, encoding: .utf8)) ?? ""
        XCTAssertTrue(securityContent.contains("Repeated threat detected"))
        XCTAssertTrue(securityContent.contains("... (repeated 9 times)"))
        XCTAssertTrue(securityContent.contains("Subsequent distinct threat"))

        // Ensure the initial line appears once and summary appears once
        let initialMatches = securityContent.components(separatedBy: "Repeated threat detected").count - 1
        XCTAssertEqual(initialMatches, 1)
        let summaryMatches = securityContent.components(separatedBy: "... (repeated 9 times)").count - 1
        XCTAssertEqual(summaryMatches, 1)
    }

    func testCollapseOnRepeatEmitsSummaryWhenWindowExpires() throws {
        ClavisLogger.customRepeatWindow = 0.05
        defer { ClavisLogger.customRepeatWindow = nil }
        let secURL = ClavisLogger.securityLogFileURL

        ClavisLogger.log(.lock, "Screen locked")
        ClavisLogger.log(.lock, "Screen locked")
        ClavisLogger.log(.lock, "Screen locked")

        // Wait for repeat window to expire
        Thread.sleep(forTimeInterval: 0.1)

        // Trigger log check after window expiry
        ClavisLogger.log(.lock, "New screen lock event after expiry")
        ClavisLogger.flush()

        let securityContent = (try? String(contentsOf: secURL, encoding: .utf8)) ?? ""
        XCTAssertTrue(securityContent.contains("... (repeated 2 times)"))
        XCTAssertTrue(securityContent.contains("New screen lock event after expiry"))
    }
}
