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

    func testCollapseOnRepeatEmitsSingleSummaryOnFlushEvenWhenOtherLinesInterleave() throws {
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

        // First line plus the summary, which names the repeated message (excerpt).
        let initialMatches = securityContent.components(separatedBy: "Repeated threat detected").count - 1
        XCTAssertEqual(initialMatches, 2)
        let summaryMatches = securityContent.components(separatedBy: "... (repeated 9 times)").count - 1
        XCTAssertEqual(summaryMatches, 1)
    }

    /// R16: alternating a few distinct messages used to reset the dedup state on every switch and
    /// rotated the canary out of the security log.
    func testAlternatingMessagesCannotEvictEvidenceFromSecurityLog() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-alternating", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        ClavisLogger.customLogFileURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customMaximumLogFileSize = 4096

        let canary = "SECURITY_CANARY_ALERT_\(UUID().uuidString)"
        ClavisLogger.log(.securityAlert, canary)

        let messages = (240...242).map { "Refused control request type \($0) from untrusted peer (PID 4242)." }
        for i in 0..<20_000 {
            ClavisLogger.log(.securityAlert, messages[i % messages.count])
        }
        ClavisLogger.flush()

        let files = ClavisLogger.rotatedSecurityLogFiles()
        let content = files.compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
        XCTAssertTrue(content.contains(canary), "Canary must survive an alternating-message flood")
        XCTAssertLessThanOrEqual(files.count, 11)
        for message in messages {
            XCTAssertTrue(content.contains(message), "Each distinct message is logged once")
        }
    }

    /// R16: varying text (a new PID per request) defeats per-message dedup; the category budget bounds it.
    func testDistinctAlertFloodIsBoundedByBudgetAndExemptCategoriesStillLog() throws {
        let tempDir = testRootURL.appendingPathComponent("logger-budget", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        ClavisLogger.customLogFileURL = tempDir.appendingPathComponent("clavis.log")
        ClavisLogger.customMaximumLogFileSize = 4096
        ClavisLogger.customMirrorBudget = 5

        let canary = "SECURITY_CANARY_ALERT_\(UUID().uuidString)"
        ClavisLogger.log(.securityAlert, canary)
        for pid in 0..<5_000 {
            ClavisLogger.log(.securityAlert, "Refused request from untrusted peer (PID \(pid)).")
        }
        // Authenticated, user-driven events must not be starved by the alert flood.
        ClavisLogger.log(.keyDelete, "Deleted key 'victim'")
        ClavisLogger.log(.lock, "Agent locked")
        ClavisLogger.flush()

        let files = ClavisLogger.rotatedSecurityLogFiles()
        let content = files.compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
        XCTAssertTrue(content.contains(canary))
        XCTAssertTrue(content.contains("Deleted key 'victim'"))
        XCTAssertTrue(content.contains("Agent locked"))
        XCTAssertTrue(content.contains("(suppressed "), "Over-budget lines must leave a marker")
        XCTAssertFalse(content.contains("(PID 4999)"), "Lines past the budget are not mirrored")
        XCTAssertLessThanOrEqual(files.count, 2)
    }

    func testMirrorBudgetResetsAfterWindow() throws {
        ClavisLogger.customRepeatWindow = 0.05
        ClavisLogger.customMirrorBudget = 2
        let secURL = ClavisLogger.securityLogFileURL

        for i in 0..<5 { ClavisLogger.log(.securityAlert, "before window \(i)") }
        Thread.sleep(forTimeInterval: 0.1)
        ClavisLogger.log(.securityAlert, "after window")
        ClavisLogger.flush()

        let content = (try? String(contentsOf: secURL, encoding: .utf8)) ?? ""
        XCTAssertTrue(content.contains("before window 0"))
        XCTAssertTrue(content.contains("before window 1"))
        XCTAssertFalse(content.contains("before window 4"))
        XCTAssertTrue(content.contains("(suppressed 3 lines"))
        XCTAssertTrue(content.contains("after window"), "Budget must reset once the window expires")
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
