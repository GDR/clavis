import XCTest
@testable import ClavisCore

final class SigningPromptGateTests: ClavisBaseTestCase {
    private final class Clock: @unchecked Sendable {
        var current = Date(timeIntervalSince1970: 1_000)
        func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
    }

    private func denial() -> Error { UserAuthenticationError.rejected(nil) }

    func testPromptsRunOneAtATime() {
        let gate = SigningPromptGate()
        let lock = NSLock()
        var concurrent = 0
        var maxConcurrent = 0
        let group = DispatchGroup()
        for _ in 0..<6 {
            group.enter()
            DispatchQueue.global().async {
                _ = try? gate.run {
                    lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                    Thread.sleep(forTimeInterval: 0.02)
                    lock.lock(); concurrent -= 1; lock.unlock()
                }
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(maxConcurrent, 1, "Authentication prompts must never overlap")
    }

    func testRepeatedDenialsTriggerCooldownWithoutRunningBody() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, now: { clock.current })
        for _ in 0..<3 {
            XCTAssertThrowsError(try gate.run { throw denial() })
        }

        var bodyRan = false
        XCTAssertThrowsError(try gate.run { bodyRan = true }) {
            XCTAssertEqual($0 as? SigningPromptGateError, .coolingDown)
        }
        XCTAssertFalse(bodyRan, "No prompt may be shown while cooling down")

        clock.advance(59)
        XCTAssertThrowsError(try gate.run { bodyRan = true })
        XCTAssertFalse(bodyRan)

        clock.advance(2)
        XCTAssertNoThrow(try gate.run { bodyRan = true })
        XCTAssertTrue(bodyRan, "Requests are admitted again after the cooldown")
    }

    func testCooldownDoublesUntilCapAndResetsAfterSuccess() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 1, cooldown: 60, now: { clock.current })
        let expected: [TimeInterval] = [60, 120, 240, 480, 900, 900]

        for duration in expected {
            XCTAssertThrowsError(try gate.run { throw denial() })
            var bodyRan = false
            XCTAssertThrowsError(try gate.run { bodyRan = true }) {
                XCTAssertEqual($0 as? SigningPromptGateError, .coolingDown)
            }
            XCTAssertFalse(bodyRan)
            clock.advance(duration - 1)
            XCTAssertThrowsError(try gate.run { bodyRan = true })
            XCTAssertFalse(bodyRan, "Still refused \(duration - 1)s into a \(duration)s lockout")
            clock.advance(1)
        }

        XCTAssertNoThrow(try gate.run { })
        XCTAssertThrowsError(try gate.run { throw denial() })
        var bodyRan = false
        clock.advance(59)
        XCTAssertThrowsError(try gate.run { bodyRan = true }) {
            XCTAssertEqual($0 as? SigningPromptGateError, .coolingDown)
        }
        XCTAssertFalse(bodyRan, "A success must restore the 60s base cooldown")
        clock.advance(1)
        XCTAssertNoThrow(try gate.run { bodyRan = true })
        XCTAssertTrue(bodyRan)
    }

    func testSuccessResetsDenialCounter() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, cooldown: 60)
        for _ in 0..<2 { XCTAssertThrowsError(try gate.run { throw denial() }) }
        XCTAssertNoThrow(try gate.run { })
        for _ in 0..<2 { XCTAssertThrowsError(try gate.run { throw denial() }) }
        XCTAssertNoThrow(try gate.run { }, "Two denials after a success must not reach the threshold")
    }

    func testNonAuthenticationFailuresDoNotCountAsDenials() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 2, cooldown: 60)
        for _ in 0..<5 {
            XCTAssertThrowsError(try gate.run { throw PrivateKeyRecordError.publicKeyMismatch })
        }
        XCTAssertNoThrow(try gate.run { })
    }

    func testSystemSSHWarnsWhenTheAgentMayBeForwarded() {
        let requester = "ssh (PID 42)"
        let forwarded = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/ssh"
        )
        XCTAssertEqual(
            forwarded,
            "use \u{201c}Main Key\u{201d} for SSH authentication (requested by ssh (PID 42)). This request may come from a forwarded agent; the remote host is not visible"
        )
        XCTAssertTrue(forwarded.contains("forwarded agent"))
        XCTAssertTrue(forwarded.contains("remote host is not visible"))
        XCTAssertTrue(forwarded.contains(requester))

        let standardized = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/./ssh"
        )
        XCTAssertEqual(standardized, forwarded)

        let homebrew = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/opt/homebrew/bin/ssh"
        )
        XCTAssertEqual(
            homebrew,
            SSHAgentServer.dataSigningReason(keyLabel: "Main Key", requester: requester)
        )
        XCTAssertFalse(homebrew.contains("forwarded agent"))
        XCTAssertFalse(homebrew.contains("remote host is not visible"))
    }

    func testPromptsNameTheRequester() {
        XCTAssertEqual(
            SSHAgentServer.dataSigningReason(keyLabel: "Main Key", requester: "/usr/bin/ssh (PID 42)"),
            "sign data requested by /usr/bin/ssh (PID 42) with \u{201c}Main Key\u{201d}"
        )
        XCTAssertEqual(
            SSHAgentServer.gitCommitSigningReason(keyLabel: "Main Key", requester: "ssh-keygen (PID 7)"),
            "sign a Git commit with \u{201c}Main Key\u{201d} (requested by ssh-keygen (PID 7))"
        )
    }

    func testRequesterDescriptionIsDisplaySafe() {
        XCTAssertEqual(SSHAgentServer.requesterDescription(processPath: "/usr/bin/ssh", pid: 42), "/usr/bin/ssh (PID 42)")
        XCTAssertNotEqual(
            SSHAgentServer.requesterDescription(processPath: "/usr/bin/ssh", pid: 42),
            SSHAgentServer.requesterDescription(processPath: "/tmp/ssh", pid: 42)
        )
        // Control, newline and bidi-format characters are removed.
        let hostile = "/tmp/evil\n\u{202E}Approve\u{0007}"
        let described = SSHAgentServer.requesterDescription(processPath: hostile, pid: 1)
        XCTAssertFalse(described.contains("\n"))
        XCTAssertFalse(described.unicodeScalars.contains("\u{202E}"))
        XCTAssertFalse(described.unicodeScalars.contains("\u{0007}"))
        // Bounded length, keeping the end of a long path, and a non-empty fallback.
        let long = "/tmp/" + String(repeating: "a", count: 500)
        let describedLong = SSHAgentServer.requesterDescription(processPath: long, pid: 1)
        XCTAssertLessThanOrEqual(describedLong.count, 80 + " (PID 1)".count)
        XCTAssertTrue(describedLong.hasSuffix(String(repeating: "a", count: 80) + " (PID 1)"))
        XCTAssertEqual(SSHAgentServer.requesterDescription(processPath: "/", pid: 3), "/ (PID 3)")
    }
}
