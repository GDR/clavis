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
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, cooldown: 15, now: { clock.current })
        for _ in 0..<3 {
            XCTAssertThrowsError(try gate.run { throw denial() })
        }

        var bodyRan = false
        XCTAssertThrowsError(try gate.run { bodyRan = true }) {
            XCTAssertEqual($0 as? SigningPromptGateError, .coolingDown)
        }
        XCTAssertFalse(bodyRan, "No prompt may be shown while cooling down")

        clock.advance(14)
        XCTAssertThrowsError(try gate.run { bodyRan = true })
        XCTAssertFalse(bodyRan)

        clock.advance(2)
        XCTAssertNoThrow(try gate.run { bodyRan = true })
        XCTAssertTrue(bodyRan, "Requests are admitted again after the cooldown")
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

    func testPromptsNameTheRequester() {
        XCTAssertEqual(
            SSHAgentServer.sshAuthenticationReason(keyLabel: "Main Key", requester: "ssh (PID 42)"),
            "use \u{201c}Main Key\u{201d} for SSH authentication (requested by ssh (PID 42))"
        )
        XCTAssertEqual(
            SSHAgentServer.gitCommitSigningReason(keyLabel: "Main Key", requester: "ssh-keygen (PID 7)"),
            "sign a Git commit with \u{201c}Main Key\u{201d} (requested by ssh-keygen (PID 7))"
        )
    }

    func testRequesterDescriptionIsDisplaySafe() {
        XCTAssertEqual(SSHAgentServer.requesterDescription(processPath: "/usr/bin/ssh", pid: 42), "ssh (PID 42)")
        // Control, newline and bidi-format characters are removed.
        let hostile = "/tmp/evil\n\u{202E}Approve\u{0007}"
        let described = SSHAgentServer.requesterDescription(processPath: hostile, pid: 1)
        XCTAssertFalse(described.contains("\n"))
        XCTAssertFalse(described.unicodeScalars.contains("\u{202E}"))
        XCTAssertFalse(described.unicodeScalars.contains("\u{0007}"))
        // Bounded length and a non-empty fallback.
        let long = "/tmp/" + String(repeating: "a", count: 500)
        XCTAssertLessThanOrEqual(SSHAgentServer.requesterDescription(processPath: long, pid: 1).count, 48 + " (PID 1)".count)
        XCTAssertEqual(SSHAgentServer.requesterDescription(processPath: "/", pid: 3), "/ (PID 3)")
    }
}
