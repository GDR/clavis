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
        XCTAssertEqual(homebrew, forwarded)
        XCTAssertTrue(homebrew.contains("forwarded agent"))
        XCTAssertTrue(homebrew.contains("remote host is not visible"))

        let otherCaller = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/security"
        )
        XCTAssertEqual(
            otherCaller,
            SSHAgentServer.dataSigningReason(keyLabel: "Main Key", requester: requester)
        )
        XCTAssertFalse(otherCaller.contains("forwarded agent"))
        XCTAssertFalse(otherCaller.contains("remote host is not visible"))
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
        // Format characters (such as zero-width space / direction marks) are removed.
        let formatHostile = "/tmp/bin\u{200B}\u{200E}\u{FEFF}"
        let describedFormat = SSHAgentServer.requesterDescription(processPath: formatHostile, pid: 1)
        XCTAssertEqual(describedFormat, "/tmp/bin (PID 1)")
        // Bounded length with visible ellipsis on path truncation, keeping the tail.
        let long = "/tmp/" + String(repeating: "a", count: 500)
        let describedLong = SSHAgentServer.requesterDescription(processPath: long, pid: 1)
        XCTAssertLessThanOrEqual(describedLong.count, 80 + " (PID 1)".count)
        XCTAssertTrue(describedLong.hasPrefix("…"))
        XCTAssertTrue(describedLong.hasSuffix(String(repeating: "a", count: 79) + " (PID 1)"))
        XCTAssertEqual(SSHAgentServer.requesterDescription(processPath: "/", pid: 3), "/ (PID 3)")
    }

    func testNoisyRequesterLocksOutWhileCleanRequesterContinues() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, cooldown: 60, now: { clock.current })
        let noisy = SigningPromptGate.Requester(executablePath: "/usr/bin/noisy", pid: 101)
        let clean = SigningPromptGate.Requester(executablePath: "/usr/bin/clean", pid: 202)

        for _ in 0..<3 {
            XCTAssertThrowsError(try gate.run(requester: noisy) { throw denial() })
        }

        // Noisy requester is locked out
        var noisyRan = false
        XCTAssertThrowsError(try gate.run(requester: noisy) { noisyRan = true }) {
            XCTAssertEqual($0 as? SigningPromptGateError, .coolingDown)
        }
        XCTAssertFalse(noisyRan, "Noisy requester must be in cooldown")

        // Clean requester continues without being locked out
        var cleanRan = false
        XCTAssertNoThrow(try gate.run(requester: clean) { cleanRan = true })
        XCTAssertTrue(cleanRan, "Clean requester must not be locked out by noisy requester")

        // Noisy requester is still locked out
        XCTAssertThrowsError(try gate.run(requester: noisy) { noisyRan = true })
        XCTAssertFalse(noisyRan)

        // After cooldown expires, noisy requester is admitted again
        clock.advance(60)
        XCTAssertNoThrow(try gate.run(requester: noisy) { noisyRan = true })
        XCTAssertTrue(noisyRan, "Noisy requester admitted after cooldown")
    }

    func testDeadSocketRequestDoesNotTriggerPromptBody() {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let clientFd = fds[0]
        let serverFd = fds[1]
        defer {
            close(clientFd)
            close(serverFd)
        }

        // Peer closes connection
        close(clientFd)

        let gate = SigningPromptGate()
        var bodyRan = false
        XCTAssertThrowsError(try gate.run(clientSocket: serverFd) {
            bodyRan = true
        }) { error in
            XCTAssertEqual(error as? SigningPromptGateError, .clientDisconnected)
        }
        XCTAssertFalse(bodyRan, "Dead socket request must never trigger prompt body")
    }

    func testQueueCapPerRequesterEnforcesMaxOneWaitingAndOneActive() {
        let gate = SigningPromptGate()
        let requester = SigningPromptGate.Requester(executablePath: "/usr/bin/git", pid: 42)
        let otherRequester = SigningPromptGate.Requester(executablePath: "/usr/bin/ssh", pid: 99)

        let activeStarted = DispatchSemaphore(value: 0)
        let activeRelease = DispatchSemaphore(value: 0)
        let waitingStarted = DispatchSemaphore(value: 0)

        let group = DispatchGroup()

        // 1. Active request for requester
        group.enter()
        DispatchQueue.global().async {
            _ = try? gate.run(requester: requester) {
                activeStarted.signal()
                activeRelease.wait()
            }
            group.leave()
        }

        XCTAssertEqual(activeStarted.wait(timeout: .now() + 2), .success)

        // 2. Waiting request for requester (1 waiting allowed)
        group.enter()
        DispatchQueue.global().async {
            waitingStarted.signal()
            _ = try? gate.run(requester: requester) {
                // Should run after activeRelease
            }
            group.leave()
        }

        XCTAssertEqual(waitingStarted.wait(timeout: .now() + 2), .success)
        Thread.sleep(forTimeInterval: 0.05)

        // 3. Third request for same requester exceeds cap (max 1 waiting + 1 active)
        var thirdRan = false
        XCTAssertThrowsError(try gate.run(requester: requester) {
            thirdRan = true
        }) { error in
            XCTAssertEqual(error as? SigningPromptGateError, .queueFull)
        }
        XCTAssertFalse(thirdRan, "Third concurrent request for same requester must be rejected")

        // 4. Another requester can still queue a request (has its own cap)
        var otherRan = false
        let otherGroup = DispatchGroup()
        otherGroup.enter()
        DispatchQueue.global().async {
            _ = try? gate.run(requester: otherRequester) {
                otherRan = true
            }
            otherGroup.leave()
        }

        // Release active request
        activeRelease.signal()
        XCTAssertEqual(group.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(otherGroup.wait(timeout: .now() + 3), .success)
        XCTAssertTrue(otherRan, "Other requester request must succeed after turn")
    }

    func testRunExclusiveSerializesConcurrentlyWithRun() {
        let gate = SigningPromptGate()
        let lock = NSLock()
        var concurrent = 0
        var maxConcurrent = 0
        let group = DispatchGroup()

        for i in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                if i % 2 == 0 {
                    _ = try? gate.run {
                        lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                        Thread.sleep(forTimeInterval: 0.02)
                        lock.lock(); concurrent -= 1; lock.unlock()
                    }
                } else {
                    gate.runExclusive {
                        lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                        Thread.sleep(forTimeInterval: 0.02)
                        lock.lock(); concurrent -= 1; lock.unlock()
                    }
                }
                group.leave()
            }
        }

        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(maxConcurrent, 1, "run and runExclusive must never overlap")
    }

    func testRunExclusiveDoesNotCountDenials() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 2, cooldown: 60)

        struct CustomTestError: Error, Equatable {}

        // Multiple failures in runExclusive
        for _ in 0..<5 {
            XCTAssertThrowsError(try gate.runExclusive { throw denial() })
            XCTAssertThrowsError(try gate.runExclusive { throw CustomTestError() })
        }

        // gate.run should still execute normally without cooldown lockout
        var ran = false
        XCTAssertNoThrow(try gate.run { ran = true })
        XCTAssertTrue(ran, "Failures in runExclusive must not trigger denial tracking or cooldown")
    }
}


