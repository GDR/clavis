import Testing
import Foundation
@testable import ClavisCore

@Suite("SigningPromptGateTests")
struct SigningPromptGateTests {
    private final class Clock: @unchecked Sendable {
        var current = Date(timeIntervalSince1970: 1_000)
        func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
    }

    private func denial() -> Error { UserAuthenticationError.rejected(nil) }

    @Test
    func testPromptsRunOneAtATime() {
        let gate = SigningPromptGate()
        let lock = NSLock()
        var concurrent = 0
        var maxConcurrent = 0
        let group = DispatchGroup()
        for _ in 0..<6 {
            group.enter()
            Thread.detachNewThread {
                _ = try? gate.run {
                    lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                    Thread.sleep(forTimeInterval: 0.005)
                    lock.lock(); concurrent -= 1; lock.unlock()
                }
                group.leave()
            }
        }
        #expect(group.wait(timeout: .now() + 5) == .success)
        #expect(maxConcurrent == 1, "Authentication prompts must never overlap")
    }

    @Test
    func testRepeatedDenialsTriggerCooldownWithoutRunningBody() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, now: { clock.current })
        for _ in 0..<3 {
            #expect(throws: (any Error).self) {
                try gate.run { throw denial() }
            }
        }

        var bodyRan = false
        #expect {
            try gate.run { bodyRan = true }
        } throws: { error in
            (error as? SigningPromptGateError) == .coolingDown
        }
        #expect(!bodyRan, "No prompt may be shown while cooling down")

        clock.advance(59)
        #expect(throws: (any Error).self) {
            try gate.run { bodyRan = true }
        }
        #expect(!bodyRan)

        clock.advance(2)
        #expect(throws: Never.self) {
            try gate.run { bodyRan = true }
        }
        #expect(bodyRan, "Requests are admitted again after the cooldown")
    }

    @Test
    func testCooldownDoublesUntilCapAndResetsAfterSuccess() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 1, cooldown: 60, now: { clock.current })
        let expected: [TimeInterval] = [60, 120, 240, 480, 900, 900]

        for duration in expected {
            #expect(throws: (any Error).self) {
                try gate.run { throw denial() }
            }
            var bodyRan = false
            #expect {
                try gate.run { bodyRan = true }
            } throws: { error in
                (error as? SigningPromptGateError) == .coolingDown
            }
            #expect(!bodyRan)
            clock.advance(duration - 1)
            #expect(throws: (any Error).self) {
                try gate.run { bodyRan = true }
            }
            #expect(!bodyRan, "Still refused \(duration - 1)s into a \(duration)s lockout")
            clock.advance(1)
        }

        #expect(throws: Never.self) {
            try gate.run { }
        }
        #expect(throws: (any Error).self) {
            try gate.run { throw denial() }
        }
        var bodyRan = false
        clock.advance(59)
        #expect {
            try gate.run { bodyRan = true }
        } throws: { error in
            (error as? SigningPromptGateError) == .coolingDown
        }
        #expect(!bodyRan, "A success must restore the 60s base cooldown")
        clock.advance(1)
        #expect(throws: Never.self) {
            try gate.run { bodyRan = true }
        }
        #expect(bodyRan)
    }

    @Test
    func testSuccessResetsDenialCounter() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, cooldown: 60)
        for _ in 0..<2 {
            #expect(throws: (any Error).self) { try gate.run { throw denial() } }
        }
        #expect(throws: Never.self) { try gate.run { } }
        for _ in 0..<2 {
            #expect(throws: (any Error).self) { try gate.run { throw denial() } }
        }
        #expect(throws: Never.self) { try gate.run { } }
    }

    @Test
    func testNonAuthenticationFailuresDoNotCountAsDenials() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 2, cooldown: 60)
        for _ in 0..<5 {
            #expect(throws: (any Error).self) {
                try gate.run { throw PrivateKeyRecordError.publicKeyMismatch }
            }
        }
        #expect(throws: Never.self) { try gate.run { } }
    }

    @Test
    func testSystemSSHWarnsWhenTheAgentMayBeForwarded() {
        let requester = "ssh (PID 42)"
        let forwarded = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/ssh"
        )
        #expect(
            forwarded ==
            "use \u{201c}Main Key\u{201d} for SSH authentication (requested by ssh (PID 42)). This request may come from a forwarded agent; the remote host is not visible"
        )
        #expect(forwarded.contains("forwarded agent"))
        #expect(forwarded.contains("remote host is not visible"))
        #expect(forwarded.contains(requester))

        let standardized = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/./ssh"
        )
        #expect(standardized == forwarded)

        let homebrew = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/opt/homebrew/bin/ssh"
        )
        #expect(homebrew == forwarded)
        #expect(homebrew.contains("forwarded agent"))
        #expect(homebrew.contains("remote host is not visible"))

        let otherCaller = SSHAgentServer.signatureReason(
            keyLabel: "Main Key",
            requester: requester,
            processPath: "/usr/bin/security"
        )
        #expect(
            otherCaller ==
            SSHAgentServer.dataSigningReason(keyLabel: "Main Key", requester: requester)
        )
        #expect(!otherCaller.contains("forwarded agent"))
        #expect(!otherCaller.contains("remote host is not visible"))
    }

    @Test
    func testPromptsNameTheRequester() {
        #expect(
            SSHAgentServer.dataSigningReason(keyLabel: "Main Key", requester: "/usr/bin/ssh (PID 42)") ==
            "sign data requested by /usr/bin/ssh (PID 42) with \u{201c}Main Key\u{201d}"
        )
        #expect(
            SSHAgentServer.gitCommitSigningReason(keyLabel: "Main Key", requester: "ssh-keygen (PID 7)") ==
            "sign a Git commit with \u{201c}Main Key\u{201d} (requested by ssh-keygen (PID 7))"
        )
    }

    @Test
    func testRequesterDescriptionIsDisplaySafe() {
        #expect(SSHAgentServer.requesterDescription(processPath: "/usr/bin/ssh", pid: 42) == "/usr/bin/ssh (PID 42)")
        #expect(
            SSHAgentServer.requesterDescription(processPath: "/usr/bin/ssh", pid: 42) !=
            SSHAgentServer.requesterDescription(processPath: "/tmp/ssh", pid: 42)
        )
        // Control, newline and bidi-format characters are removed.
        let hostile = "/tmp/evil\n\u{202E}Approve\u{0007}"
        let described = SSHAgentServer.requesterDescription(processPath: hostile, pid: 1)
        #expect(!described.contains("\n"))
        #expect(!described.unicodeScalars.contains("\u{202E}"))
        #expect(!described.unicodeScalars.contains("\u{0007}"))
        // Format characters (such as zero-width space / direction marks) are removed.
        let formatHostile = "/tmp/bin\u{200B}\u{200E}\u{FEFF}"
        let describedFormat = SSHAgentServer.requesterDescription(processPath: formatHostile, pid: 1)
        #expect(describedFormat == "/tmp/bin (PID 1)")
        // Bounded length with visible middle ellipsis on path truncation, keeping both prefix and tail.
        let long = "/tmp/" + String(repeating: "a", count: 500)
        let describedLong = SSHAgentServer.requesterDescription(processPath: long, pid: 1)
        #expect(describedLong.count <= 80 + " (PID 1)".count)
        #expect(describedLong.hasPrefix("/tmp/" + String(repeating: "a", count: 27)))
        #expect(describedLong.contains("…"))
        #expect(describedLong.hasSuffix(String(repeating: "a", count: 47) + " (PID 1)"))
        #expect(SSHAgentServer.requesterDescription(processPath: "/", pid: 3) == "/ (PID 3)")

        // Whitespace padding is collapsed into a single space so leading directory cannot be pushed off-screen.
        let paddedSpoof = "/Users/attacker/evil" + String(repeating: " ", count: 80) + "/usr/bin/ssh"
        let describedPadded = SSHAgentServer.requesterDescription(processPath: paddedSpoof, pid: 99)
        #expect(describedPadded == "/Users/attacker/evil /usr/bin/ssh (PID 99)")
    }

    @Test
    func testNoisyRequesterLocksOutWhileCleanRequesterContinues() {
        let clock = Clock()
        let gate = SigningPromptGate(maxConsecutiveDenials: 3, cooldown: 60, now: { clock.current })
        let noisy = SigningPromptGate.Requester(executablePath: "/usr/bin/noisy", pid: 101)
        let clean = SigningPromptGate.Requester(executablePath: "/usr/bin/clean", pid: 202)

        for _ in 0..<3 {
            #expect(throws: (any Error).self) {
                try gate.run(requester: noisy) { throw denial() }
            }
        }

        // Noisy requester is locked out
        var noisyRan = false
        #expect {
            try gate.run(requester: noisy) { noisyRan = true }
        } throws: { error in
            (error as? SigningPromptGateError) == .coolingDown
        }
        #expect(!noisyRan, "Noisy requester must be in cooldown")

        // Clean requester continues without being locked out
        var cleanRan = false
        #expect(throws: Never.self) {
            try gate.run(requester: clean) { cleanRan = true }
        }
        #expect(cleanRan, "Clean requester must not be locked out by noisy requester")

        // Noisy requester is still locked out
        #expect(throws: (any Error).self) {
            try gate.run(requester: noisy) { noisyRan = true }
        }
        #expect(!noisyRan)

        // After cooldown expires, noisy requester is admitted again
        clock.advance(60)
        #expect(throws: Never.self) {
            try gate.run(requester: noisy) { noisyRan = true }
        }
        #expect(noisyRan, "Noisy requester admitted after cooldown")
    }

    @Test
    func testDeadSocketRequestDoesNotTriggerPromptBody() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        var clientFd: Int32 = fds[0]
        let serverFd = fds[1]
        defer {
            if clientFd >= 0 { close(clientFd) }
            close(serverFd)
        }

        // Peer closes connection
        close(clientFd)
        clientFd = -1


        let gate = SigningPromptGate()
        var bodyRan = false
        #expect {
            try gate.run(clientSocket: serverFd) {
                bodyRan = true
            }
        } throws: { error in
            (error as? SigningPromptGateError) == .clientDisconnected
        }
        #expect(!bodyRan, "Dead socket request must never trigger prompt body")
    }

    @Test
    func testIsSocketAliveStates() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let clientFd = fds[0]
        let serverFd = fds[1]
        defer {
            close(clientFd)
            close(serverFd)
        }

        // Idle socket returns true
        #expect(SigningPromptGate.isSocketAlive(serverFd), "Idle socket should be alive")

        // Pending byte (write 1 byte to peer) returns true
        var byte: UInt8 = 0x42
        #expect(write(clientFd, &byte, 1) == 1)
        #expect(SigningPromptGate.isSocketAlive(serverFd), "Socket with pending byte should be alive")
    }

    @Test
    func testIsSocketAlivePeerClosed() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        var clientFd: Int32 = fds[0]
        let serverFd = fds[1]
        defer {
            if clientFd >= 0 { close(clientFd) }
            close(serverFd)
        }

        // Peer closed returns false
        close(clientFd)
        clientFd = -1
        #expect(!SigningPromptGate.isSocketAlive(serverFd), "Closed peer without pending bytes should return false")
    }

    @Test
    func testIsSocketAlivePeerClosedWithQueuedByteReturnsTrueUntilRead() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        var clientFd: Int32 = fds[0]
        let serverFd = fds[1]
        defer {
            if clientFd >= 0 { close(clientFd) }
            close(serverFd)
        }

        // Peer closed with queued byte returns true until read
        var byte: UInt8 = 0xAA
        #expect(write(clientFd, &byte, 1) == 1)
        close(clientFd)
        clientFd = -1

        #expect(SigningPromptGate.isSocketAlive(serverFd), "Socket with queued byte from closed peer should return true")

        var readBuf: UInt8 = 0
        #expect(read(serverFd, &readBuf, 1) == 1)
        #expect(readBuf == 0xAA)

        #expect(!SigningPromptGate.isSocketAlive(serverFd), "Socket should return false once queued byte is read")
    }

    @Test
    func testGateRunWithPendingBytesDoesNotThrowClientDisconnected() {
        var fds: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let clientFd = fds[0]
        let serverFd = fds[1]
        defer {
            close(clientFd)
            close(serverFd)
        }

        var byte: UInt8 = 0x55
        #expect(write(clientFd, &byte, 1) == 1)

        let gate = SigningPromptGate()
        var bodyRan = false
        #expect(throws: Never.self) {
            try gate.run(clientSocket: serverFd) {
                bodyRan = true
            }
        }
        #expect(bodyRan, "gate.run should not throw clientDisconnected for socket with pending byte")
    }

    @Test
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
        Thread.detachNewThread {
            _ = try? gate.run(requester: requester) {
                activeStarted.signal()
                activeRelease.wait()
            }
            group.leave()
        }

        #expect(activeStarted.wait(timeout: .now() + 5) == .success)

        // 2. Waiting request for requester (1 waiting allowed)
        group.enter()
        Thread.detachNewThread {
            waitingStarted.signal()
            _ = try? gate.run(requester: requester) {
                // Should run after activeRelease
            }
            group.leave()
        }

        #expect(waitingStarted.wait(timeout: .now() + 5) == .success)

        Thread.sleep(forTimeInterval: 0.05)

        // 3. Third request for same requester exceeds cap (max 1 waiting + 1 active)
        var thirdRan = false
        #expect {
            try gate.run(requester: requester) {
                thirdRan = true
            }
        } throws: { error in
            (error as? SigningPromptGateError) == .queueFull
        }
        #expect(!thirdRan, "Third concurrent request for same requester must be rejected")

        // 4. Another requester can still queue a request (has its own cap)
        var otherRan = false
        let otherGroup = DispatchGroup()
        otherGroup.enter()
        Thread.detachNewThread {
            _ = try? gate.run(requester: otherRequester) {
                otherRan = true
            }
            otherGroup.leave()
        }

        // Release active request
        activeRelease.signal()
        #expect(group.wait(timeout: .now() + 3) == .success)
        #expect(otherGroup.wait(timeout: .now() + 3) == .success)
        #expect(otherRan, "Other requester request must succeed after turn")
    }

    @Test
    func testRunExclusiveSerializesConcurrentlyWithRun() {
        let gate = SigningPromptGate()
        let lock = NSLock()
        var concurrent = 0
        var maxConcurrent = 0
        let group = DispatchGroup()

        for i in 0..<8 {
            group.enter()
            Thread.detachNewThread {
                if i % 2 == 0 {
                    _ = try? gate.run {
                        lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                        Thread.sleep(forTimeInterval: 0.005)
                        lock.lock(); concurrent -= 1; lock.unlock()
                    }
                } else {
                    gate.runExclusive {
                        lock.lock(); concurrent += 1; maxConcurrent = max(maxConcurrent, concurrent); lock.unlock()
                        Thread.sleep(forTimeInterval: 0.005)
                        lock.lock(); concurrent -= 1; lock.unlock()
                    }
                }
                group.leave()
            }
        }

        #expect(group.wait(timeout: .now() + 5) == .success)
        #expect(maxConcurrent == 1, "run and runExclusive must never overlap")
    }

    @Test
    func testRunExclusiveDoesNotCountDenials() {
        let gate = SigningPromptGate(maxConsecutiveDenials: 2, cooldown: 60)

        struct CustomTestError: Error, Equatable {}

        // Multiple failures in runExclusive
        for _ in 0..<5 {
            #expect(throws: (any Error).self) { try gate.runExclusive { throw denial() } }
            #expect(throws: (any Error).self) { try gate.runExclusive { throw CustomTestError() } }
        }

        // gate.run should still execute normally without cooldown lockout
        var ran = false
        #expect(throws: Never.self) { try gate.run { ran = true } }
        #expect(ran, "Failures in runExclusive must not trigger denial tracking or cooldown")
    }

    @Test
    func testAgentPolicyAndExtendSessionDropWhenSocketDisconnected() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        try await fixture.run {
            // Create a socket whose peer is disconnected
            var fds: [Int32] = [-1, -1]
            #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
            let deadSock = fds[0]
            close(fds[1])
            defer { close(deadSock) }


            let countingAuth = CountingAuthenticator()
            let audit = InMemoryAuditRecorder()
            let keyMgr = fixture.makeKeyManager(authenticator: countingAuth, auditRecorder: audit)
            let key = try keyMgr.generateKey(label: "gate-drop-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let policyStore = InMemoryAgentPolicyStore()
            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: audit,
                watchRootExit: false
            )

            let server = SSHAgentServer(
                role: .personal,
                keyManager: keyMgr,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: audit,
                agentSessions: registry,
                agentPolicies: policyStore
            )

            // Register session
            var regPayload = Data([SSHAgentServer.registerAgentSessionRequest])
            regPayload.appendWireString(key.label)
            regPayload.appendWireString("gate-tool")
            regPayload.appendWireUInt32(30)
            let regResp = server.processAgentRequest(
                payload: regPayload,
                clientPid: 1234,
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(regResp.first == 6)
            let sessionID = try #require(registry.summaries().first?.id)

            let authCountBefore = countingAuth.authenticationCount

            // 1. setAgentPolicy with dead socket
            let newPolicy = AgentKeyPolicy(mode: .ask)
            let policyData = try JSONEncoder().encode(newPolicy)
            var setPolicyPayload = Data([SSHAgentServer.setAgentPolicyRequest])
            setPolicyPayload.appendWireString(key.fingerprint)
            setPolicyPayload.appendWireString(String(data: policyData, encoding: .utf8)!)

            let setResp = server.processAgentRequest(
                payload: setPolicyPayload,
                clientPid: 1234,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: 1000,
                clientSocket: deadSock,
                isTrustedControlPeer: { true }
            )
            #expect(setResp == Data([5]))
            #expect(countingAuth.authenticationCount == authCountBefore, "setAgentPolicy must not prompt on dead socket")

            // 2. extendAgentSession with dead socket
            var extendPayload = Data([SSHAgentServer.extendAgentSessionRequest])
            extendPayload.appendWireString(sessionID)
            extendPayload.appendWireUInt32(30)

            let extendResp = server.processAgentRequest(
                payload: extendPayload,
                clientPid: 1234,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: 1000,
                clientSocket: deadSock,
                isTrustedControlPeer: { true }
            )
            #expect(extendResp == Data([5]))
            #expect(countingAuth.authenticationCount == authCountBefore, "extendAgentSession must not prompt on dead socket")
        }
    }
}


