import XCTest
@testable import ClavisCore

final class AgentSessionRegistryTests: ClavisBaseTestCase {
    private var auditRecorder: InMemoryAuditRecorder!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auditRecorder = InMemoryAuditRecorder()
    }

    private func makeSession(
        id: String = "0123456789abcdef0123456789abcdef",
        keyLabel: String = "test-agent-key",
        keyFingerprint: String = "SHA256:agentfingerprint1234567890",
        toolName: String = "agent-tool",
        rootPid: pid_t = 100,
        rootStartTime: UInt64 = 1000,
        startedAt: Date = Date(),
        expiresAt: Date = Date().addingTimeInterval(3600)
    ) -> AgentSession {
        AgentSession(
            id: id,
            keyLabel: keyLabel,
            keyFingerprint: keyFingerprint,
            toolName: toolName,
            root: AgentSessionRoot(pid: rootPid, startTime: rootStartTime),
            startedAt: startedAt,
            expiresAt: expiresAt,
            grant: AgentSessionGrant()
        )
    }

    func test_001_AC2_noSessionMeansNoSession() {
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let result = registry.session(forKeyFingerprint: "SHA256:unknown", peerPid: 100)
        XCTAssertEqual(result, .noSession)
    }

    func test_001_AC3_peerOutsideTreeIsRejected() {
        let session = makeSession(rootPid: 100, rootStartTime: 1000)
        let processTable: [pid_t: (startTime: UInt64, parentPid: pid_t)] = [
            100: (startTime: 1000, parentPid: 1),
            200: (startTime: 2000, parentPid: 1)
        ]
        let registry = AgentSessionRegistry(
            processInfo: { processTable[$0] },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        registry.add(session)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 200)
        XCTAssertEqual(result, .outsideTree)
    }

    func test_001_T1_descendantIsFound() {
        let session = makeSession(rootPid: 100, rootStartTime: 1000)
        let processTable: [pid_t: (startTime: UInt64, parentPid: pid_t)] = [
            100: (startTime: 1000, parentPid: 1),
            250: (startTime: 2500, parentPid: 100),
            300: (startTime: 3000, parentPid: 250)
        ]
        let registry = AgentSessionRegistry(
            processInfo: { processTable[$0] },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        registry.add(session)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 300)
        XCTAssertEqual(result, .found(session))
    }

    func test_001_T1_pidReuseIsNotMember() {
        let session = makeSession(rootPid: 100, rootStartTime: 1000)
        // Candidate root is alive with start time 1000.
        // Peer 300 has an ancestor with pid 100, but when looking up that ancestor,
        // it has a different start time (e.g. reused PID).
        var callCountFor100 = 0
        let registry = AgentSessionRegistry(
            processInfo: { pid in
                if pid == 100 {
                    callCountFor100 += 1
                    // 1st call is add liveness check
                    // 2nd call is candidate root liveness check
                    // 3rd call is during tree walk from peer 300
                    return callCountFor100 <= 2 ? (startTime: 1000, parentPid: 1) : (startTime: 9999, parentPid: 1)
                }
                if pid == 300 {
                    return (startTime: 3000, parentPid: 100)
                }
                return nil
            },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        registry.add(session)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 300)
        XCTAssertEqual(result, .outsideTree)
    }

    func test_001_T1_leaseExpiryEndsSession() {
        var currentTime = Date(timeIntervalSince1970: 1_000_000)
        let session = makeSession(
            rootPid: 100,
            rootStartTime: 1000,
            startedAt: currentTime,
            expiresAt: currentTime.addingTimeInterval(300)
        )
        let registry = AgentSessionRegistry(
            now: { currentTime },
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        registry.add(session)

        // Advance time past expiry
        currentTime = currentTime.addingTimeInterval(301)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        XCTAssertEqual(result, .expired(session))

        // Session was ended on lookup
        XCTAssertEqual(registry.count, 0)
        let secondLookup = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        XCTAssertEqual(secondLookup, .noSession)
    }

    func test_001_T1_walkStopsAt64Hops() {
        let session = makeSession(rootPid: 100, rootStartTime: 1000)
        // Cyclic process table that does not contain root 100
        let processTable: [pid_t: (startTime: UInt64, parentPid: pid_t)] = [
            100: (startTime: 1000, parentPid: 1),
            200: (startTime: 2000, parentPid: 201),
            201: (startTime: 2001, parentPid: 200)
        ]
        let registry = AgentSessionRegistry(
            processInfo: { processTable[$0] },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        registry.add(session)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 200)
        XCTAssertEqual(result, .outsideTree)
    }

    func test_001_AC4_deadRootEndsSessionOnLookup() {
        let recorder = InMemoryAuditRecorder()
        var rootAlive = true
        let session = makeSession(rootPid: 100, rootStartTime: 1000)
        let registry = AgentSessionRegistry(
            processInfo: { pid in
                if pid == 100 && rootAlive {
                    return (startTime: 1000, parentPid: 1)
                }
                return nil
            },
            auditRecorder: recorder,
            watchRootExit: false
        )
        registry.add(session)
        XCTAssertEqual(registry.count, 1)

        rootAlive = false
        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 100)
        XCTAssertEqual(result, .noSession)
        XCTAssertEqual(registry.count, 0)

        XCTAssertTrue(recorder.events.contains { event in
            event.type == .sessionEnd && event.result == .info && event.reason == .rootExited && event.sessionID == session.id && event.keyKind == .agent
        })
    }

    func test_001_T1_rootExitSourceEndsSession() throws {
        let recorder = InMemoryAuditRecorder()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["5"]
        try process.run()
        let pid = process.processIdentifier

        guard let snap = SSHAgentServer.processParentSnapshot(pid: pid) else {
            process.terminate()
            XCTFail("Failed to get process parent snapshot for child")
            return
        }

        let session = makeSession(rootPid: pid, rootStartTime: snap.startTime)
        let registry = AgentSessionRegistry(
            auditRecorder: recorder,
            watchRootExit: true
        )
        registry.add(session)
        XCTAssertEqual(registry.count, 1)

        process.terminate()

        let deadline = Date().addingTimeInterval(2.0)
        while registry.count > 0 && Date() < deadline {
            usleep(20_000)
        }
        XCTAssertEqual(registry.count, 0)
        process.waitUntilExit()

        XCTAssertTrue(recorder.events.contains { event in
            event.type == .sessionEnd && event.reason == .rootExited && event.sessionID == session.id
        })
    }

    func test_001_AC5_screenLockEndsAllSessions() throws {
        let fakeMonitor = FakeSystemEventMonitor()
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let session1 = makeSession(id: "11111111111111111111111111111111", keyLabel: "key-1")
        let session2 = makeSession(id: "22222222222222222222222222222222", keyLabel: "key-2")

        registry.add(session1)
        registry.add(session2)
        XCTAssertEqual(registry.count, 2)

        registry.installSystemEventHandler(monitor: fakeMonitor)
        fakeMonitor.fire(id: "agent.sessions")

        XCTAssertEqual(registry.count, 0)
        let endEvents = auditRecorder.events.filter { $0.type == .sessionEnd && $0.reason == .screenLocked }
        XCTAssertEqual(endEvents.count, 2)
    }

    func test_001_T4_daemonStopEndsAllSessions() throws {
        let pid = getpid()
        let snap = SSHAgentServer.processParentSnapshot(pid: pid)!
        let session = makeSession(keyLabel: "key-stop", rootPid: pid, rootStartTime: snap.startTime)
        AgentSessionRegistry.shared.add(session)
        XCTAssertGreaterThanOrEqual(AgentSessionRegistry.shared.count, 1)

        AgentServers.stopAll()

        XCTAssertEqual(AgentSessionRegistry.shared.count, 0)
    }
}


