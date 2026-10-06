import XCTest
@testable import ClavisCore

final class AgentSessionRegistryTests: ClavisBaseTestCase {
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
                    // 1st call is candidate root liveness check (startTime: 1000 matches)
                    // 2nd call is during tree walk from peer 300 (startTime: 9999 does not match)
                    return callCountFor100 == 1 ? (startTime: 1000, parentPid: 1) : (startTime: 9999, parentPid: 1)
                }
                if pid == 300 {
                    return (startTime: 3000, parentPid: 100)
                }
                return nil
            },
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
            watchRootExit: false
        )
        registry.add(session)

        let result = registry.session(forKeyFingerprint: session.keyFingerprint, peerPid: 200)
        XCTAssertEqual(result, .outsideTree)
    }
}
