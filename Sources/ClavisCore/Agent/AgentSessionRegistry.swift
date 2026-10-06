import Foundation

public enum AgentSessionLookup: Equatable {
    case found(AgentSession)
    case noSession
    case outsideTree
    case expired(AgentSession)
}

public final class AgentSessionRegistry: @unchecked Sendable {
    public static let shared = AgentSessionRegistry()

    public typealias ProcessInfoProvider = (pid_t) -> (startTime: UInt64, parentPid: pid_t)?

    private let lock = NSLock()
    private var sessions: [String: AgentSession] = [:]
    private let now: () -> Date
    private let processInfo: ProcessInfoProvider
    private let auditRecorder: AuditRecording
    private let watchRootExit: Bool

    public init(
        now: @escaping () -> Date = Date.init,
        processInfo: ProcessInfoProvider? = nil,
        auditRecorder: AuditRecording = AuditRecorder.shared,
        watchRootExit: Bool = true
    ) {
        self.now = now
        self.processInfo = processInfo ?? {
            SSHAgentServer.processParentSnapshot(pid: $0).map { ($0.startTime, $0.parentPid) }
        }
        self.auditRecorder = auditRecorder
        self.watchRootExit = watchRootExit
    }

    public func add(_ session: AgentSession) {
        lock.lock()
        defer { lock.unlock() }
        sessions[session.id] = session
    }

    public func session(forKeyFingerprint fp: String, peerPid: pid_t) -> AgentSessionLookup {
        lock.lock()
        defer { lock.unlock() }

        let candidates = sessions.values.filter { $0.keyFingerprint == fp }
        guard !candidates.isEmpty else {
            return .noSession
        }

        var aliveCandidates: [AgentSession] = []
        var expiredCandidates: [AgentSession] = []
        let currentTime = now()

        for candidate in candidates {
            // Liveness check: root must still be alive and have matching startTime
            guard let snap = processInfo(candidate.root.pid), snap.startTime == candidate.root.startTime else {
                endInternal(id: candidate.id, reason: .rootExited)
                continue
            }

            // Expiry check
            if currentTime >= candidate.expiresAt {
                endInternal(id: candidate.id, reason: .leaseExpired)
                expiredCandidates.append(candidate)
                continue
            }

            aliveCandidates.append(candidate)
        }

        // Check if peer is member of any alive candidate's process tree
        for candidate in aliveCandidates {
            if isProcessInTree(peerPid: peerPid, root: candidate.root) {
                return .found(candidate)
            }
        }

        if let firstExpired = expiredCandidates.first {
            return .expired(firstExpired)
        }

        if aliveCandidates.isEmpty {
            return .noSession
        }

        return .outsideTree
    }

    private func isProcessInTree(peerPid: pid_t, root: AgentSessionRoot) -> Bool {
        var currentPid = peerPid
        var hops = 0
        var visited = Set<pid_t>()

        while currentPid > 1 && hops < 64 {
            guard visited.insert(currentPid).inserted else {
                // Cycle detected
                break
            }
            guard let snap = processInfo(currentPid) else {
                break
            }
            if currentPid == root.pid && snap.startTime == root.startTime {
                return true
            }
            if snap.parentPid == currentPid {
                break
            }
            currentPid = snap.parentPid
            hops += 1
        }

        return false
    }

    @discardableResult
    public func end(id: String, reason: AgentSessionEndReason) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return endInternal(id: id, reason: reason)
    }

    @discardableResult
    private func endInternal(id: String, reason: AgentSessionEndReason) -> Bool {
        guard let session = sessions.removeValue(forKey: id) else {
            return false
        }
        session.grant.invalidate()
        return true
    }

    @discardableResult
    public func endAll(reason: AgentSessionEndReason) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let ids = Array(sessions.keys)
        var count = 0
        for id in ids {
            if endInternal(id: id, reason: reason) {
                count += 1
            }
        }
        return count
    }

    @discardableResult
    public func endAll(keyLabel: String, reason: AgentSessionEndReason) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let matchingIds = sessions.values.filter { $0.keyLabel == keyLabel }.map { $0.id }
        var count = 0
        for id in matchingIds {
            if endInternal(id: id, reason: reason) {
                count += 1
            }
        }
        return count
    }

    public func summaries() -> [AgentSessionSummary] {
        lock.lock()
        defer { lock.unlock() }
        return sessions.values.map { $0.summary }.sorted { $0.startedAt < $1.startedAt }
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return sessions.count
    }
}
