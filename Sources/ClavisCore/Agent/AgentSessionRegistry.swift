import Foundation

public enum AgentSessionLookup: Equatable {
    case found(AgentSession)
    case noSession
    case outsideTree
    case expired(AgentSession)
}

public final class AgentSessionRegistry: @unchecked Sendable {
    public static let shared = AgentSessionRegistry()
    public static let agentSessionsChangedNotification = NSNotification.Name("com.clavis.agentSessionsChanged")

    public typealias ProcessInfoProvider = (pid_t) -> (startTime: UInt64, parentPid: pid_t)?

    private let lock = NSLock()
    private var sessions: [String: AgentSession] = [:]
    private var exitSources: [String: DispatchSourceProcess] = [:]
    private let exitQueue = DispatchQueue(label: "com.clavis.agent.session.exit", qos: .utility)
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
        sessions[session.id] = session

        guard let snap = processInfo(session.root.pid), snap.startTime == session.root.startTime else {
            let ended = removeSessionLocked(id: session.id)
            lock.unlock()
            if let ended {
                recordAudit(session: ended, reason: .rootExited)
                postNotification()
            }
            return
        }

        if watchRootExit {
            let source = DispatchSource.makeProcessSource(identifier: session.root.pid, eventMask: .exit, queue: exitQueue)
            source.setEventHandler { [weak self] in
                self?.end(id: session.id, reason: .rootExited)
            }
            exitSources[session.id] = source
            source.resume()
        }
        lock.unlock()
        postNotification()
    }

    public func session(forKeyFingerprint fp: String, peerPid: pid_t) -> AgentSessionLookup {
        var endedSessions: [(AgentSession, AgentSessionEndReason)] = []
        lock.lock()

        let candidates = sessions.values.filter { $0.keyFingerprint == fp }
        guard !candidates.isEmpty else {
            lock.unlock()
            return .noSession
        }

        var aliveCandidates: [AgentSession] = []
        var expiredCandidates: [AgentSession] = []
        let currentTime = now()

        for candidate in candidates {
            guard let snap = processInfo(candidate.root.pid), snap.startTime == candidate.root.startTime else {
                if let ended = removeSessionLocked(id: candidate.id) {
                    endedSessions.append((ended, .rootExited))
                }
                continue
            }

            if currentTime >= candidate.expiresAt {
                if let ended = removeSessionLocked(id: candidate.id) {
                    endedSessions.append((ended, .leaseExpired))
                }
                expiredCandidates.append(candidate)
                continue
            }

            aliveCandidates.append(candidate)
        }

        for candidate in aliveCandidates {
            if isProcessInTree(peerPid: peerPid, root: candidate.root) {
                lock.unlock()
                recordAudits(endedSessions)
                return .found(candidate)
            }
        }

        lock.unlock()
        recordAudits(endedSessions)

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
        let session = removeSessionLocked(id: id)
        lock.unlock()
        guard let ended = session else { return false }
        recordAudit(session: ended, reason: reason)
        postNotification()
        return true
    }

    @discardableResult
    public func endAll(reason: AgentSessionEndReason) -> Int {
        lock.lock()
        let ids = Array(sessions.keys)
        var endedSessions: [AgentSession] = []
        for id in ids {
            if let s = removeSessionLocked(id: id) {
                endedSessions.append(s)
            }
        }
        lock.unlock()
        for s in endedSessions {
            recordAudit(session: s, reason: reason)
        }
        if !endedSessions.isEmpty {
            postNotification()
        }
        return endedSessions.count
    }

    @discardableResult
    public func endAll(keyLabel: String, reason: AgentSessionEndReason) -> Int {
        lock.lock()
        let matchingIds = sessions.values.filter { $0.keyLabel == keyLabel }.map { $0.id }
        var endedSessions: [AgentSession] = []
        for id in matchingIds {
            if let s = removeSessionLocked(id: id) {
                endedSessions.append(s)
            }
        }
        lock.unlock()
        for s in endedSessions {
            recordAudit(session: s, reason: reason)
        }
        if !endedSessions.isEmpty {
            postNotification()
        }
        return endedSessions.count
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

    private func removeSessionLocked(id: String) -> AgentSession? {
        guard let session = sessions.removeValue(forKey: id) else {
            return nil
        }
        if let source = exitSources.removeValue(forKey: id) {
            source.cancel()
        }
        session.grant.invalidate()
        return session
    }

    private func recordAudit(session: AgentSession, reason: AgentSessionEndReason) {
        let event = AuditEvent(
            type: reason == .revokedByUser ? .sessionRevoke : .sessionEnd,
            result: .info,
            reason: reason.auditReason,
            keyFingerprint: session.keyFingerprint,
            keyKind: .agent,
            sessionID: session.id,
            sensitive: AuditSensitive(keyLabel: session.keyLabel)
        )
        auditRecorder.record(event)
    }

    private func recordAudits(_ sessions: [(AgentSession, AgentSessionEndReason)]) {
        for (session, reason) in sessions {
            recordAudit(session: session, reason: reason)
        }
        if !sessions.isEmpty {
            postNotification()
        }
    }

    private func postNotification() {
        DistributedNotificationCenter.default().postNotificationName(
            Self.agentSessionsChangedNotification,
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
    }
}
