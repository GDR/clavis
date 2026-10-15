import Foundation
import Darwin
import ClavisCore

public final class MockAgentController: AgentControlling, @unchecked Sendable {
    private let lock = NSLock()

    // Configuration / State
    public var stubbedIsAgentRunning: Bool = false
    public var stubbedAgentPID: pid_t? = nil
    public var stubbedSessions: [AgentSessionSummary] = []
    public var stubbedPolicies: [String: String] = [:]
    public var stubbedGitGrace: (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? = nil

    // Error injection / return overrides
    public var startAgentError: Error? = nil
    public var stopAgentResult: Bool = true
    public var restartAgentError: Error? = nil
    public var sendLockAllError: Error? = nil

    // Call tracking
    public var startAgentCallCount = 0
    public var stopAgentCallCount = 0
    public var restartAgentCallCount = 0
    public var sendLockAllCallCount = 0
    public var queryAgentGitGraceCallCount = 0
    public var listAgentSessionsCallCount = 0
    public var endAgentSessionCallCount = 0
    public var revokeAllAgentSessionsCallCount = 0
    public var extendAgentSessionCallCount = 0
    public var getAgentPolicyCallCount = 0
    public var setAgentPolicyCallCount = 0

    public var recordedEndSessionIDs: [String] = []
    public var recordedExtendCalls: [(id: String, minutes: Int)] = []
    public var recordedSetPolicies: [(target: String, json: String)] = []

    public init(
        isRunning: Bool = false,
        pid: pid_t? = nil,
        sessions: [AgentSessionSummary] = [],
        gitGrace: (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? = nil
    ) {
        self.stubbedIsAgentRunning = isRunning
        self.stubbedAgentPID = pid
        self.stubbedSessions = sessions
        self.stubbedGitGrace = gitGrace
    }

    public var isAgentRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stubbedIsAgentRunning
    }

    public var agentPID: pid_t? {
        lock.lock()
        defer { lock.unlock() }
        return stubbedAgentPID
    }

    public func startAgent() throws {
        lock.lock()
        startAgentCallCount += 1
        let err = startAgentError
        if err == nil {
            stubbedIsAgentRunning = true
            if stubbedAgentPID == nil {
                stubbedAgentPID = 12345
            }
        }
        lock.unlock()
        if let err { throw err }
    }

    @discardableResult
    public func stopAgent() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        stopAgentCallCount += 1
        if stopAgentResult {
            stubbedIsAgentRunning = false
            stubbedAgentPID = nil
        }
        return stopAgentResult
    }

    public func restartAgent() throws {
        lock.lock()
        restartAgentCallCount += 1
        let err = restartAgentError
        if err == nil {
            stubbedIsAgentRunning = true
            stubbedAgentPID = 12346
        }
        lock.unlock()
        if let err { throw err }
    }

    public func sendLockAllToAgent() throws {
        lock.lock()
        sendLockAllCallCount += 1
        let err = sendLockAllError
        lock.unlock()
        if let err { throw err }
    }

    public func queryAgentGitGrace() -> (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? {
        lock.lock()
        defer { lock.unlock() }
        queryAgentGitGraceCallCount += 1
        return stubbedGitGrace
    }

    public func listAgentSessions() -> [AgentSessionSummary] {
        lock.lock()
        defer { lock.unlock() }
        listAgentSessionsCallCount += 1
        return stubbedSessions
    }

    @discardableResult
    public func endAgentSession(id: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        endAgentSessionCallCount += 1
        recordedEndSessionIDs.append(id)
        let initialCount = stubbedSessions.count
        stubbedSessions.removeAll { $0.id == id }
        return stubbedSessions.count < initialCount
    }

    @discardableResult
    public func revokeAllAgentSessions() -> Int {
        lock.lock()
        defer { lock.unlock() }
        revokeAllAgentSessionsCallCount += 1
        let count = stubbedSessions.count
        stubbedSessions.removeAll()
        return count
    }

    public func extendAgentSession(id: String, minutes: Int) -> Date? {
        lock.lock()
        defer { lock.unlock() }
        extendAgentSessionCallCount += 1
        recordedExtendCalls.append((id: id, minutes: minutes))
        guard let idx = stubbedSessions.firstIndex(where: { $0.id == id }) else { return nil }
        let current = stubbedSessions[idx]
        let newExpiry = current.expiresAt.addingTimeInterval(TimeInterval(minutes * 60))
        stubbedSessions[idx] = AgentSessionSummary(
            id: current.id,
            keyLabel: current.keyLabel,
            keyFingerprint: current.keyFingerprint,
            toolName: current.toolName,
            rootPid: current.rootPid,
            startedAt: current.startedAt,
            expiresAt: newExpiry
        )
        return newExpiry
    }

    public func getAgentPolicy(target: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        getAgentPolicyCallCount += 1
        return stubbedPolicies[target]
    }

    public func setAgentPolicy(target: String, policyJson: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        setAgentPolicyCallCount += 1
        recordedSetPolicies.append((target: target, json: policyJson))
        stubbedPolicies[target] = policyJson
        return true
    }
}
