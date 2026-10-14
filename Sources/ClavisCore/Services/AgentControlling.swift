import Foundation
import Darwin

/// Protocol abstracting daemon lifecycle management, control requests, and agent session tracking.
public protocol AgentControlling: Sendable {
    var isAgentRunning: Bool { get }
    var agentPID: pid_t? { get }

    func startAgent() throws
    @discardableResult
    func stopAgent() -> Bool
    func restartAgent() throws

    func sendLockAllToAgent() throws
    func queryAgentGitGrace() -> (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)?

    func listAgentSessions() -> [AgentSessionSummary]
    @discardableResult
    func endAgentSession(id: String) -> Bool
    @discardableResult
    func revokeAllAgentSessions() -> Int
    func extendAgentSession(id: String, minutes: Int) -> Date?

    func getAgentPolicy(target: String) -> String?
    func setAgentPolicy(target: String, policyJson: String) -> Bool
}
