import Foundation
import Combine
import ClavisCore

/// Presentation follows acknowledged daemon policy, never a local pause preference.
@MainActor
public final class RequestPauseModel: ObservableObject {
    public enum State: Equatable { case unknown, accepting, paused }
    @Published public private(set) var state: State = .unknown
    @Published public private(set) var isBusy = false
    @Published public private(set) var errorMessage: String?
    private let agent: any AgentControlling

    public init(agent: any AgentControlling) { self.agent = agent }
    public var isPaused: Bool { state == .paused }
    public var status: String {
        switch state {
        case .unknown: return "Agent status unavailable"
        case .accepting: return "Agent active"
        case .paused: return "Requests paused"
        }
    }

    public func refresh() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        let agent = agent
        let snapshot = await Task.detached { agent.applicationRegistry() }.value
        apply(snapshot)
    }

    /// Pause revokes approvals immediately; resume requires daemon-side fresh authentication.
    /// Neither path invents a successful state when the control service is unavailable.
    @discardableResult
    public func setPaused(_ paused: Bool) async -> Bool {
        guard !isBusy else { return false }
        if state == (paused ? .paused : .accepting) { return true }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        let agent = agent
        let result = await Task.detached {
            let accepted = agent.changeApplicationPolicy(paused ? .pause : .resume)
            return (accepted, agent.applicationRegistry())
        }.value
        apply(result.1)
        guard result.0 else {
            errorMessage = "The request policy change was not confirmed. Check the agent and try again."
            return false
        }
        guard let snapshot = result.1, snapshot.isPaused == paused else {
            errorMessage = "The agent accepted the change, but its current request policy could not be confirmed."
            return false
        }
        return true
    }

    private func apply(_ snapshot: ApplicationRegistrySnapshot?) {
        guard let snapshot else {
            state = .unknown
            return
        }
        state = snapshot.isPaused ? .paused : .accepting
    }
}
