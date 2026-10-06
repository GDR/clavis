import Foundation

public enum AgentServers {
    public static func startAll(
        personal: SSHAgentServer = .shared,
        agent: SSHAgentServer = .agentShared
    ) throws {
        try personal.start()
        do {
            try agent.start()
        } catch {
            ClavisLogger.log(
                "SECURITY_ALERT",
                "Failed to start agent socket server at '\(agent.socketPath)': \(error.localizedDescription). Personal socket remains active."
            )
        }
    }

    public static func stopAll(
        personal: SSHAgentServer = .shared,
        agent: SSHAgentServer = .agentShared
    ) {
        agent.stop()
        personal.stop()
    }
}
