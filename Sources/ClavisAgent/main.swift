import Foundation
import ClavisCore

// Setup signal handling for graceful shutdown
func setupSignalHandlers() {
    signal(SIGINT) { _ in
        ClavisLogger.log("AGENT_DAEMON", "Received SIGINT, terminating...")
        SSHAgentServer.sharedInstance.stop()
        SingleInstanceLock.agent.release()
        exit(0)
    }
    signal(SIGTERM) { _ in
        ClavisLogger.log("AGENT_DAEMON", "Received SIGTERM, terminating...")
        SSHAgentServer.sharedInstance.stop()
        SingleInstanceLock.agent.release()
        exit(0)
    }
    signal(SIGHUP, SIG_IGN) // Ignore SIGHUP so closing parent terminal/GUI doesn't kill the agent
    signal(SIGPIPE, SIG_IGN)
}

// Detach from parent session if running as daemon
if CommandLine.arguments.contains("--daemon") {
    setsid()
}

guard SingleInstanceLock.agent.acquire() else {
    let existingPid = SingleInstanceLock.agent.lockOwnerPID ?? 0
    ClavisLogger.log("AGENT_DAEMON", "Another clavis-agent instance is already running (PID: \(existingPid)). Exiting.")
    exit(0)
}

setupSignalHandlers()

do {
    try SSHAgentServer.sharedInstance.start()
    ClavisLogger.log("AGENT_DAEMON", "🔑 Clavis SSH Agent daemon active at \(SSHAgentServer.defaultSocketPath) (PID: \(getpid()))")
    dispatchMain()
} catch {
    ClavisLogger.log("AGENT_DAEMON", "Failed to start SSH agent server: \(error.localizedDescription)")
    SingleInstanceLock.agent.release()
    exit(1)
}
