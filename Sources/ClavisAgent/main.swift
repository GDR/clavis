import Foundation
import ClavisCore

// POSIX handlers only suppress default delivery. Cleanup runs later on the
// main dispatch queue, where locking, Foundation, and logging are safe.
func setupSignalHandlers() -> [DispatchSourceSignal] {
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    signal(SIGHUP, SIG_IGN)
    signal(SIGPIPE, SIG_IGN)

    var isTerminating = false
    return [SIGINT, SIGTERM].map { signalNumber in
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
        source.setEventHandler {
            guard !isTerminating else { return }
            isTerminating = true
            ClavisLogger.log(.agentDaemon, "Received signal \(signalNumber), terminating...")
            SSHAgentServer.sharedInstance.stop()
            SingleInstanceLock.agent.release()
            exit(0)
        }
        source.resume()
        return source
    }
}

// Detach from parent session if running as daemon
if CommandLine.arguments.contains("--daemon") {
    setsid()
}

guard SingleInstanceLock.agent.acquire() else {
    let existingPid = SingleInstanceLock.agent.lockOwnerPID ?? 0
    ClavisLogger.log(.agentDaemon, "Another clavis-agent instance is already running (PID: \(existingPid)). Exiting.")
    exit(0)
}

let terminationSignalSources = setupSignalHandlers()

do {
    try SSHAgentServer.sharedInstance.start()
    ClavisLogger.log(.agentDaemon, "🔑 Clavis SSH Agent daemon active at \(SSHAgentServer.defaultSocketPath) (PID: \(getpid()))")
    _ = SystemEventMonitor.shared
    withExtendedLifetime(terminationSignalSources) {
        RunLoop.main.run()
    }
} catch {
    ClavisLogger.log(.agentDaemon, "Failed to start SSH agent server: \(error.localizedDescription)")
    SingleInstanceLock.agent.release()
    exit(1)
}
