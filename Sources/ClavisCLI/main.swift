import Foundation
import ClavisCore

func printOut(_ message: String) {
    if let data = (message + "\n").data(using: .utf8) {
        FileHandle.standardOutput.write(data)
    }
}

func printErr(_ message: String) {
    if let data = (message + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

if let cliResult = CLIService.handle(args: CommandLine.arguments) {
    if !cliResult.output.isEmpty {
        printOut(cliResult.output)
    }
    if let err = cliResult.error, !err.isEmpty {
        printErr(err)
    }
    exit(cliResult.exitCode)
} else {
    let isDaemon = CommandLine.arguments.contains("--daemon") || CommandLine.arguments.contains("daemon")
    if isDaemon {
        if CommandLine.arguments.contains("status") {
            if AgentLifecycleManager.shared.isAgentRunning {
                let pidStr = AgentLifecycleManager.shared.agentPID.map { " (PID \($0))" } ?? ""
                printOut("🟢 Clavis SSH Agent is active at \(SSHAgentServer.defaultSocketPath)\(pidStr)")
                exit(0)
            } else {
                printErr("🔴 Clavis SSH Agent is not running.")
                exit(1)
            }
        } else if CommandLine.arguments.contains("stop") {
            if AgentLifecycleManager.shared.stopAgent() {
                printOut("🛑 Clavis SSH Agent stopped.")
                exit(0)
            } else {
                printOut("ℹ️ Clavis SSH Agent was not running.")
                exit(0)
            }
        } else if CommandLine.arguments.contains("restart") {
            do {
                try AgentLifecycleManager.shared.restartAgent()
                printOut("🔄 Clavis SSH Agent restarted at \(SSHAgentServer.defaultSocketPath)")
                exit(0)
            } catch {
                printErr("Failed to restart SSH agent: \(error.localizedDescription)")
                exit(1)
            }
        } else {
            guard SingleInstanceLock.agent.acquire() else {
                let existingPid = SingleInstanceLock.agent.lockOwnerPID ?? 0
                printErr("Another clavis-agent instance is already running (PID: \(existingPid)).")
                exit(1)
            }
            signal(SIGINT) { _ in
                SSHAgentServer.sharedInstance.stop()
                SingleInstanceLock.agent.release()
                exit(0)
            }
            signal(SIGTERM) { _ in
                SSHAgentServer.sharedInstance.stop()
                SingleInstanceLock.agent.release()
                exit(0)
            }
            signal(SIGHUP, SIG_IGN)
            signal(SIGPIPE, SIG_IGN)
            do {
                try SSHAgentServer.sharedInstance.start()
                printOut("🔑 Clavis SSH Agent socket daemon started at \(SSHAgentServer.defaultSocketPath) (PID: \(getpid()))")
                dispatchMain()
            } catch {
                printErr("Failed to start SSH agent server: \(error.localizedDescription)")
                SingleInstanceLock.agent.release()
                exit(1)
            }
        }
    } else {
        let helpMsg = """
        Clavis — Native macOS Ed25519 Keychain & SSH Agent Daemon

        USAGE:
          clavis-cli generate <label>         Generate a new Ed25519 key pair in Keychain
          clavis-cli import <label> [--stdin]    Import a 32-byte hex seed into Keychain
          clavis-cli list                     List all stored keys and OpenSSH public keys
          clavis-cli export-pub <label>       Print the OpenSSH public key for <label>
          clavis-cli delete <label>           Delete key pair from Keychain
          clavis-cli daemon [status|stop|restart]   Run or manage SSH Agent socket daemon
        """
        printOut(helpMsg)
        exit(0)
    }
}
