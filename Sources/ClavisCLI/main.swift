import Foundation
import ClavisCore

guard PlatformSupport.hasSecureEnclave else {
    FileHandle.standardError.write(Data((PlatformSupport.unsupportedMessage + "\n").utf8))
    exit(1)
}

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

if let cliResult = CLIService.handleSocketOnly(args: CommandLine.arguments) {
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
                printOut(CLIMessages.Agent.active(socketPath: SSHAgentServer.defaultSocketPath, pid: AgentLifecycleManager.shared.agentPID))
                exit(0)
            } else {
                printErr(CLIMessages.Agent.notRunning)
                exit(1)
            }
        } else if CommandLine.arguments.contains("stop") {
            if AgentLifecycleManager.shared.stopAgent() {
                printOut(CLIMessages.Agent.stopped)
                exit(0)
            } else {
                printOut(CLIMessages.Agent.notRunningInfo)
                exit(0)
            }
        } else if CommandLine.arguments.contains("restart") {
            do {
                try AgentLifecycleManager.shared.restartAgent()
                printOut(CLIMessages.Agent.restarted(socketPath: SSHAgentServer.defaultSocketPath))
                exit(0)
            } catch {
                printErr("Failed to restart SSH agent: \(error.localizedDescription)")
                exit(1)
            }
        } else {
            if AgentLifecycleManager.shared.isAgentRunning {
                let existingPid = AgentLifecycleManager.shared.agentPID ?? 0
                printOut(CLIMessages.Agent.alreadyRunning(pid: existingPid))
                exit(0)
            }
            do {
                try AgentLifecycleManager.shared.startAgent()
                let startedPid = AgentLifecycleManager.shared.agentPID ?? 0
                printOut(CLIMessages.Agent.daemonStarted(socketPath: SSHAgentServer.defaultSocketPath, pid: startedPid))
                exit(0)
            } catch {
                printErr("Failed to start SSH agent server: \(error.localizedDescription)")
                exit(1)
            }
        }
    } else {
        printOut(CLIMessages.help)
        exit(0)
    }
}
