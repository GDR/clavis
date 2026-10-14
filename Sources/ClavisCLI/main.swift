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

func installTerminationSignalSources(cleanup: @escaping () -> Void) -> [DispatchSourceSignal] {
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
            cleanup()
            exit(0)
        }
        source.resume()
        return source
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
            guard SingleInstanceLock.agent.acquire() else {
                let existingPid = SingleInstanceLock.agent.lockOwnerPID ?? 0
                printErr(CLIMessages.Agent.alreadyRunning(pid: existingPid))
                exit(1)
            }
            let resealer = AuditResealer()
            let terminationSignalSources = installTerminationSignalSources {
                resealer.stop()
                AgentServers.stopAll()
                AuditRecorder.shared.flush()
                SingleInstanceLock.agent.release()
            }
            do {
                try AgentServers.startAll()
                resealer.start()
                printOut(CLIMessages.Agent.daemonStarted(socketPath: SSHAgentServer.defaultSocketPath, pid: getpid()))
                _ = SystemEventMonitor.shared
                SystemEventMonitor.shared.addHandler(id: "audit.lock") {
                    AuditRecorder.shared.record(AuditEvent(type: .lock, result: .info, reason: .screenLocked))
                }
                AgentSessionRegistry.shared.installSystemEventHandler()
                withExtendedLifetime(terminationSignalSources) {
                    dispatchMain()
                }
            } catch {
                printErr("Failed to start SSH agent server: \(error.localizedDescription)")
                SingleInstanceLock.agent.release()
                exit(1)
            }
        }
    } else {
        printOut(CLIMessages.help)
        exit(0)
    }
}
