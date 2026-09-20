import Foundation

public enum AgentLifecycleError: LocalizedError, Equatable {
    case agentBinaryNotFound
    case agentStartFailed(String)
    case agentStopFailed(String)

    public var errorDescription: String? {
        switch self {
        case .agentBinaryNotFound:
            return "The clavis-agent executable could not be located."
        case .agentStartFailed(let reason):
            return "Failed to start SSH agent daemon: \(reason)"
        case .agentStopFailed(let reason):
            return "Failed to stop SSH agent daemon: \(reason)"
        }
    }
}

public final class AgentLifecycleManager: @unchecked Sendable {
    public static let shared = AgentLifecycleManager()

    public var socketPath: String
    private let lock = NSLock()

    public init(socketPath: String = SSHAgentServer.defaultSocketPath) {
        self.socketPath = socketPath
    }

    public var isAgentRunning: Bool {
        SSHAgentServer.isSocketListening(atPath: socketPath)
    }

    public var agentPID: pid_t? {
        SingleInstanceLock.agent.lockOwnerPID
    }

    public func locateAgentExecutable() -> URL? {
        let fileManager = FileManager.default

        // 1. Check App bundle Contents/Helpers/clavis-agent
        if let bundleURL = Bundle.main.executableURL?.deletingLastPathComponent().deletingLastPathComponent() {
            let helperURL = bundleURL.appendingPathComponent("Helpers/clavis-agent")
            if fileManager.isExecutableFile(atPath: helperURL.path) {
                return helperURL
            }
        }

        // 2. Check sibling to main executable (e.g. .build/release/clavis-agent or Nix $out/bin/clavis-agent)
        if let execURL = Bundle.main.executableURL {
            let siblingURL = execURL.deletingLastPathComponent().appendingPathComponent("clavis-agent")
            if fileManager.isExecutableFile(atPath: siblingURL.path) {
                return siblingURL
            }
        }

        // 3. Check current process arguments directory
        let arg0 = ProcessInfo.processInfo.arguments[0]
        let arg0URL = URL(fileURLWithPath: arg0)
        let arg0Sibling = arg0URL.deletingLastPathComponent().appendingPathComponent("clavis-agent")
        if fileManager.isExecutableFile(atPath: arg0Sibling.path) {
            return arg0Sibling
        }

        // 4. Common system installation paths
        let commonPaths = [
            "/usr/local/bin/clavis-agent",
            "/opt/homebrew/bin/clavis-agent",
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".nix-profile/bin/clavis-agent").path
        ]
        for path in commonPaths {
            if fileManager.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }

        // 5. PATH lookup
        if let envPath = ProcessInfo.processInfo.environment["PATH"] {
            for dir in envPath.split(separator: ":") {
                let candidate = URL(fileURLWithPath: String(dir)).appendingPathComponent("clavis-agent")
                if fileManager.isExecutableFile(atPath: candidate.path) {
                    return candidate
                }
            }
        }

        return nil
    }

    public func ensureAgentRunning() {
        if !isAgentRunning {
            do {
                try startAgent()
            } catch {
                ClavisLogger.log("AGENT_LIFECYCLE", "Failed to auto-start agent: \(error.localizedDescription)")
            }
        }
    }

    public func startAgent() throws {
        lock.lock()
        defer { lock.unlock() }

        if SSHAgentServer.isSocketListening(atPath: socketPath) {
            ClavisLogger.log("AGENT_LIFECYCLE", "Agent is already running on \(socketPath)")
            return
        }

        guard let agentURL = locateAgentExecutable() else {
            throw AgentLifecycleError.agentBinaryNotFound
        }

        // Clean up stale socket file if not listening
        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }

        let process = Process()
        process.executableURL = agentURL
        process.arguments = ["--daemon"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            throw AgentLifecycleError.agentStartFailed(error.localizedDescription)
        }

        // Wait up to 3 seconds for the socket to become responsive
        let deadline = Date().addingTimeInterval(3.0)
        while Date() < deadline {
            if SSHAgentServer.isSocketListening(atPath: socketPath) {
                ClavisLogger.log("AGENT_LIFECYCLE", "Agent successfully started and listening on \(socketPath)")
                return
            }
            usleep(50_000) // 50ms
        }

        if !SSHAgentServer.isSocketListening(atPath: socketPath) {
            throw AgentLifecycleError.agentStartFailed("Agent process launched but socket did not respond within 3 seconds.")
        }
    }

    @discardableResult
    public func stopAgent() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let pid = agentPID ?? SingleInstanceLock.agent.lockOwnerPID else {
            if FileManager.default.fileExists(atPath: socketPath) {
                try? FileManager.default.removeItem(atPath: socketPath)
            }
            return false
        }

        ClavisLogger.log("AGENT_LIFECYCLE", "Stopping agent daemon PID \(pid)")
        kill(pid, SIGTERM)

        // Wait for process to exit and release socket
        let deadline = Date().addingTimeInterval(2.0)
        while Date() < deadline {
            if kill(pid, 0) != 0 {
                break
            }
            usleep(50_000)
        }

        // Force kill if still alive
        if kill(pid, 0) == 0 {
            ClavisLogger.log("AGENT_LIFECYCLE", "Forcefully killing agent daemon PID \(pid)")
            kill(pid, SIGKILL)
            usleep(50_000)
        }

        if FileManager.default.fileExists(atPath: socketPath) {
            try? FileManager.default.removeItem(atPath: socketPath)
        }

        return true
    }

    public func restartAgent() throws {
        _ = stopAgent()
        usleep(100_000) // 100ms
        try startAgent()
    }
}
