import Foundation

public enum AgentLifecycleError: LocalizedError, Equatable {
    case agentBinaryNotFound
    case agentStartFailed(String)
    case agentStopFailed(String)
    case agentControlFailed(String)

    public var errorDescription: String? {
        switch self {
        case .agentBinaryNotFound:
            return "The clavis-agent executable could not be located."
        case .agentStartFailed(let reason):
            return "Failed to start SSH agent daemon: \(reason)"
        case .agentStopFailed(let reason):
            return "Failed to stop SSH agent daemon: \(reason)"
        case .agentControlFailed(let reason):
            return "Failed to revoke the SSH agent grant: \(reason)"
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

        // Production: only the helper at the fixed app-bundle location is eligible.
        if let bundleURL = Bundle.main.executableURL?.deletingLastPathComponent().deletingLastPathComponent() {
            let helperURL = bundleURL.appendingPathComponent("Helpers/clavis-agent")
            if fileManager.isExecutableFile(atPath: helperURL.path), isTrustedExecutable(helperURL) {
                return helperURL
            }
        }

        // Development and non-app packaging must opt in to one explicit path.
        // Never search inherited PATH or common mutable installation locations.
        if let explicitPath = ProcessInfo.processInfo.environment["CLAVIS_AGENT_EXECUTABLE"],
           explicitPath.hasPrefix("/") {
            let candidate = URL(fileURLWithPath: explicitPath).standardizedFileURL
            if fileManager.isExecutableFile(atPath: candidate.path), isTrustedExecutable(candidate) {
                return candidate
            }
        }

        return nil
    }

    private func isTrustedExecutable(_ url: URL) -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == 0 || info.st_uid == geteuid(),
              (info.st_mode & 0o022) == 0 else {
            return false
        }

        let parent = url.deletingLastPathComponent()
        var parentInfo = stat()
        guard lstat(parent.path, &parentInfo) == 0,
              (parentInfo.st_mode & S_IFMT) == S_IFDIR,
              parentInfo.st_uid == 0 || parentInfo.st_uid == geteuid(),
              (parentInfo.st_mode & 0o022) == 0 else {
            return false
        }
        return true
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

    /// Synchronously revokes a per-key grant in the running agent. If no agent
    /// socket exists, there can be no remote grant to revoke.
    public func invalidateAgentGrant(label: String) throws {
        guard FileManager.default.fileExists(atPath: socketPath) else { return }
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw AgentLifecycleError.agentControlFailed("socket creation failed (errno \(errno))")
        }
        defer { close(sock) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            throw AgentLifecycleError.agentControlFailed("socket path is too long")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (index, byte) in pathBytes.enumerated() { raw[index] = byte }
        }
        let addrLength = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, addrLength)
            }
        }
        guard connected == 0 else {
            throw AgentLifecycleError.agentControlFailed("connection failed (errno \(errno))")
        }

        var payload = Data([SSHAgentServer.invalidateKeyRequest])
        payload.appendWireString(label)
        var packet = Data()
        var length = UInt32(payload.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { packet.append(contentsOf: $0) }
        packet.append(payload)

        guard writeAll(packet, to: sock),
              let header = readExactly(4, from: sock) else {
            throw AgentLifecycleError.agentControlFailed("agent did not acknowledge revocation")
        }
        var responseLength: UInt32 = 0
        _ = Swift.withUnsafeMutableBytes(of: &responseLength) { header.copyBytes(to: $0) }
        responseLength = UInt32(bigEndian: responseLength)
        guard responseLength == 1,
              let response = readExactly(1, from: sock),
              response.first == 6 else {
            throw AgentLifecycleError.agentControlFailed("agent rejected revocation")
        }
    }

    private func writeAll(_ data: Data, to fd: Int32) -> Bool {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return false }
            var written = 0
            while written < raw.count {
                let result = write(fd, base.advanced(by: written), raw.count - written)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { return false }
                written += result
            }
            return true
        }
    }

    private func readExactly(_ count: Int, from fd: Int32) -> Data? {
        var data = Data(count: count)
        let success = data.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var readCount = 0
            while readCount < count {
                let result = read(fd, base.advanced(by: readCount), count - readCount)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { return false }
                readCount += result
            }
            return true
        }
        return success ? data : nil
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
