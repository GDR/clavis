import Foundation
import Security
import Darwin

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
            return "Failed to control SSH agent: \(reason)"
        }
    }
}

public final class AgentLifecycleManager: @unchecked Sendable {
    public static let shared = AgentLifecycleManager()

    public var socketPath: String
    private let lock = NSLock()
    private let agentPIDProvider: () -> pid_t?
    private let processNameProvider: (pid_t) -> String?
    private let isAlive: (pid_t) -> Bool
    private let sigtermTimeout: TimeInterval

    public init(
        socketPath: String = SSHAgentServer.defaultSocketPath,
        agentPIDProvider: (() -> pid_t?)? = nil,
        processNameProvider: ((pid_t) -> String?)? = nil,
        isAlive: ((pid_t) -> Bool)? = nil,
        sigtermTimeout: TimeInterval = 2.0
    ) {
        self.socketPath = socketPath
        self.agentPIDProvider = agentPIDProvider ?? {
            guard socketPath == SSHAgentServer.defaultSocketPath else { return nil }
            return SingleInstanceLock.agent.lockOwnerPID
        }
        self.processNameProvider = processNameProvider ?? { pid in
            SSHAgentServer.getProcessName(pid: pid)
        }
        self.isAlive = isAlive ?? { Self.isProcessAlive(pid: $0) }
        self.sigtermTimeout = sigtermTimeout
    }

    /// Checks whether a process is alive and not a zombie.
    static func isProcessAlive(pid: pid_t) -> Bool {
        guard kill(pid, 0) == 0 else {
            return false
        }

        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        errno = 0
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        if ret == size {
            // SZOMB (status 5 in <sys/proc.h>) indicates a zombie process that has exited but is not yet reaped.
            return info.pbi_status != 5
        }
        if errno == ESRCH {
            return false
        }
        return kill(pid, 0) == 0
    }

    public var isAgentRunning: Bool {
        SSHAgentServer.isSocketListening(atPath: socketPath)
    }

    public var agentPID: pid_t? {
        agentPIDProvider()
    }

    public func locateAgentExecutable() -> URL? {
        let fileManager = FileManager.default
        let selfExecURL = (Bundle.main.executableURL ?? CommandLine.arguments.first.map { URL(fileURLWithPath: $0) })?.resolvingSymlinksInPath()

        // Production: prefer the bundled helper app so macOS can associate
        // authentication prompts with its name and icon.
        if let bundleURL = selfExecURL?.deletingLastPathComponent().deletingLastPathComponent() {
            let helpersURL = bundleURL.appendingPathComponent("Helpers")
            let helperURLs = [
                helpersURL.appendingPathComponent("Clavis Agent.app/Contents/MacOS/clavis-agent"),
                // Keep compatibility with app bundles created before the helper
                // became a nested application bundle.
                helpersURL.appendingPathComponent("clavis-agent")
            ]
            for helperURL in helperURLs
            where fileManager.isExecutableFile(atPath: helperURL.path) && isTrustedExecutable(helperURL) {
                return helperURL.resolvingSymlinksInPath()
            }
        }

        // Development and non-app packaging must opt in to one explicit path.
        // Never search inherited PATH or common mutable installation locations.
        if let explicitPath = ProcessInfo.processInfo.environment["CLAVIS_AGENT_EXECUTABLE"],
           explicitPath.hasPrefix("/") {
            let candidate = URL(fileURLWithPath: explicitPath).standardizedFileURL
            if fileManager.isExecutableFile(atPath: candidate.path), isTrustedExecutable(candidate) {
                return candidate.resolvingSymlinksInPath()
            }
        }

        // Sibling binary location (e.g. running directly from .build/release or bin directory)
        if let execURL = selfExecURL {
            let sibling = execURL.deletingLastPathComponent().appendingPathComponent("clavis-agent")
            if fileManager.isExecutableFile(atPath: sibling.path), isTrustedExecutable(sibling) {
                return sibling.resolvingSymlinksInPath()
            }
        }

        return nil
    }

    #if DEBUG
    /// Test-only escape hatch. It does not exist in release builds, so nothing in a shipped
    /// binary can switch off agent code-signature verification.
    public static var disableCodeSignatureCheckForTesting = false
    #endif

    private func isTrustedExecutable(_ url: URL) -> Bool {
        let resolved = url.resolvingSymlinksInPath()
        var info = stat()
        guard lstat(resolved.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == 0 || info.st_uid == geteuid(),
              (info.st_mode & 0o022) == 0 else {
            return false
        }

        let parent = resolved.deletingLastPathComponent()
        var parentInfo = stat()
        guard lstat(parent.path, &parentInfo) == 0,
              (parentInfo.st_mode & S_IFMT) == S_IFDIR,
              parentInfo.st_uid == 0 || parentInfo.st_uid == geteuid(),
              (parentInfo.st_mode & 0o022) == 0 else {
            return false
        }

        #if DEBUG
        if Self.disableCodeSignatureCheckForTesting {
            return true
        }
        #endif

        return Self.verifyCodeSignature(of: resolved)
    }

    /// Verifies that the target executable carries a valid code signature and
    /// satisfies the Clavis trust requirement (shared identifier **and** the same
    /// signing team as the running process).
    ///
    /// There is deliberately no identifier-only fallback in release builds: the
    /// identifier is attacker-chosen (`codesign -s - -i Clavis`). When the running
    /// process has no team identifier (unsigned or ad-hoc builds) release builds
    /// fail closed; debug builds may accept a validly signed binary that carries
    /// the shared identifier so local development keeps working.
    public static func verifyCodeSignature(of url: URL) -> Bool {
        #if DEBUG
        let allowIdentifierOnlyDevelopmentFallback = true
        #else
        let allowIdentifierOnlyDevelopmentFallback = false
        #endif
        return verifyCodeSignature(
            of: url,
            requirement: ClavisCodeTrust.requirement,
            allowIdentifierOnlyDevelopmentFallback: allowIdentifierOnlyDevelopmentFallback
        )
    }

    static func verifyCodeSignature(
        of url: URL,
        requirement: SecRequirement?,
        allowIdentifierOnlyDevelopmentFallback: Bool
    ) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let targetCode = staticCode else {
            ClavisLogger.log("AGENT_LIFECYCLE", "Failed to create SecStaticCode for \(url.path)")
            return false
        }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidity(targetCode, flags, nil) == errSecSuccess else {
            ClavisLogger.log("AGENT_LIFECYCLE", "Code signature validity check failed for \(url.path)")
            return false
        }

        if let requirement {
            if SecStaticCodeCheckValidity(targetCode, flags, requirement) == errSecSuccess {
                return true
            }
            // A signing requirement exists and was not met. Never downgrade to a weaker check.
            ClavisLogger.log("SECURITY_ALERT", "Rejected helper \(url.path): does not satisfy the Clavis signing requirement.")
            return false
        }

        if allowIdentifierOnlyDevelopmentFallback,
           ClavisCodeTrust.signingIdentifier(of: targetCode) == ClavisCodeTrust.sharedIdentifier {
            ClavisLogger.log("AGENT_LIFECYCLE", "Development build: accepting \(url.path) on identifier only.")
            return true
        }

        ClavisLogger.log("AGENT_LIFECYCLE", "Code signature identity/requirement mismatch for \(url.path)")
        return false
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

    /// Sends a control packet over the UNIX domain socket and reads the response body.
    /// Sets socket timeouts and SO_NOSIGPIPE to prevent deadlocks and SIGPIPE crashes.
    internal func sendControlRequest(_ payload: Data, timeout: TimeInterval = 3) throws -> Data {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw AgentLifecycleError.agentControlFailed("socket creation failed (errno \(errno))")
        }
        defer { close(sock) }

        var nosigpipe: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout<Int32>.size))

        let sec = Int(timeout)
        let usec = Int32((timeout - Double(sec)) * 1_000_000)
        var tv = timeval(tv_sec: sec, tv_usec: usec)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

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

        var packet = Data()
        var length = UInt32(payload.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { packet.append(contentsOf: $0) }
        packet.append(payload)

        guard writeAll(packet, to: sock) else {
            throw AgentLifecycleError.agentControlFailed("failed to write control request")
        }
        guard let header = readExactly(4, from: sock) else {
            throw AgentLifecycleError.agentControlFailed("failed to read response header")
        }
        var responseLength: UInt32 = 0
        _ = Swift.withUnsafeMutableBytes(of: &responseLength) { header.copyBytes(to: $0) }
        responseLength = UInt32(bigEndian: responseLength)
        guard responseLength <= 65536 else {
            throw AgentLifecycleError.agentControlFailed("response length too large (\(responseLength))")
        }
        guard let response = readExactly(Int(responseLength), from: sock) else {
            throw AgentLifecycleError.agentControlFailed("failed to read response body")
        }
        return response
    }

    /// Synchronously revokes a per-key grant in the running agent. If no agent
    /// socket exists, there can be no remote grant to revoke.
    public func invalidateAgentGrant(label: String) throws {
        guard FileManager.default.fileExists(atPath: socketPath) else { return }

        var payload = Data([SSHAgentServer.invalidateKeyRequest])
        payload.appendWireString(label)

        do {
            let response = try sendControlRequest(payload)
            guard response.count == 1, response.first == 6 else {
                _ = stopAgent()
                throw AgentLifecycleError.agentControlFailed("agent rejected revocation (daemon terminated)")
            }
        } catch let error as AgentLifecycleError {
            _ = stopAgent()
            throw error
        } catch {
            _ = stopAgent()
            throw AgentLifecycleError.agentControlFailed("agent did not acknowledge revocation (daemon terminated): \(error.localizedDescription)")
        }
    }

    /// Queries the running agent daemon for the current active Git signing grant over the secure socket.
    public func queryAgentGitGrace() -> (keyLabel: String, remainingSeconds: Int, remainingOperations: Int)? {
        guard FileManager.default.fileExists(atPath: socketPath) else { return nil }

        let payload = Data([SSHAgentServer.queryGitGraceRequest])
        guard let response = try? sendControlRequest(payload) else { return nil }
        guard response.count > 1, response.first == 6 else { return nil }

        var reader = DataReader(data: Data(response.dropFirst()))
        guard let label = reader.readWireString(),
              let seconds = reader.readUInt32(),
              let operations = reader.readUInt32() else {
            return nil
        }

        if label.isEmpty { return nil }
        return (label, Int(seconds), Int(operations))
    }

    /// Instructs the running agent daemon to purge all cached session secrets and Git grace periods over the secure socket.
    public func sendLockAllToAgent() throws {
        guard FileManager.default.fileExists(atPath: socketPath) else {
            // Missing socket means "no agent running" and is a success only if the agent
            // process is really not running.
            if let pid = agentPID,
               processNameProvider(pid) == "clavis-agent" {
                ClavisLogger.log("SECURITY_ALERT", "Agent socket is missing but agent process \(pid) is still running. Stopping agent.")
                let stopped = stopAgent()
                throw AgentLifecycleError.agentControlFailed("Agent socket is missing while agent process \(pid) was running (stopped: \(stopped))")
            }
            return
        }

        let payload = Data([SSHAgentServer.lockAllRequest])
        do {
            let response = try sendControlRequest(payload)
            guard response.count == 1, response.first == 6 else {
                throw AgentLifecycleError.agentControlFailed("agent rejected lock-all")
            }
        } catch {
            ClavisLogger.log("SECURITY_ALERT", "Lock-all not acknowledged: \(error). Stopping agent.")
            if agentPID != nil {
                if !stopAgent() {
                    throw AgentLifecycleError.agentStopFailed("Failed to stop unresponsive agent after lock-all failure: \(error.localizedDescription)")
                }
            } else {
                _ = stopAgent()
            }
            throw error
        }
    }

    public func registerAgentSession(
        keyLabel: String,
        toolName: String,
        leaseMinutes: Int
    ) throws -> (id: String, leaseSeconds: Int) {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(UInt32(leaseMinutes))

        let response = try sendControlRequest(payload, timeout: 75)
        guard response.first == 6 else {
            throw AgentLifecycleError.agentControlFailed("registration refused")
        }
        var reader = DataReader(data: Data(response.dropFirst()))
        guard let id = reader.readWireString(),
              let lease = reader.readUInt32(),
              reader.isEOF else {
            throw AgentLifecycleError.agentControlFailed("malformed response")
        }
        return (id, Int(lease))
    }

    @discardableResult
    public func endAgentSession(id: String) -> Bool {
        guard FileManager.default.fileExists(atPath: socketPath) else { return false }
        var payload = Data([SSHAgentServer.endAgentSessionRequest])
        payload.appendWireString(id)
        return (try? sendControlRequest(payload))?.first == 6
    }

    public func listAgentSessions() -> [AgentSessionSummary] {
        guard FileManager.default.fileExists(atPath: socketPath),
              let response = try? sendControlRequest(Data([SSHAgentServer.listAgentSessionsRequest])),
              response.first == 6 else { return [] }
        var reader = DataReader(data: Data(response.dropFirst()))
        guard let count = reader.readUInt32() else { return [] }
        var list: [AgentSessionSummary] = []
        for _ in 0..<count {
            guard let id = reader.readWireString(),
                  let label = reader.readWireString(),
                  let fp = reader.readWireString(),
                  let tool = reader.readWireString(),
                  let pid = reader.readUInt32(),
                  let start = reader.readUInt32(),
                  let exp = reader.readUInt32() else { return list }
            list.append(AgentSessionSummary(
                id: id, keyLabel: label, keyFingerprint: fp, toolName: tool,
                rootPid: pid_t(pid),
                startedAt: Date(timeIntervalSince1970: TimeInterval(start)),
                expiresAt: Date(timeIntervalSince1970: TimeInterval(exp))
            ))
        }
        return list
    }

    @discardableResult
    public func revokeAllAgentSessions() -> Int {
        guard FileManager.default.fileExists(atPath: socketPath),
              let response = try? sendControlRequest(Data([SSHAgentServer.revokeAllAgentSessionsRequest])),
              response.first == 6 else { return 0 }
        var reader = DataReader(data: Data(response.dropFirst()))
        return Int(reader.readUInt32() ?? 0)
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

        guard socketPath == SSHAgentServer.defaultSocketPath || agentPID != nil,
              let pid = agentPID ?? SingleInstanceLock.agent.lockOwnerPID else {
            if FileManager.default.fileExists(atPath: socketPath) {
                try? FileManager.default.removeItem(atPath: socketPath)
            }
            return false
        }

        // Verify that the target PID is actually a clavis-agent process before sending any signals
        guard processNameProvider(pid) == "clavis-agent" else {
            ClavisLogger.log("AGENT_LIFECYCLE", "PID \(pid) is not a clavis-agent process; refusing to signal")
            if FileManager.default.fileExists(atPath: socketPath) {
                try? FileManager.default.removeItem(atPath: socketPath)
            }
            return false
        }

        ClavisLogger.log("AGENT_LIFECYCLE", "Stopping agent daemon PID \(pid)")
        kill(pid, SIGTERM)

        // Wait for process to exit and release socket
        let deadline = Date().addingTimeInterval(sigtermTimeout)
        while Date() < deadline {
            if !isAlive(pid) {
                break
            }
            usleep(50_000)
        }

        // Force kill if still alive and verified as clavis-agent
        if isAlive(pid), processNameProvider(pid) == "clavis-agent" {
            ClavisLogger.log("AGENT_LIFECYCLE", "Forcefully killing agent daemon PID \(pid)")
            kill(pid, SIGKILL)
            usleep(50_000)

            // Poll for up to ~500 ms for process to exit after SIGKILL
            let killDeadline = Date().addingTimeInterval(0.5)
            while Date() < killDeadline {
                if !isAlive(pid) {
                    break
                }
                usleep(50_000)
            }
        }

        // If the pid is still alive (or same pid with process name == "clavis-agent"):
        // do not remove the socket file, log a security alert, and return false.
        if isAlive(pid) && (processNameProvider(pid) == "clavis-agent" || processNameProvider(pid) == nil) {
            ClavisLogger.log("SECURITY_ALERT", "Failed to terminate agent daemon PID \(pid); process survived SIGKILL")
            return false
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
