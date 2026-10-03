import Foundation
import Network
import Darwin

public enum SSHAgentServerError: LocalizedError, Equatable {
    case socketAlreadyInUse(String)
    case socketCreationFailed(Int32)
    case socketBindFailed(String, Int32)
    case socketListenFailed(Int32)
    case socketOptionFailed(Int32)
    case unsafeSocketPath(String)
    case socketPermissionFailed(String, Int32)
    case pathTooLong(String)

    public var errorDescription: String? {
        switch self {
        case .socketAlreadyInUse(let path):
            return "Another SSH agent is actively listening on socket at \(path)"
        case .socketCreationFailed(let code):
            return "Failed to create socket (errno: \(code))"
        case .socketBindFailed(let path, let code):
            return "Failed to bind socket at \(path) (errno: \(code))"
        case .socketListenFailed(let code):
            return "Failed to listen on socket (errno: \(code))"
        case .socketOptionFailed(let code):
            return "Failed to configure socket security options (errno: \(code))"
        case .unsafeSocketPath(let path):
            return "Refusing unsafe SSH agent socket path: \(path)"
        case .socketPermissionFailed(let path, let code):
            return "Failed to enforce SSH agent socket permissions at \(path) (errno: \(code))"
        case .pathTooLong(let path):
            return "Socket path is too long: \(path)"
        }
    }
}

public class SSHAgentServer {
    internal static let invalidateKeyRequest: UInt8 = 240
    internal static let queryGitGraceRequest: UInt8 = 241
    internal static let lockAllRequest: UInt8 = 242
    public static let shared = SSHAgentServer()
    public static let sharedInstance = shared
    public static let defaultSocketPath = NSString(string: "~/.ssh/clavis.sock").expandingTildeInPath

    public let socketPath: String
    private let maxConcurrentClients: Int
    private let maxConcurrentClientsPerPID: Int
    private let clientIdleTimeout: TimeInterval
    private let handshakeTimeout: TimeInterval
    private let keyManager: KeychainManager
    private let controlPeerValidator: (Int32) -> Bool
    private let promptGate: SigningPromptGate
    private let stateLock = NSLock()
    private var _serverSocket: Int32 = -1
    private var _isRunning = false
    private var _activeClientCount = 0
    private var _clientPIDCounts: [pid_t: Int] = [:]
    private let queue = DispatchQueue(label: "com.clavis.ssh-agent", attributes: .concurrent)

    public init(
        socketPath: String = SSHAgentServer.defaultSocketPath,
        maxConcurrentClients: Int = 32,
        maxConcurrentClientsPerPID: Int = 8,
        clientIdleTimeout: TimeInterval = 30,
        handshakeTimeout: TimeInterval = 2.0,
        keyManager: KeychainManager = .shared,
        promptGate: SigningPromptGate = SigningPromptGate(),
        controlPeerValidator: ((Int32) -> Bool)? = nil
    ) {
        self.promptGate = promptGate
        self.controlPeerValidator = controlPeerValidator ?? { ClavisCodeTrust.isTrustedPeer(socket: $0) }
        self.socketPath = socketPath
        self.maxConcurrentClients = max(1, maxConcurrentClients)
        self.maxConcurrentClientsPerPID = max(1, maxConcurrentClientsPerPID)
        self.clientIdleTimeout = max(0.1, clientIdleTimeout)
        self.handshakeTimeout = max(0.05, min(clientIdleTimeout, handshakeTimeout))
        self.keyManager = keyManager
    }

    /// Tests whether an active SSH agent server is listening on the given AF_UNIX socket.
    public static func isSocketListening(atPath path: String = defaultSocketPath) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = path.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { return false }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() {
                raw[i] = byte
            }
        }

        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let res = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, addrLen)
            }
        }
        return res == 0
    }

    private var isRunning: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _isRunning
        }
        set {
            stateLock.lock()
            _isRunning = newValue
            stateLock.unlock()
        }
    }

    private var serverSocket: Int32 {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _serverSocket
        }
        set {
            stateLock.lock()
            _serverSocket = newValue
            stateLock.unlock()
        }
    }

    public func start() throws {
        // Prevent clobbering an actively listening server
        if Self.isSocketListening(atPath: socketPath) {
            ClavisLogger.log("SSH_AGENT", "Refusing to start: socket at \(socketPath) is actively listening.")
            throw SSHAgentServerError.socketAlreadyInUse(socketPath)
        }

        let fileManager = FileManager.default
        let dir = (socketPath as NSString).deletingLastPathComponent
        if !fileManager.fileExists(atPath: dir) {
            try fileManager.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        guard chmod(dir, 0o700) == 0, isSecureDirectory(dir) else {
            throw SSHAgentServerError.socketPermissionFailed(dir, errno)
        }

        var existing = stat()
        if lstat(socketPath, &existing) == 0 {
            guard (existing.st_mode & S_IFMT) == S_IFSOCK, existing.st_uid == geteuid() else {
                throw SSHAgentServerError.unsafeSocketPath(socketPath)
            }
            guard unlink(socketPath) == 0 else {
                throw SSHAgentServerError.socketPermissionFailed(socketPath, errno)
            }
        } else if errno != ENOENT {
            throw SSHAgentServerError.unsafeSocketPath(socketPath)
        }

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw SSHAgentServerError.socketCreationFailed(errno)
        }
        var didStart = false
        defer {
            if !didStart {
                close(sock)
                serverSocket = -1
                _ = unlink(socketPath)
            }
        }

        var nosigpipe = 1
        guard setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe))) == 0 else {
            throw SSHAgentServerError.socketOptionFailed(errno)
        }

        self.serverSocket = sock

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            throw SSHAgentServerError.pathTooLong(socketPath)
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() {
                raw[i] = byte
            }
        }

        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        guard withUnsafePointer(to: &addr, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(sock, $0, addrLen)
            }
        }) == 0 else {
            throw SSHAgentServerError.socketBindFailed(socketPath, errno)
        }

        // Enforce strict 0600 permissions on the created socket file (read/write only by owner)
        guard chmod(socketPath, S_IRUSR | S_IWUSR) == 0, isSecureSocketPath(socketPath) else {
            throw SSHAgentServerError.socketPermissionFailed(socketPath, errno)
        }

        guard listen(sock, 5) == 0 else {
            throw SSHAgentServerError.socketListenFailed(errno)
        }

        isRunning = true
        didStart = true
        queue.async {
            self.acceptLoop()
        }
    }

    public func stop() {
        stateLock.lock()
        _isRunning = false
        let sock = _serverSocket
        _serverSocket = -1
        stateLock.unlock()

        if sock >= 0 {
            shutdown(sock, SHUT_RDWR)
            close(sock)
        }
        try? FileManager.default.removeItem(atPath: socketPath)
    }

    public var isSocketActive: Bool {
        return isRunning && serverSocket >= 0
    }

    internal var activeClientCount: Int {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _activeClientCount
    }

    public static func getProcessName(pid: pid_t) -> String? {
        guard let fullPath = getProcessPath(pid: pid) else { return nil }
        return (fullPath as NSString).lastPathComponent
    }

    public static func getProcessPath(pid: pid_t) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let ret = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        if ret > 0 {
            return String(cString: pathBuffer)
        }
        return nil
    }

    /// Process start time in microseconds since the epoch; stable across `exec`, changes on PID reuse.
    static func processStartTime(pid: pid_t) -> UInt64? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
    }

    /// `true` while `pid` is still the same process image that was attributed when the
    /// connection was accepted. A peer that `exec`s a different binary after connecting
    /// (keeping the inherited socket) or a recycled PID would otherwise keep the identity,
    /// and therefore the Git signing grant, of the executable seen at `accept()`.
    static func peerProcessUnchanged(pid: pid_t, path: String, startTime: UInt64) -> Bool {
        guard let currentPath = getProcessPath(pid: pid),
              let currentStart = processStartTime(pid: pid) else {
            return false
        }
        return currentPath == path && currentStart == startTime
    }

    /// Resolves a process-instance-bound identity for Git signing grants.
    /// Incorporates the executable path, parent process path/PID, process start time,
    /// and process group to prevent other arbitrary background processes from hijacking grants.
    public static func resolveClientIdentity(pid: pid_t, processPath: String) -> String {
        let stdPath = URL(fileURLWithPath: processPath).standardizedFileURL.path

        var procInfo = proc_bsdinfo()
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard ret == MemoryLayout<proc_bsdinfo>.size else {
            return "\(stdPath):pid:\(pid)"
        }

        let ppid = pid_t(procInfo.pbi_ppid)
        let pgid = procInfo.pbi_pgid
        let startTime = procInfo.pbi_start_tvsec

        if ppid > 1, let parentPath = getProcessPath(pid: ppid) {
            var parentInfo = proc_bsdinfo()
            let pRet = proc_pidinfo(ppid, PROC_PIDTBSDINFO, 0, &parentInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
            if pRet == MemoryLayout<proc_bsdinfo>.size {
                let parentStart = parentInfo.pbi_start_tvsec
                let stdParentPath = URL(fileURLWithPath: parentPath).standardizedFileURL.path
                return "\(stdPath)|parent:\(stdParentPath):\(ppid):\(parentStart)|pgid:\(pgid)"
            }
            let stdParentPath = URL(fileURLWithPath: parentPath).standardizedFileURL.path
            return "\(stdPath)|parent:\(stdParentPath):\(ppid)|pgid:\(pgid)"
        }

        return "\(stdPath)|self:\(pid):\(startTime)|pgid:\(pgid)"
    }

    private func acceptLoop() {
        while isRunning {
            let listeningSock = serverSocket
            guard listeningSock >= 0 else { break }
            let clientSocket = accept(listeningSock, nil, nil)
            if clientSocket >= 0 {
                // Verify peer UID matches our own UID
                var peerUid: uid_t = 0
                var peerGid: gid_t = 0
                if getpeereid(clientSocket, &peerUid, &peerGid) != 0 || peerUid != geteuid() {
                    ClavisLogger.log("SSH_AGENT_AUTH", "Rejected connection from unauthorized peer UID \(peerUid) (expected \(geteuid()))")
                    close(clientSocket)
                    continue
                }

                // Query peer PID on Darwin
                var peerPid: pid_t = 0
                var pidLen = socklen_t(MemoryLayout<pid_t>.size)
                let clientPid: pid_t? = (getsockopt(clientSocket, SOL_LOCAL, LOCAL_PEERPID, &peerPid, &pidLen) == 0 && peerPid > 0) ? peerPid : nil
                let clientExecutablePath = clientPid.flatMap { SSHAgentServer.getProcessPath(pid: $0) }
                let clientStartTime = clientPid.flatMap { SSHAgentServer.processStartTime(pid: $0) }

                var optval: Int32 = 1
                guard setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &optval, socklen_t(MemoryLayout<Int32>.size)) == 0,
                      configureTimeouts(for: clientSocket, timeoutInterval: handshakeTimeout) else {
                    close(clientSocket)
                    continue
                }

                guard reserveClientSlot(clientPid: clientPid) else {
                    ClavisLogger.log("SSH_AGENT_LIMIT", "Rejected connection because concurrent client limit or per-PID limit was reached (PID: \(clientPid.map(String.init) ?? "unknown")).")
                    close(clientSocket)
                    continue
                }

                queue.async {
                    defer { self.releaseClientSlot(clientPid: clientPid) }
                    self.handleClient(
                        socket: clientSocket,
                        clientPid: clientPid,
                        clientExecutablePath: clientExecutablePath,
                        clientStartTime: clientStartTime
                    )
                }
            }
        }
    }

    internal func reserveClientSlot(clientPid: pid_t? = nil) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard _activeClientCount < maxConcurrentClients else { return false }
        if let pid = clientPid {
            let count = _clientPIDCounts[pid] ?? 0
            guard count < maxConcurrentClientsPerPID else { return false }
            _clientPIDCounts[pid] = count + 1
        }
        _activeClientCount += 1
        return true
    }

    internal func releaseClientSlot(clientPid: pid_t? = nil) {
        stateLock.lock()
        defer { stateLock.unlock() }
        _activeClientCount = max(0, _activeClientCount - 1)
        if let pid = clientPid {
            if let count = _clientPIDCounts[pid], count > 1 {
                _clientPIDCounts[pid] = count - 1
            } else {
                _clientPIDCounts.removeValue(forKey: pid)
            }
        }
    }

    private func configureTimeouts(for socket: Int32, timeoutInterval: TimeInterval) -> Bool {
        let seconds = floor(timeoutInterval)
        var timeout = timeval(
            tv_sec: Int(seconds),
            tv_usec: Int32((timeoutInterval - seconds) * 1_000_000)
        )
        let timeoutSize = socklen_t(MemoryLayout<timeval>.size)
        return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeoutSize) == 0 &&
            setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeoutSize) == 0
    }

    private func handleClient(
        socket clientSocket: Int32,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil
    ) {
        defer { close(clientSocket) }

        var isFirstPacket = true
        while isRunning {
            if !isFirstPacket {
                _ = configureTimeouts(for: clientSocket, timeoutInterval: clientIdleTimeout)
            }

            var lengthHeader = UInt32(0)
            if !readFullBytes(from: clientSocket, buffer: &lengthHeader, count: 4) {
                break
            }
            isFirstPacket = false

            if let pid = clientPid, let path = clientExecutablePath, let start = clientStartTime,
               !Self.peerProcessUnchanged(pid: pid, path: path, startTime: start) {
                ClavisLogger.log("SECURITY_ALERT", "Dropping connection: peer PID \(pid) is no longer the process attributed at accept (exec or PID reuse).")
                break
            }

            let msgLength = Int(UInt32(bigEndian: lengthHeader))
            if msgLength <= 0 || msgLength > 65536 { break }

            var payload = Data(count: msgLength)
            let readSuccess = payload.withUnsafeMutableBytes { ptr -> Bool in
                guard let base = ptr.baseAddress else { return false }
                return readFullBytes(from: clientSocket, buffer: base, count: msgLength)
            }
            if !readSuccess { break }

            let response = processAgentRequest(
                payload: payload,
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                isTrustedControlPeer: { self.controlPeerValidator(clientSocket) }
            )
            var responseLen = UInt32(response.count).bigEndian
            let writeHeaderSuccess = Swift.withUnsafeBytes(of: &responseLen) { ptr -> Bool in
                guard let base = ptr.baseAddress else { return false }
                return writeFullBytes(to: clientSocket, buffer: base, count: 4)
            }
            if !writeHeaderSuccess { break }

            let writePayloadSuccess = response.withUnsafeBytes { ptr -> Bool in
                guard let base = ptr.baseAddress else { return false }
                return writeFullBytes(to: clientSocket, buffer: base, count: response.count)
            }
            if !writePayloadSuccess { break }
        }
    }

    private func readFullBytes(from fd: Int32, buffer: UnsafeMutableRawPointer, count: Int) -> Bool {
        var bytesRead = 0
        while bytesRead < count {
            let result = read(fd, buffer.advanced(by: bytesRead), count - bytesRead)
            if result < 0 {
                if errno == EINTR { continue }
                return false
            }
            if result == 0 { return false }
            bytesRead += result
        }
        return true
    }

    private func writeFullBytes(to fd: Int32, buffer: UnsafeRawPointer, count: Int) -> Bool {
        var bytesWritten = 0
        while bytesWritten < count {
            let result = write(fd, buffer.advanced(by: bytesWritten), count - bytesWritten)
            if result < 0 {
                if errno == EINTR { continue }
                return false
            }
            if result == 0 { return false }
            bytesWritten += result
        }
        return true
    }

    /// Clavis-private control opcodes (240-242). They share the socket with the
    /// standard agent protocol, which can be relayed to remote hosts by
    /// `ssh -A`, so they are honored only for Clavis-signed local peers.
    private func isControlOpcode(_ msgType: UInt8) -> Bool {
        msgType == Self.invalidateKeyRequest
            || msgType == Self.queryGitGraceRequest
            || msgType == Self.lockAllRequest
    }

    /// - Parameter isTrustedControlPeer: lazily evaluated, only for control opcodes.
    ///   Defaults to "untrusted" so a caller must opt in explicitly.
    internal func processAgentRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        isTrustedControlPeer: () -> Bool = { false }
    ) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]
        ClavisLogger.log("SSH_AGENT_REQ", "Received SSH Agent request type \(msgType)")

        if isControlOpcode(msgType), !isTrustedControlPeer() {
            let clientDesc = clientPid.map { "PID \($0)" } ?? "unknown peer"
            ClavisLogger.log("SECURITY_ALERT", "Refused control request type \(msgType) from untrusted peer (\(clientDesc)).")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            guard payload.count == 1 else { return Data([5]) }
            return handleRequestIdentities(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath
            )
        case Self.invalidateKeyRequest:
            var reader = DataReader(data: Data(payload.dropFirst()))
            guard let label = reader.readWireString(), !label.isEmpty, reader.isEOF else {
                return Data([5])
            }
            GitSigningGraceManager.shared.invalidate(keyLabel: label)
            return Data([6]) // SSH_AGENT_SUCCESS
        case Self.queryGitGraceRequest:
            guard payload.count == 1 else { return Data([5]) }
            var response = Data([6])
            if let grant = GitSigningGraceManager.shared.currentActiveGrant {
                response.appendWireString(grant.keyLabel)
                response.appendWireUInt32(UInt32(grant.remainingSeconds))
                response.appendWireUInt32(UInt32(grant.remainingOperations))
            } else {
                response.appendWireString("")
                response.appendWireUInt32(0)
                response.appendWireUInt32(0)
            }
            return response
        case Self.lockAllRequest:
            guard payload.count == 1 else { return Data([5]) }
            SessionCacheManager.shared.clearCacheInternal(broadcast: false)
            GitSigningGraceManager.shared.invalidateAll(broadcast: false)
            return Data([6]) // SSH_AGENT_SUCCESS
        default:
            ClavisLogger.log("SSH_AGENT_REQ", "Unsupported SSH Agent request type \(msgType)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    internal func handleRequestIdentities(
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil
    ) -> Data {
        let clientDesc: String
        if let pid = clientPid, let path = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) {
            clientDesc = "\(Self.safeProcessPath(path)) (PID \(pid))"
        } else {
            clientDesc = "local process"
        }
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "Listing active SSH identities for \(clientDesc)...")
        // Exclude gitSigningOnly keys from general SSH identity listings (prevents accidental SSH login usage)
        let keys = ((try? keyManager.listKeys()) ?? []).filter { $0.purpose != .gitSigningOnly }
        var response = Data()
        response.append(12) // SSH2_AGENT_IDENTITIES_ANSWER

        var count = UInt32(keys.count).bigEndian
        Swift.withUnsafeBytes(of: &count) { response.append(contentsOf: $0) }

        for key in keys {
            response.appendWireData(key.publicKeyBlob)
            response.appendWireString(key.label)
        }
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "Returned \(keys.count) identity(ies) (0 Touch ID prompts).")
        return response
    }

    internal func handleSignRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let keyBlob = reader.readWireData(),
              let dataToSign = reader.readWireData(),
              let flags = reader.readUInt32(),
              flags == 0,
              reader.isEOF else {
            ClavisLogger.log("SSH_AGENT_SIGN", "Failed to parse sign request wire payload.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let matchingKey = keys.first(where: { $0.publicKeyBlob == keyBlob }) else {
            ClavisLogger.log("SSH_AGENT_SIGN", "No matching key found for requested public key blob.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        guard let pid = clientPid,
              let processPath = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) else {
            ClavisLogger.log("SSH_AGENT_AUTH", "Rejected signing request because peer process attribution was unavailable.")
            return Data([5])
        }
        let clientDesc = "\(Self.safeProcessPath(processPath)) (PID \(pid))"
        let requester = Self.requesterDescription(processPath: processPath, pid: pid)
        let clientIdentity = SSHAgentServer.resolveClientIdentity(pid: pid, processPath: processPath)

        // Domain verification: Parse signed payload as OpenSSH SSHSIG (strict Git format)
        let gitSSHSIG = SSHSIGPayload.parse(from: dataToSign)

        // Security invariant: If key is restricted to Git signing, reject any non-Git payload
        if matchingKey.purpose == .gitSigningOnly && gitSSHSIG == nil {
            ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' is restricted to Git signing. Refusing non-Git signature request from \(clientDesc).")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        do {
            let sigBlob: Data

            if let _ = gitSSHSIG {
                // Git signing request
                if let grantedSignature = try GitSigningGraceManager.shared.withGrant(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    operation: { context in
                        try keyManager.signSSH(
                            key: matchingKey,
                            data: dataToSign,
                            prompt: "",
                            useCache: false,
                            existingContext: context
                        )
                    }
                ) {
                    // Fast-path: Active 5-minute grant
                    ClavisLogger.log("GIT_GRACE", "Using active client-bound Git signing grant for '\(matchingKey.label)'. 0 Touch ID prompts.")
                    sigBlob = grantedSignature
                } else if GitSigningGraceManager.shared.hasRecentGitSignature(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    windowSeconds: 30.0
                ) {
                    // Rebase / repeated commit pattern detected (Commit #2+ within 30s)
                    ClavisLogger.log("GIT_GRACE", "Detected rapid Git signing pattern (<30s) for '\(matchingKey.label)'. Prompting user for session...")
                    let choice = GitSigningGraceManager.promptProvider(matchingKey.label, clientDesc)
                    switch choice {
                    case .cancel:
                        ClavisLogger.log("GIT_GRACE", "User cancelled Git signing session.")
                        return Data([5]) // SSH_AGENT_FAILURE

                    case .grantFiveMinutes:
                        ClavisLogger.log("GIT_GRACE", "User approved 5-minute Git signing session. Authorizing via Touch ID...")
                        let authPrompt = Self.gitSigningSessionReason(keyLabel: matchingKey.label)
                        let grant = try promptGate.run {
                            try keyManager.authorizeGitSigningGrant(
                                key: matchingKey,
                                prompt: authPrompt,
                                clientIdentity: clientIdentity,
                                duration: 300.0,
                                maxOperations: 200
                            )
                        }
                        // Perform the commit #2 signature under the newly created grant.
                        // A failure here must drop the grant; otherwise the reused context
                        // stays authorized for the rest of the session.
                        let grantedSignature: Data
                        do {
                            guard let signature = try GitSigningGraceManager.shared.withGrant(
                                for: matchingKey.label,
                                clientIdentity: clientIdentity,
                                operation: { context in
                                    try keyManager.signSSH(
                                        key: matchingKey,
                                        data: dataToSign,
                                        prompt: "",
                                        useCache: false,
                                        existingContext: context
                                    )
                                }
                            ) else {
                                grant.invalidate()
                                return Data([5])
                            }
                            grantedSignature = signature
                        } catch {
                            grant.invalidate()
                            throw error
                        }
                        sigBlob = grantedSignature

                    case .singleShot:
                        ClavisLogger.log("GIT_GRACE", "User chose single-shot signing.")
                        let prompt = Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                        sigBlob = try promptedSign(key: matchingKey, data: dataToSign, prompt: prompt)
                        GitSigningGraceManager.shared.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                    }
                } else {
                    // Commit #1 (single commit / first in a potential sequence) -> standard Touch ID, no dialog
                    let prompt = Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                    sigBlob = try promptedSign(key: matchingKey, data: dataToSign, prompt: prompt)
                    GitSigningGraceManager.shared.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                }
            } else {
                // Non-Git payload is not validated as SSH authentication. Grace period NEVER applies.
                // Agent forwarding (`ssh -A`) is relayed by local /usr/bin/ssh, which hides the remote host.
                let prompt = Self.signatureReason(
                    keyLabel: matchingKey.label,
                    requester: requester,
                    processPath: processPath
                )
                ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key '\(matchingKey.label)' requested by \(clientDesc)...")
                sigBlob = try promptedSign(key: matchingKey, data: dataToSign, prompt: prompt)
            }

            var response = Data()
            response.append(14) // SSH2_AGENT_SIGN_RESPONSE
            response.appendWireData(sigBlob)
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature completed successfully for '\(matchingKey.label)' (\(clientDesc)).")
            return response
        } catch {
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature failed for '\(matchingKey.label)' (\(clientDesc)): \(error.localizedDescription)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    private static func safeProcessPath(_ path: String) -> String {
        let sanitized = path.unicodeScalars.map { scalar -> Character in
            CharacterSet.controlCharacters.contains(scalar) ? "?" : Character(String(scalar))
        }
        return String(sanitized.prefix(512))
    }

    static func sshAuthenticationReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.sshAuthentication(keyLabel: keyLabel)
    }

    static func sshAuthenticationReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.sshAuthentication(keyLabel: keyLabel, requester: requester)
    }

    /// Prompt for a payload that is neither a Git SSHSIG nor otherwise validated.
    /// Only Apple's `/usr/bin/ssh` is treated as a possible forwarded-agent relay.
    static func signatureReason(keyLabel: String, requester: String, processPath: String) -> String {
        let standardized = URL(fileURLWithPath: processPath).standardizedFileURL.path
        if standardized == "/usr/bin/ssh" {
            return ClavisUIStrings.Prompt.sshAuthenticationFromForwardedAgent(keyLabel: keyLabel, requester: requester)
        }
        return dataSigningReason(keyLabel: keyLabel, requester: requester)
    }

    static func dataSigningReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.dataSigning(keyLabel: keyLabel, requester: requester)
    }

    static func gitCommitSigningReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: keyLabel, requester: requester)
    }

    /// Display-safe description of the requesting process for system auth prompts:
    /// sanitized executable path and PID. Control, newline, and bidi characters are
    /// stripped. Long paths keep their tail (about 80 characters) so two executables
    /// that share a basename still look different.
    static func requesterDescription(processPath: String, pid: pid_t) -> String {
        let cleaned = String(String.UnicodeScalarView(processPath.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
                && !CharacterSet.newlines.contains($0)
                && !Self.isBidiScalar($0)
        }))
        let bounded = cleaned.count > 80 ? String(cleaned.suffix(80)) : cleaned
        return "\(bounded.isEmpty ? "unknown" : bounded) (PID \(pid))"
    }

    /// Directional formatting characters that can spoof the displayed path.
    private static func isBidiScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return true
        default:
            return false
        }
    }

    /// Runs a signature that presents its own authentication prompt through the prompt gate
    /// (one prompt at a time, cooldown after repeated denials).
    private func promptedSign(key: Ed25519KeyInfo, data: Data, prompt: String) throws -> Data {
        try promptGate.run {
            try keyManager.signSSH(key: key, data: data, prompt: prompt, useCache: false)
        }
    }

    static func gitCommitSigningReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: keyLabel)
    }

    static func gitSigningSessionReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.gitSigningSession(keyLabel: keyLabel)
    }

    private func isSecureDirectory(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 &&
            (info.st_mode & S_IFMT) == S_IFDIR &&
            info.st_uid == geteuid() &&
            (info.st_mode & 0o077) == 0
    }

    private func isSecureSocketPath(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 &&
            (info.st_mode & S_IFMT) == S_IFSOCK &&
            info.st_uid == geteuid() &&
            (info.st_mode & 0o777) == 0o600
    }
}
