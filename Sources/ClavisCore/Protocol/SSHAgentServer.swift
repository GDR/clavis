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

/// Process instance that a Git signing grant was approved for.
struct GitApprovedProcess: Equatable, Sendable {
    let pid: pid_t
    let startTime: UInt64
    let path: String?

    init(pid: pid_t, startTime: UInt64, path: String? = nil) {
        self.pid = pid
        self.startTime = startTime
        self.path = path
    }
}

/// Parent and start time from a single `proc_pidinfo` read.
struct ProcessParentSnapshot: Equatable {
    var startTime: UInt64
    var parentPid: pid_t
}

public class SSHAgentServer {
    internal static let invalidateKeyRequest: UInt8 = 240
    internal static let queryGitGraceRequest: UInt8 = 241
    internal static let lockAllRequest: UInt8 = 242
    internal static let registerAgentSessionRequest: UInt8 = 243
    internal static let endAgentSessionRequest: UInt8 = 244
    internal static let listAgentSessionsRequest: UInt8 = 245
    internal static let revokeAllAgentSessionsRequest: UInt8 = 246
    internal static let extendAgentSessionRequest: UInt8 = 247
    internal static let setAgentPolicyRequest: UInt8 = 248
    internal static let getAgentPolicyRequest: UInt8 = 249
    public static let defaultSocketPath = NSString(string: "~/.ssh/clavis.sock").expandingTildeInPath
    public static let defaultAgentSocketPath = NSString(string: "~/.ssh/clavis-agent.sock").expandingTildeInPath
    public static let shared = SSHAgentServer()
    public static let sharedInstance = shared
    public static let agentShared = SSHAgentServer(socketPath: defaultAgentSocketPath, role: .agent)

    public static let defaultMaxConnectionLifetime: TimeInterval = 120.0
    public static let defaultMaxRequestsPerConnection: Int = 200

    public let socketPath: String
    public let role: AgentSocketRole
    private let maxConcurrentClients: Int
    private let maxConcurrentClientsPerPID: Int
    private let clientIdleTimeout: TimeInterval
    private let handshakeTimeout: TimeInterval
    internal let maxConnectionLifetime: TimeInterval
    internal let maxRequestsPerConnection: Int
    private let keyManager: KeychainManager
    private let auditRecorder: AuditRecording
    private let agentSessions: AgentSessionRegistry
    private let agentPolicies: AgentPolicyStoring
    private let authenticator: UserAuthenticating
    private let notificationPoster: (String, [String: String]) -> Void
    private let controlPeerValidator: (Int32) -> Bool
    private let peerProcessValidator: (pid_t, String, UInt64) -> Bool
    private let backoffHandler: (useconds_t) -> Void
    private let acceptCall: (Int32) -> (fd: Int32, err: Int32)
    private let promptGate: SigningPromptGate
    private let stateLock = NSLock()
    private var _serverSocket: Int32 = -1
    private var _isRunning = false
    private var _activeClientCount = 0
    private var _clientPIDCounts: [pid_t: Int] = [:]
    private var _boundInode: ino_t?
    private var _boundDevice: dev_t?
    private var _onPermanentListenerFailure: (() -> Void)?
    public var onPermanentListenerFailure: (() -> Void)? {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _onPermanentListenerFailure
        }
        set {
            stateLock.lock()
            _onPermanentListenerFailure = newValue
            stateLock.unlock()
        }
    }
    private let queue = DispatchQueue(label: "com.clavis.ssh-agent", attributes: .concurrent)

    internal var boundInode: ino_t? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _boundInode
    }

    internal var boundDevice: dev_t? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _boundDevice
    }

    public init(
        socketPath: String = SSHAgentServer.defaultSocketPath,
        role: AgentSocketRole = .personal,
        maxConcurrentClients: Int = 32,
        maxConcurrentClientsPerPID: Int = 8,
        clientIdleTimeout: TimeInterval = 30,
        handshakeTimeout: TimeInterval = 2.0,
        maxConnectionLifetime: TimeInterval = SSHAgentServer.defaultMaxConnectionLifetime,
        maxRequestsPerConnection: Int = SSHAgentServer.defaultMaxRequestsPerConnection,
        keyManager: KeychainManager = .shared,
        promptGate: SigningPromptGate = SigningPromptGate(),
        controlPeerValidator: ((Int32) -> Bool)? = nil,
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil,
        backoffHandler: ((useconds_t) -> Void)? = nil,
        acceptCall: ((Int32) -> (fd: Int32, err: Int32))? = nil,
        onPermanentListenerFailure: (() -> Void)? = nil,
        auditRecorder: AuditRecording = AuditRecorder.shared,
        agentSessions: AgentSessionRegistry = .shared,
        agentPolicies: AgentPolicyStoring = KeychainAgentPolicyStore(),
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        notificationPoster: @escaping (String, [String: String]) -> Void = { name, userInfo in
            DistributedNotificationCenter.default().postNotificationName(
                NSNotification.Name(name),
                object: nil,
                userInfo: userInfo,
                deliverImmediately: true
            )
        }
    ) {
        self.role = role
        self.promptGate = promptGate
        self.controlPeerValidator = controlPeerValidator ?? { ClavisCodeTrust.isTrustedPeer(socket: $0) }
        self.peerProcessValidator = peerProcessValidator ?? { SSHAgentServer.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }
        self.backoffHandler = backoffHandler ?? { usleep($0) }
        self.acceptCall = acceptCall ?? { sock in
            let fd = accept(sock, nil, nil)
            return (fd, errno)
        }
        self.socketPath = socketPath
        self.maxConcurrentClients = max(1, maxConcurrentClients)
        self.maxConcurrentClientsPerPID = max(1, maxConcurrentClientsPerPID)
        self.clientIdleTimeout = max(0.1, clientIdleTimeout)
        self.handshakeTimeout = max(0.05, min(clientIdleTimeout, handshakeTimeout))
        self.maxConnectionLifetime = max(0.01, maxConnectionLifetime)
        self.maxRequestsPerConnection = max(1, maxRequestsPerConnection)
        self.keyManager = keyManager
        self.auditRecorder = auditRecorder
        self.agentSessions = agentSessions
        self.agentPolicies = agentPolicies
        self.authenticator = authenticator
        self.notificationPoster = notificationPoster
        self._onPermanentListenerFailure = onPermanentListenerFailure
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
                stateLock.lock()
                let expectedInode = _boundInode
                let expectedDevice = _boundDevice
                _boundInode = nil
                _boundDevice = nil
                stateLock.unlock()
                if let expectedInode = expectedInode, let expectedDevice = expectedDevice {
                    var currentStat = stat()
                    if lstat(socketPath, &currentStat) == 0,
                       (currentStat.st_mode & S_IFMT) == S_IFSOCK,
                       currentStat.st_ino == expectedInode,
                       currentStat.st_dev == expectedDevice,
                       currentStat.st_uid == geteuid() {
                        _ = unlink(socketPath)
                    }
                }
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

        var boundStat = stat()
        guard lstat(socketPath, &boundStat) == 0 else {
            throw SSHAgentServerError.socketPermissionFailed(socketPath, errno)
        }

        stateLock.lock()
        _boundInode = boundStat.st_ino
        _boundDevice = boundStat.st_dev
        stateLock.unlock()

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
        let expectedInode = _boundInode
        let expectedDevice = _boundDevice
        _boundInode = nil
        _boundDevice = nil
        stateLock.unlock()

        if sock >= 0 {
            shutdown(sock, SHUT_RDWR)
            close(sock)
        }

        guard let expectedInode = expectedInode, let expectedDevice = expectedDevice else {
            return
        }

        var currentStat = stat()
        if lstat(socketPath, &currentStat) == 0 {
            if (currentStat.st_mode & S_IFMT) == S_IFSOCK,
               currentStat.st_ino == expectedInode,
               currentStat.st_dev == expectedDevice,
               currentStat.st_uid == geteuid() {
                _ = unlink(socketPath)
            }
        }
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
        processParentSnapshot(pid: pid)?.startTime
    }

    /// One `proc_pidinfo` snapshot: start time plus parent pid.
    static func processParentSnapshot(pid: pid_t) -> ProcessParentSnapshot? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return ProcessParentSnapshot(
            startTime: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
            parentPid: pid_t(info.pbi_ppid)
        )
    }

    /// `true` when `peer` is the approved process instance or a live descendant of it
    /// via a git-only process chain ending in a recognized signer helper.
    /// The walk stops at pid 1, a cycle, or a missing snapshot. A sibling that merely
    /// shares the approved process's parent does not match.
    static func gitGrantCoversPeer(
        peerPid: pid_t,
        peerStartTime: UInt64,
        peerPath: String? = nil,
        approvedPid: pid_t,
        approvedStartTime: UInt64,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> Bool {
        guard peerPid > 0, approvedPid > 1 else { return false }

        // Direct match: approved process instance itself (e.g. test runner or direct anchor)
        if peerPid == approvedPid {
            guard let peerSnap = processInfo(peerPid) else { return false }
            return peerSnap.startTime == peerStartTime && peerStartTime == approvedStartTime
        }

        // Descendant match:
        // Peer must be a known signer helper (ssh-keygen or resolved gpg.ssh.program)
        guard let resolvedPeerPath = peerPath ?? processPathLookup(peerPid) else {
            return false
        }
        guard isSignerHelper(path: resolvedPeerPath, resolvedGpgSSHProgram: resolvedGpgSSHProgram) else {
            return false
        }

        guard let peerSnap = processInfo(peerPid), peerSnap.startTime == peerStartTime else {
            return false
        }

        // Ancestor path walk: from peer's parent up to approvedPid.
        // Every process on the ancestor path from peer up to approved git (exclusive) must have basename "git".
        var current = peerSnap.parentPid
        var seen = Set<pid_t>([peerPid])
        seen.reserveCapacity(8)

        for _ in 0..<64 {
            guard current > 1, seen.insert(current).inserted else { return false }
            guard let info = processInfo(current) else { return false }

            if current == approvedPid {
                return info.startTime == approvedStartTime
            }

            guard let path = processPathLookup(current) else { return false }
            let base = (path as NSString).lastPathComponent
            guard base == "git" else { return false }

            let parent = info.parentPid
            if parent <= 0 || parent == current {
                return false
            }
            current = parent
        }
        return false
    }

    static func gitGrantCoversPeer(peer: GitApprovedProcess, approved: GitApprovedProcess) -> Bool {
        gitGrantCoversPeer(
            peerPid: peer.pid,
            peerStartTime: peer.startTime,
            peerPath: peer.path,
            approvedPid: approved.pid,
            approvedStartTime: approved.startTime,
            processInfo: { processParentSnapshot(pid: $0) },
            processPathLookup: { getProcessPath(pid: $0) },
            resolvedGpgSSHProgram: { gpgSSHProgramResolver() }
        )
    }

    public static var gpgSSHProgramResolver: () -> String? = {
        resolveGpgSSHProgram()
    }

    static func resolveGpgSSHProgram(gitExecutablePath: String? = nil, timeout: TimeInterval = 2.0) -> String? {
        let gitPath: String
        if let customPath = gitExecutablePath {
            guard FileManager.default.isExecutableFile(atPath: customPath) else { return nil }
            gitPath = customPath
        } else if FileManager.default.isExecutableFile(atPath: "/usr/bin/git") {
            gitPath = "/usr/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/git") {
            gitPath = "/opt/homebrew/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/usr/local/bin/git") {
            gitPath = "/usr/local/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/Applications/Xcode.app/Contents/Developer/usr/bin/git") {
            gitPath = "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
        } else {
            return nil
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: gitPath)
        process.arguments = ["config", "--get", "gpg.ssh.program"]
        let stdoutPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }

        let readHandle = stdoutPipe.fileHandleForReading
        let readFd = readHandle.fileDescriptor
        let maxOutputBytes = 64 * 1024
        var outputData = Data()
        var timedOut = false

        let startUptime = DispatchTime.now().uptimeNanoseconds
        let timeoutNanos = UInt64(max(0, timeout) * 1_000_000_000)
        let deadlineUptime = startUptime + timeoutNanos

        var chunk = [UInt8](repeating: 0, count: 4096)

        // Read stdout on the calling thread with poll(2) to avoid close races with
        // readDataToEndOfFile() which can throw an uncatchable Obj-C exception if closed
        // while blocked on Darwin.
        while true {
            let nowUptime = DispatchTime.now().uptimeNanoseconds
            if nowUptime >= deadlineUptime {
                timedOut = true
                break
            }
            let remainingNanos = deadlineUptime - nowUptime
            let remainingMs = Int32(min(max(1, (remainingNanos + 999_999) / 1_000_000), UInt64(Int32.max)))

            var pfd = pollfd(fd: readFd, events: Int16(POLLIN), revents: 0)
            let pollRet = poll(&pfd, 1, remainingMs)

            if pollRet < 0 {
                if errno == EINTR {
                    continue
                }
                break
            } else if pollRet == 0 {
                timedOut = true
                break
            }

            let bytesRead = read(readFd, &chunk, chunk.count)
            if bytesRead > 0 {
                if outputData.count < maxOutputBytes {
                    let toAppend = min(bytesRead, maxOutputBytes - outputData.count)
                    outputData.append(contentsOf: chunk[0..<toAppend])
                }
            } else if bytesRead == 0 {
                break
            } else {
                if errno == EINTR {
                    continue
                }
                break
            }
        }

        try? readHandle.close()

        if timedOut {
            process.terminate()
            usleep(50_000)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return nil
        }

        while process.isRunning {
            let nowUptime = DispatchTime.now().uptimeNanoseconds
            if nowUptime >= deadlineUptime {
                process.terminate()
                usleep(50_000)
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
                process.waitUntilExit()
                return nil
            }
            usleep(5_000)
        }

        process.waitUntilExit()

        guard process.terminationStatus == 0 else { return nil }
        guard let raw = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        return raw
    }

    static func isSignerHelper(
        path: String,
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> Bool {
        let stdPath = URL(fileURLWithPath: path).standardizedFileURL.path
        if stdPath == "/usr/bin/ssh-keygen" || (path as NSString).lastPathComponent == "ssh-keygen" {
            return true
        }
        if let custom = resolvedGpgSSHProgram(), !custom.isEmpty {
            let expandedCustom = NSString(string: custom).expandingTildeInPath
            let stdCustom = URL(fileURLWithPath: expandedCustom).standardizedFileURL.path
            if stdPath == stdCustom || (path as NSString).lastPathComponent == (expandedCustom as NSString).lastPathComponent {
                return true
            }
        }
        return false
    }

    static func isRefusedAnchor(pid: pid_t, path: String) -> Bool {
        if pid <= 1 { return true }
        let base = (path as NSString).lastPathComponent.lowercased()
        let refusedBases: Set<String> = [
            "launchd",
            "sh", "bash", "zsh", "csh", "tcsh", "fish", "dash", "ksh",
            "terminal", "iterm", "iterm2", "alacritty", "kitty", "wezterm", "wezterm-gui",
            "tmux", "screen", "login"
        ]
        return refusedBases.contains(base)
    }

    /// Resolves the process anchor for a Git signing grant.
    /// If peer executable matches known signer helper (/usr/bin/ssh-keygen, resolved gpg.ssh.program)
    /// and parent executable basename is git, anchors the grant on parent git (pid + start time).
    /// Never anchors on shell, terminal, or launchd.
    static func grantAnchor(
        peerPid: pid_t,
        peerPath: String,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> GitApprovedProcess? {
        guard peerPid > 1 else { return nil }

        // If peer executable matches known signer helper, verify parent process is git
        if isSignerHelper(path: peerPath, resolvedGpgSSHProgram: resolvedGpgSSHProgram) {
            guard let peerSnap = processInfo(peerPid) else { return nil }
            let parentPid = peerSnap.parentPid
            guard parentPid > 1 else { return nil }
            guard let parentSnap = processInfo(parentPid), parentSnap.startTime > 0 else { return nil }
            guard let parentPath = processPathLookup(parentPid) else { return nil }
            let parentBase = (parentPath as NSString).lastPathComponent
            if parentBase == "git" {
                guard !isRefusedAnchor(pid: parentPid, path: parentPath) else { return nil }
                // Walk up contiguous git ancestors to anchor on the root git process (e.g. git rebase)
                var topGitPid = parentPid
                var topGitSnap = parentSnap
                var topGitPath = parentPath
                var current = parentPid
                var seen = Set<pid_t>([peerPid, current])
                for _ in 0..<64 {
                    guard let currSnap = processInfo(current) else { break }
                    let ppid = currSnap.parentPid
                    guard ppid > 1, seen.insert(ppid).inserted else { break }
                    guard let pSnap = processInfo(ppid), pSnap.startTime > 0 else { break }
                    guard let pPath = processPathLookup(ppid) else { break }
                    let pBase = (pPath as NSString).lastPathComponent
                    guard pBase == "git", !isRefusedAnchor(pid: ppid, path: pPath) else { break }
                    topGitPid = ppid
                    topGitSnap = pSnap
                    topGitPath = pPath
                    current = ppid
                }
                return GitApprovedProcess(pid: topGitPid, startTime: topGitSnap.startTime, path: topGitPath)
            }
            // Signer helper whose parent is not git (e.g. shell, terminal, or launchd): refused.
            return nil
        }

        // If peer executable basename is git (or test runner xctest in DEBUG), anchor on itself
        let peerBase = (peerPath as NSString).lastPathComponent
        #if DEBUG
        let isDirectAnchor = (peerBase == "git" || peerBase == "xctest")
        #else
        let isDirectAnchor = (peerBase == "git")
        #endif
        if isDirectAnchor {
            guard !isRefusedAnchor(pid: peerPid, path: peerPath) else { return nil }
            guard let peerSnap = processInfo(peerPid), peerSnap.startTime > 0 else { return nil }
            var topGitPid = peerPid
            var topGitSnap = peerSnap
            var topGitPath = peerPath
            var current = peerPid
            var seen = Set<pid_t>([current])
            for _ in 0..<64 {
                guard let currSnap = processInfo(current) else { break }
                let ppid = currSnap.parentPid
                guard ppid > 1, seen.insert(ppid).inserted else { break }
                guard let pSnap = processInfo(ppid), pSnap.startTime > 0 else { break }
                guard let pPath = processPathLookup(ppid) else { break }
                let pBase = (pPath as NSString).lastPathComponent
                guard pBase == "git", !isRefusedAnchor(pid: ppid, path: pPath) else { break }
                topGitPid = ppid
                topGitSnap = pSnap
                topGitPath = pPath
                current = ppid
            }
            return GitApprovedProcess(pid: topGitPid, startTime: topGitSnap.startTime, path: topGitPath)
        }

        // All other executables are refused
        return nil
    }

    static func grantAnchor(peerPid: pid_t, peerPath: String) -> GitApprovedProcess? {
        grantAnchor(
            peerPid: peerPid,
            peerPath: peerPath,
            processInfo: { processParentSnapshot(pid: $0) },
            processPathLookup: { getProcessPath(pid: $0) },
            resolvedGpgSSHProgram: { gpgSSHProgramResolver() }
        )
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

    /// Groups recent Git signatures by executable, parent, and process group.
    /// When `ppid > 1` the string omits the signing process instance, so it must not
    /// authorize a grant: grants are bound to `GitApprovedProcess` and its descendants.
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

    /// Returns true if an errno indicates a permanent failure of the listening socket.
    public static func isPermanentSocketError(_ errorCode: Int32) -> Bool {
        errorCode == EBADF || errorCode == EINVAL || errorCode == ENOTSOCK
    }

    internal func acceptLoop() {
        while isRunning {
            let listeningSock = serverSocket
            guard listeningSock >= 0 else { break }
            let (clientSocket, errorCode) = acceptCall(listeningSock)
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
            } else {
                guard isRunning else { break }
                if errorCode == EINTR || errorCode == ECONNABORTED {
                    continue
                }
                if Self.isPermanentSocketError(errorCode) {
                    ClavisLogger.log("SECURITY_ALERT", "SSH agent listener failed permanently with errno \(errorCode) (\(String(cString: strerror(errorCode)))); shutting down.")
                    stop()
                    onPermanentListenerFailure?()
                    break
                }
                backoffHandler(100_000)
                continue
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

    internal func handleClient(
        socket clientSocket: Int32,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil
    ) {
        defer { close(clientSocket) }

        var isFirstPacket = true
        var requestCount = 0
        let connectionStart = Date()

        while isRunning {
            let elapsed = Date().timeIntervalSince(connectionStart)
            if elapsed >= maxConnectionLifetime {
                ClavisLogger.log("SSH_AGENT_LIMIT", "Dropping connection: reached max lifetime (\(maxConnectionLifetime)s).")
                break
            }
            if requestCount >= maxRequestsPerConnection {
                ClavisLogger.log("SSH_AGENT_LIMIT", "Dropping connection: reached max request cap (\(maxRequestsPerConnection)).")
                break
            }

            let remainingLifetime = max(0.01, maxConnectionLifetime - elapsed)
            let baseTimeout = isFirstPacket ? handshakeTimeout : clientIdleTimeout
            let effectiveTimeout = min(baseTimeout, remainingLifetime)
            _ = configureTimeouts(for: clientSocket, timeoutInterval: effectiveTimeout)

            var lengthHeader = UInt32(0)
            if !readFullBytes(from: clientSocket, buffer: &lengthHeader, count: 4) {
                break
            }
            isFirstPacket = false
            requestCount += 1

            if let pid = clientPid, let path = clientExecutablePath, let start = clientStartTime,
               !self.peerProcessValidator(pid, path, start) {
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
                clientStartTime: clientStartTime,
                clientSocket: clientSocket,
                isTrustedControlPeer: { self.controlPeerValidator(clientSocket) }
            )
            guard !response.isEmpty else {
                // Signature withheld and connection dropped
                break
            }

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
            || msgType == Self.registerAgentSessionRequest
            || msgType == Self.endAgentSessionRequest
            || msgType == Self.listAgentSessionsRequest
            || msgType == Self.revokeAllAgentSessionsRequest
            || msgType == Self.extendAgentSessionRequest
            || msgType == Self.setAgentPolicyRequest
            || msgType == Self.getAgentPolicyRequest
    }

    /// - Parameter isTrustedControlPeer: lazily evaluated, only for control opcodes.
    ///   Defaults to "untrusted" so a caller must opt in explicitly.
    internal func processAgentRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        isTrustedControlPeer: () -> Bool = { false }
    ) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]
        ClavisLogger.log("SSH_AGENT_REQ", "Received SSH Agent request type \(msgType)")

        if isControlOpcode(msgType) {
            let clientDesc = clientPid.map { "PID \($0)" } ?? "unknown peer"
            if role == .agent {
                ClavisLogger.log("SECURITY_ALERT", "Refused control request type \(msgType) on agent socket (\(clientDesc)).")
                return Data([5]) // SSH_AGENT_FAILURE
            }
            if !isTrustedControlPeer() {
                ClavisLogger.log("SECURITY_ALERT", "Refused control request type \(msgType) from untrusted peer (\(clientDesc)).")
                return Data([5]) // SSH_AGENT_FAILURE
            }
        }

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            guard payload.count == 1 else { return Data([5]) }
            return handleRequestIdentities(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case Self.invalidateKeyRequest:
            var reader = DataReader(data: Data(payload.dropFirst()))
            guard let label = reader.readWireString(), !label.isEmpty, reader.isEOF else {
                return Data([5])
            }
            GitSigningGraceManager.shared.invalidate(keyLabel: label)
            agentSessions.endAll(keyLabel: label, reason: .keyChanged)
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
            agentSessions.endAll(reason: .lockAll)
            auditRecorder.record(
                AuditEvent(
                    type: .lock,
                    result: .info,
                    reason: .lockNow
                )
            )
            return Data([6]) // SSH_AGENT_SUCCESS
        case Self.registerAgentSessionRequest:
            return handleRegisterAgentSession(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case Self.endAgentSessionRequest:
            var reader = DataReader(data: Data(payload.dropFirst()))
            guard let sessionId = reader.readWireString(), !sessionId.isEmpty, reader.isEOF else {
                return Data([5])
            }
            let ended = agentSessions.end(id: sessionId, reason: .revokedByUser)
            return ended ? Data([6]) : Data([5])
        case Self.listAgentSessionsRequest:
            let reader = DataReader(data: Data(payload.dropFirst()))
            guard reader.isEOF else { return Data([5]) }
            let summaries = agentSessions.summaries()
            var response = Data([6])
            response.appendWireUInt32(UInt32(summaries.count))
            for s in summaries {
                response.appendWireString(s.id)
                response.appendWireString(s.keyLabel)
                response.appendWireString(s.keyFingerprint)
                response.appendWireString(s.toolName)
                response.appendWireUInt32(UInt32(s.rootPid))
                response.appendWireUInt32(UInt32(s.startedAt.timeIntervalSince1970))
                response.appendWireUInt32(UInt32(s.expiresAt.timeIntervalSince1970))
            }
            return response
        case Self.revokeAllAgentSessionsRequest:
            let reader = DataReader(data: Data(payload.dropFirst()))
            guard reader.isEOF else { return Data([5]) }
            let ended = agentSessions.endAll(reason: .revokedByUser)
            var response = Data([6])
            response.appendWireUInt32(UInt32(ended))
            return response
        case Self.extendAgentSessionRequest:
            return handleExtendAgentSession(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case Self.setAgentPolicyRequest:
            return handleSetAgentPolicy(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case Self.getAgentPolicyRequest:
            return handleGetAgentPolicy(
                payload: Data(payload.dropFirst())
            )
        default:
            ClavisLogger.log("SSH_AGENT_REQ", "Unsupported SSH Agent request type \(msgType)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    private func handleRegisterAgentSession(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let keyLabel = reader.readWireString(),
              let toolName = reader.readWireString(),
              let leaseMinutes = reader.readUInt32(),
              reader.isEOF else {
            return Data([5])
        }

        guard !toolName.isEmpty, toolName.utf8.count <= 256, !keyLabel.isEmpty else {
            return Data([5])
        }

        guard let pid = clientPid, let startTime = clientStartTime else {
            return Data([5])
        }

        let processPath = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) ?? ""
        let chain = AuditProcessChain.build(pid: pid, executablePath: processPath)

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.label == keyLabel }) else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .unknownKey,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        guard key.purpose == .agent else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .wrongKeyKind,
                    keyFingerprint: key.fingerprint,
                    keyKind: key.purpose.auditKind,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        let policy: AgentKeyPolicy
        let global: AgentGlobalPolicy
        do {
            policy = try agentPolicies.policy(forFingerprint: key.fingerprint)
            global = try agentPolicies.global()
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .policyUnavailable,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        let requested = Int(leaseMinutes)
        let leaseMinutesActual = min(requested == 0 ? policy.leaseMinutes : requested, global.maxLeaseMinutes)
        let leaseSeconds = UInt32(leaseMinutesActual * 60)

        let requester = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let grant: AgentSessionGrant
        do {
            grant = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                let promptText = ClavisUIStrings.AgentSession.approvePrompt(
                    tool: toolName,
                    keyLabel: key.label,
                    minutes: Int(leaseMinutesActual)
                )
                return try keyManager.authorizeAgentSession(key: key, prompt: promptText)
            }
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        guard self.peerProcessValidator(pid, processPath, startTime) else {
            grant.invalidate()
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .peerChanged,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        let startedAt = Date()
        let expiresAt = startedAt.addingTimeInterval(TimeInterval(leaseSeconds))
        let maxExpiresAt = startedAt.addingTimeInterval(Double(global.maxLeaseMinutes * 60))
        let session = AgentSession(
            keyLabel: key.label,
            keyFingerprint: key.fingerprint,
            toolName: toolName,
            root: AgentSessionRoot(pid: pid, startTime: startTime),
            startedAt: startedAt,
            expiresAt: expiresAt,
            maxExpiresAt: maxExpiresAt,
            policy: policy,
            grant: grant
        )
        agentSessions.add(session)

        auditRecorder.record(
            AuditEvent(
                type: .sessionStart,
                result: .allowed,
                reason: .sessionApproved,
                keyFingerprint: key.fingerprint,
                keyKind: .agent,
                sessionID: session.id,
                sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
            )
        )

        var response = Data([6])
        response.appendWireString(session.id)
        response.appendWireUInt32(leaseSeconds)
        return response
    }

    private func handleSetAgentPolicy(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let fingerprint = reader.readWireString(),
              let jsonString = reader.readWireString(),
              reader.isEOF else {
            return Data([5])
        }

        guard let jsonData = jsonString.data(using: .utf8),
              let policy = try? JSONDecoder().decode(AgentKeyPolicy.self, from: jsonData) else {
            return Data([5])
        }

        do {
            try policy.validate()
        } catch {
            return Data([5])
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
            return Data([5])
        }

        guard key.purpose == .agent else {
            return Data([5])
        }

        let pid = clientPid ?? 0
        let processPath = clientExecutablePath ?? (clientPid.flatMap { SSHAgentServer.getProcessPath(pid: $0) }) ?? ""
        let chain = clientPid != nil ? AuditProcessChain.build(pid: pid, executablePath: processPath) : []

        do {
            _ = try authenticator.authenticate(reason: ClavisUIStrings.AgentPolicy.changePrompt)
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        do {
            try agentPolicies.save(policy, forFingerprint: fingerprint)
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: .allowed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([6])
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: .failed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }
    }

    private func handleGetAgentPolicy(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let fingerprint = reader.readWireString(), reader.isEOF else {
            return Data([5])
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
            return Data([5])
        }

        guard key.purpose == .agent else {
            return Data([5])
        }

        do {
            let policy = try agentPolicies.policy(forFingerprint: fingerprint)
            let data = try JSONEncoder().encode(policy)
            guard let jsonString = String(data: data, encoding: .utf8) else {
                return Data([5])
            }
            var response = Data([6])
            response.appendWireString(jsonString)
            return response
        } catch {
            return Data([5])
        }
    }

    private func handleExtendAgentSession(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let sessionId = reader.readWireString(),
              let minutes32 = reader.readUInt32(),
              reader.isEOF else {
            return Data([5])
        }

        let minutes = Int(minutes32)
        guard minutes > 0 else {
            return Data([5])
        }

        let summaries = agentSessions.summaries()
        guard let summary = summaries.first(where: { $0.id == sessionId }) else {
            return Data([5])
        }

        let pid = clientPid ?? 0
        let processPath = clientExecutablePath ?? (clientPid.flatMap { SSHAgentServer.getProcessPath(pid: $0) }) ?? ""
        let chain = clientPid != nil ? AuditProcessChain.build(pid: pid, executablePath: processPath) : []

        do {
            _ = try authenticator.authenticate(reason: ClavisUIStrings.AgentSession.extendPrompt)
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .sessionExtend,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: summary.keyFingerprint,
                    keyKind: .agent,
                    sessionID: sessionId,
                    sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        guard let newExpiry = agentSessions.extend(id: sessionId, by: minutes) else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionExtend,
                    result: .failed,
                    keyFingerprint: summary.keyFingerprint,
                    keyKind: .agent,
                    sessionID: sessionId,
                    sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        auditRecorder.record(
            AuditEvent(
                type: .sessionExtend,
                result: .allowed,
                keyFingerprint: summary.keyFingerprint,
                keyKind: .agent,
                sessionID: sessionId,
                sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
            )
        )

        var response = Data([6])
        response.appendWireUInt32(UInt32(newExpiry.timeIntervalSince1970))
        return response
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
        // Filter keys according to socket role (personal lists general; agent lists agent)
        let keys = ((try? keyManager.listKeys()) ?? []).filter { role.listedPurposes.contains($0.purpose) }
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

    private struct PendingSignAudit {
        var result: AuditResult = .failed
        var reason: AuditReason? = .signingError
        var keyFingerprint: String?
        var keyKind: AuditKeyKind? = .personal
        var keyLabel: String?
        var sessionID: String?
        var chain: [AuditProcess] = []

        func makeEvent() -> AuditEvent {
            AuditEvent(
                type: .signature,
                result: result,
                reason: reason,
                keyFingerprint: keyFingerprint,
                keyKind: keyKind,
                sessionID: sessionID,
                count: 1,
                sensitive: AuditSensitive(
                    keyLabel: keyLabel,
                    processChain: chain,
                    host: nil
                )
            )
        }
    }

    internal func handleSignRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil
    ) -> Data {
        var audit = PendingSignAudit()
        defer { auditRecorder.record(audit.makeEvent()) }

        var reader = DataReader(data: payload)
        guard let keyBlob = reader.readWireData(),
              let dataToSign = reader.readWireData(),
              let flags = reader.readUInt32(),
              flags == 0,
              reader.isEOF else {
            audit.result = .denied
            audit.reason = .malformedRequest
            ClavisLogger.log("SSH_AGENT_REJECT", "Failed to parse sign request wire payload.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let matchingKey = keys.first(where: { $0.publicKeyBlob == keyBlob }) else {
            audit.result = .denied
            audit.reason = .unknownKey
            ClavisLogger.log("SSH_AGENT_REJECT", "No matching key found for requested public key blob.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        audit.keyFingerprint = matchingKey.fingerprint
        audit.keyLabel = matchingKey.label
        audit.keyKind = matchingKey.purpose.auditKind

        guard let pid = clientPid,
              let processPath = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) else {
            audit.result = .denied
            audit.reason = .noPeerAttribution
            ClavisLogger.log("SSH_AGENT_REJECT", "Rejected signing request because peer process attribution was unavailable.")
            return Data([5])
        }

        audit.chain = AuditProcessChain.build(pid: pid, executablePath: processPath)

        let clientDesc = "\(Self.safeProcessPath(processPath)) (PID \(pid))"

        guard role.allowedPurposes.contains(matchingKey.purpose) else {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' with purpose '\(matchingKey.purpose.rawValue)' is not allowed on \(role.rawValue) socket. Refusing request from \(clientDesc).")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        // Domain verification: Parse signed payload as OpenSSH SSHSIG (strict Git format)
        let gitSSHSIG = SSHSIGPayload.parse(from: dataToSign)

        if matchingKey.purpose == .agent && gitSSHSIG != nil {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Agent key '\(matchingKey.label)' cannot be used for SSHSIG signing. Refusing request from \(clientDesc).")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        if role == .agent {
            switch agentSessions.session(forKeyFingerprint: matchingKey.fingerprint, peerPid: pid) {
            case .found(let session):
                audit.sessionID = session.id
                switch session.policy.mode {
                case .none:
                    do {
                        let sigBlob = try session.grant.sign(dataToSign, using: keyManager)
                        audit.result = .allowed
                        audit.reason = .viaAgentSession
                        var response = Data()
                        response.append(14) // SSH2_AGENT_SIGN_RESPONSE
                        response.appendWireData(sigBlob)
                        return response
                    } catch {
                        agentSessions.end(id: session.id, reason: .signingError)
                        audit.result = .failed
                        audit.reason = .signingError
                        return Data([5])
                    }
                case .notify:
                    do {
                        let sigBlob = try session.grant.sign(dataToSign, using: keyManager)
                        audit.result = .allowed
                        audit.reason = .viaAgentSession
                        notificationPoster(
                            "com.clavis.agentSigned",
                            ["sessionID": session.id, "fingerprint": session.keyFingerprint]
                        )
                        var response = Data()
                        response.append(14) // SSH2_AGENT_SIGN_RESPONSE
                        response.appendWireData(sigBlob)
                        return response
                    } catch {
                        agentSessions.end(id: session.id, reason: .signingError)
                        audit.result = .failed
                        audit.reason = .signingError
                        return Data([5])
                    }
                case .ask:
                    let requester = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
                    do {
                        let sigBlob = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                            try keyManager.signSSH(
                                key: matchingKey,
                                data: dataToSign,
                                prompt: ClavisUIStrings.AgentSession.askPrompt,
                                useCache: false,
                                existingContext: nil,
                                allowedPurposes: [.agent]
                            )
                        }
                        audit.result = .allowed
                        audit.reason = .viaPrompt
                        var response = Data()
                        response.append(14) // SSH2_AGENT_SIGN_RESPONSE
                        response.appendWireData(sigBlob)
                        return response
                    } catch {
                        let isCancelled = AuditEvent.isUserCancellation(error)
                        audit.result = isCancelled ? .cancelled : .denied
                        audit.reason = isCancelled ? .userCancelled : .authenticationFailed
                        return Data([5])
                    }
                }
            case .noSession:
                audit.result = .denied
                audit.reason = .noAgentSession
                return Data([5])
            case .outsideTree:
                audit.result = .denied
                audit.reason = .outsideSessionTree
                return Data([5])
            case .expired:
                audit.result = .denied
                audit.reason = .leaseExpired
                return Data([5])
            }
        }
        let requester = Self.requesterDescription(processPath: processPath, pid: pid)
        let requesterIdentity = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let clientIdentity = SSHAgentServer.resolveClientIdentity(pid: pid, processPath: processPath)
        let attributedStartTime = clientStartTime ?? SSHAgentServer.processStartTime(pid: pid)
        let peerProcess = attributedStartTime.map {
            GitApprovedProcess(pid: pid, startTime: $0, path: processPath)
        }

        // Security invariant: If key is restricted to Git signing, reject any non-Git payload
        if matchingKey.purpose == .gitSigningOnly && gitSSHSIG == nil {
            audit.result = .denied
            audit.reason = .gitOnlyKeyNonGitPayload
            ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' is restricted to Git signing. Refusing non-Git signature request from \(clientDesc).")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        do {
            let sigBlob: Data
            var isFromGitGrant = false

            if let _ = gitSSHSIG {
                // Git signing request
                if let grantedSignature = try GitSigningGraceManager.shared.withGrant(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    peerProcess: peerProcess,
                    operation: { context in
                        try keyManager.signSSH(
                            key: matchingKey,
                            data: dataToSign,
                            prompt: "",
                            useCache: false,
                            existingContext: context,
                            allowedPurposes: role.allowedPurposes
                        )
                    }
                ) {
                    // Fast-path: Active 5-minute grant
                    ClavisLogger.log("GIT_GRACE", "Using active client-bound Git signing grant for '\(matchingKey.label)'. 0 Touch ID prompts.")
                    sigBlob = grantedSignature
                    isFromGitGrant = true
                } else if GitSigningGraceManager.shared.hasRecentGitSignature(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    windowSeconds: 30.0
                ) {
                    // Rebase / repeated commit pattern detected (Commit #2+ within 30s)
                    ClavisLogger.log("GIT_GRACE", "Detected rapid Git signing pattern (<30s) for '\(matchingKey.label)'. Prompting user for session...")
                    let gitAnchor = SSHAgentServer.grantAnchor(peerPid: pid, peerPath: processPath)
                    let anchorPath = gitAnchor?.path
                    let anchorPid = gitAnchor?.pid
                    let promptDesc = Self.requesterDescription(
                        processPath: anchorPath ?? processPath,
                        pid: anchorPid ?? pid
                    )
                    let choice = promptGate.runExclusive {
                        GitSigningGraceManager.promptProvider(matchingKey.label, promptDesc)
                    }
                    switch choice {
                    case .cancel:
                        audit.result = .cancelled
                        audit.reason = .userCancelled
                        ClavisLogger.log("GIT_GRACE", "User cancelled Git signing session.")
                        return Data([5]) // SSH_AGENT_FAILURE

                    case .grantFiveMinutes:
                        guard let anchor = gitAnchor else {
                            audit.result = .denied
                            audit.reason = .gitAnchorUnavailable
                            ClavisLogger.log("SECURITY_ALERT", "Refusing Git signing grant: peer PID \(pid) (\(processPath)) cannot be anchored on a valid Git process.")
                            return Data([5])
                        }
                        ClavisLogger.log("GIT_GRACE", "User approved 5-minute Git signing session for \(promptDesc). Authorizing via Touch ID...")
                        let authPrompt = Self.gitSigningSessionReason(keyLabel: matchingKey.label)
                        let grant = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                            try keyManager.authorizeGitSigningGrant(
                                key: matchingKey,
                                prompt: authPrompt,
                                clientIdentity: clientIdentity,
                                duration: 300.0,
                                maxOperations: 200,
                                approvedProcess: anchor
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
                                peerProcess: peerProcess,
                                operation: { context in
                                    try keyManager.signSSH(
                                        key: matchingKey,
                                        data: dataToSign,
                                        prompt: "",
                                        useCache: false,
                                        existingContext: context,
                                        allowedPurposes: role.allowedPurposes
                                    )
                                }
                            ) else {
                                grant.invalidate()
                                audit.result = .failed
                                audit.reason = .signingError
                                return Data([5])
                            }
                            grantedSignature = signature
                        } catch {
                            grant.invalidate()
                            throw error
                        }
                        sigBlob = grantedSignature
                        isFromGitGrant = true

                    case .singleShot:
                        ClavisLogger.log("GIT_GRACE", "User chose single-shot signing.")
                        let prompt = Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                        sigBlob = try promptedSign(
                            key: matchingKey,
                            data: dataToSign,
                            prompt: prompt,
                            requester: requesterIdentity,
                            clientSocket: clientSocket
                        )
                        GitSigningGraceManager.shared.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                    }
                } else {
                    // Commit #1 (single commit / first in a potential sequence) -> standard Touch ID, no dialog
                    let prompt = Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                    sigBlob = try promptedSign(
                        key: matchingKey,
                        data: dataToSign,
                        prompt: prompt,
                        requester: requesterIdentity,
                        clientSocket: clientSocket
                    )
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
                sigBlob = try promptedSign(
                    key: matchingKey,
                    data: dataToSign,
                    prompt: prompt,
                    requester: requesterIdentity,
                    clientSocket: clientSocket
                )
            }

            // TOCTOU check: re-run peerProcessUnchanged after signing prompt returns and before sending signature
            guard let start = attributedStartTime, self.peerProcessValidator(pid, processPath, start) else {
                audit.result = .denied
                audit.reason = .peerChanged
                ClavisLogger.log("SECURITY_ALERT", "Dropping connection: peer process changed during signing prompt (TOCTOU violation for PID \(pid)).")
                GitSigningGraceManager.shared.invalidateAll(broadcast: false)
                return Data()
            }

            if isFromGitGrant {
                audit.result = .allowed
                audit.reason = .viaGitGrant
            } else {
                audit.result = .allowed
                audit.reason = .viaPrompt
            }

            var response = Data()
            response.append(14) // SSH2_AGENT_SIGN_RESPONSE
            response.appendWireData(sigBlob)
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature completed successfully for '\(matchingKey.label)' (\(clientDesc)).")
            return response
        } catch {
            if error is KeyPurposeError {
                audit.result = .denied
                audit.reason = .wrongKeyKind
            } else if AuditEvent.isUserCancellation(error) {
                audit.result = .cancelled
                audit.reason = .userCancelled
            } else if case UserAuthenticationError.rejected = error {
                audit.result = .denied
                audit.reason = .authenticationFailed
            } else {
                audit.result = .failed
                audit.reason = .signingError
            }
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
    /// Any executable whose basename is `ssh` is treated as a possible forwarded-agent relay.
    static func signatureReason(keyLabel: String, requester: String, processPath: String) -> String {
        let url = URL(fileURLWithPath: processPath).standardizedFileURL
        if url.lastPathComponent == "ssh" {
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
    /// sanitized executable path and PID. Control, newline, format, and bidi characters are
    /// stripped. Long paths keep their tail (about 80 characters) with a visible ellipsis
    /// so two executables that share a basename still look different.
    static func requesterDescription(processPath: String, pid: pid_t) -> String {
        let cleaned = String(String.UnicodeScalarView(processPath.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
                && !CharacterSet.newlines.contains($0)
                && !Self.isBidiScalar($0)
                && $0.properties.generalCategory != .format
                && $0.properties.generalCategory != .control
                && $0.properties.generalCategory != .lineSeparator
                && $0.properties.generalCategory != .paragraphSeparator
        }))
        let maxLength = 80
        let bounded: String
        if cleaned.count > maxLength {
            bounded = "…" + String(cleaned.suffix(maxLength - 1))
        } else {
            bounded = cleaned
        }
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
    private func promptedSign(
        key: Ed25519KeyInfo,
        data: Data,
        prompt: String,
        requester: SigningPromptGate.Requester? = nil,
        clientSocket: Int32? = nil
    ) throws -> Data {
        try promptGate.run(requester: requester, clientSocket: clientSocket) {
            try keyManager.signSSH(
                key: key,
                data: data,
                prompt: prompt,
                useCache: false,
                existingContext: nil,
                allowedPurposes: role.allowedPurposes
            )
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
