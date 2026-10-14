import Foundation
import Darwin

/// Encapsulates POSIX AF_UNIX listener lifecycle, permission checks, accept loop,
/// per-PID connection limits, timeouts, and wire framing.
public final class UnixSocketServer {
    public struct Configuration: Sendable {
        public let socketPath: String
        public let maxClients: Int
        public let maxClientsPerPID: Int
        public let clientLifetime: TimeInterval
        public let maxRequestsPerConnection: Int
        public let clientTimeout: TimeInterval

        public init(
            socketPath: String,
            maxClients: Int = 32,
            maxClientsPerPID: Int = 8,
            clientLifetime: TimeInterval = 120.0,
            maxRequestsPerConnection: Int = 200,
            clientTimeout: TimeInterval = 30.0
        ) {
            self.socketPath = socketPath
            self.maxClients = maxClients
            self.maxClientsPerPID = maxClientsPerPID
            self.clientLifetime = clientLifetime
            self.maxRequestsPerConnection = maxRequestsPerConnection
            self.clientTimeout = clientTimeout
        }
    }

    public typealias RequestHandler = (
        _ payload: Data,
        _ clientPid: pid_t?,
        _ clientExecutablePath: String?,
        _ clientStartTime: UInt64?,
        _ clientSocket: Int32,
        _ connection: AgentConnectionState,
        _ isTrustedControlPeer: @escaping () -> Bool
    ) -> Data

    public typealias SimpleClientHandler = (Int32, pid_t, Data?) -> Void

    public let configuration: Configuration
    public var socketPath: String { configuration.socketPath }
    public var maxConcurrentClients: Int { configuration.maxClients }
    public var maxConcurrentClientsPerPID: Int { configuration.maxClientsPerPID }
    public var clientIdleTimeout: TimeInterval { configuration.clientTimeout }
    public let handshakeTimeout: TimeInterval
    public var maxConnectionLifetime: TimeInterval { configuration.clientLifetime }
    public var maxRequestsPerConnection: Int { configuration.maxRequestsPerConnection }

    public let logger: (String) -> Void
    private let controlPeerValidator: (Int32) -> Bool
    private let peerProcessValidator: (pid_t, String, UInt64) -> Bool
    private let backoffHandler: (useconds_t) -> Void
    private let acceptCall: (Int32) -> (fd: Int32, err: Int32)
    private let clientHandler: SimpleClientHandler?
    private let requestHandler: RequestHandler?

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

    private let queue = DispatchQueue(label: "com.clavis.unix-socket-server", attributes: .concurrent)

    public init(
        configuration: Configuration,
        clientHandler: @escaping SimpleClientHandler,
        logger: @escaping (String) -> Void = { _ in }
    ) {
        self.configuration = configuration
        self.handshakeTimeout = 2.0
        self.logger = logger
        self.controlPeerValidator = { ClavisCodeTrust.isTrustedPeer(socket: $0) }
        self.peerProcessValidator = { ProcessInspector.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }
        self.backoffHandler = { usleep($0) }
        self.acceptCall = { sock in
            let fd = accept(sock, nil, nil)
            return (fd, errno)
        }
        self.clientHandler = clientHandler
        self.requestHandler = nil
        self._onPermanentListenerFailure = nil
    }

    public init(
        configuration: Configuration,
        handshakeTimeout: TimeInterval = 2.0,
        controlPeerValidator: ((Int32) -> Bool)? = nil,
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil,
        backoffHandler: ((useconds_t) -> Void)? = nil,
        acceptCall: ((Int32) -> (fd: Int32, err: Int32))? = nil,
        onPermanentListenerFailure: (() -> Void)? = nil,
        logger: @escaping (String) -> Void = { _ in },
        clientHandler: SimpleClientHandler? = nil,
        requestHandler: RequestHandler? = nil
    ) {
        self.configuration = configuration
        self.handshakeTimeout = max(0.05, min(configuration.clientTimeout, handshakeTimeout))
        self.logger = logger
        self.controlPeerValidator = controlPeerValidator ?? { ClavisCodeTrust.isTrustedPeer(socket: $0) }
        self.peerProcessValidator = peerProcessValidator ?? { ProcessInspector.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }
        self.backoffHandler = backoffHandler ?? { usleep($0) }
        self.acceptCall = acceptCall ?? { sock in
            let fd = accept(sock, nil, nil)
            return (fd, errno)
        }
        self.clientHandler = clientHandler
        self.requestHandler = requestHandler
        self._onPermanentListenerFailure = onPermanentListenerFailure
    }

    public convenience init(
        socketPath: String,
        maxConcurrentClients: Int = 32,
        maxConcurrentClientsPerPID: Int = 8,
        clientIdleTimeout: TimeInterval = 30.0,
        handshakeTimeout: TimeInterval = 2.0,
        maxConnectionLifetime: TimeInterval = 120.0,
        maxRequestsPerConnection: Int = 200,
        controlPeerValidator: ((Int32) -> Bool)? = nil,
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil,
        backoffHandler: ((useconds_t) -> Void)? = nil,
        acceptCall: ((Int32) -> (fd: Int32, err: Int32))? = nil,
        onPermanentListenerFailure: (() -> Void)? = nil,
        logger: @escaping (String) -> Void = { _ in },
        requestHandler: RequestHandler? = nil
    ) {
        let config = Configuration(
            socketPath: socketPath,
            maxClients: maxConcurrentClients,
            maxClientsPerPID: maxConcurrentClientsPerPID,
            clientLifetime: maxConnectionLifetime,
            maxRequestsPerConnection: maxRequestsPerConnection,
            clientTimeout: clientIdleTimeout
        )
        self.init(
            configuration: config,
            handshakeTimeout: handshakeTimeout,
            controlPeerValidator: controlPeerValidator,
            peerProcessValidator: peerProcessValidator,
            backoffHandler: backoffHandler,
            acceptCall: acceptCall,
            onPermanentListenerFailure: onPermanentListenerFailure,
            logger: logger,
            clientHandler: nil,
            requestHandler: requestHandler
        )
    }

    public var isSocketActive: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isRunning && _serverSocket >= 0
    }

    public var boundInode: ino_t? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _boundInode
    }

    public var boundDevice: dev_t? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _boundDevice
    }

    public var activeClientCount: Int {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _activeClientCount
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

    public func reserveClientSlot(for pid: pid_t) -> Bool {
        reserveClientSlot(clientPid: pid)
    }

    public func releaseClientSlot(for pid: pid_t) {
        releaseClientSlot(clientPid: pid)
    }

    public func reserveClientSlot(clientPid: pid_t? = nil) -> Bool {
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

    public func releaseClientSlot(clientPid: pid_t? = nil) {
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
                let clientExecutablePath = clientPid.flatMap { ProcessInspector.getProcessPath(pid: $0) }
                let clientStartTime = clientPid.flatMap { ProcessInspector.processStartTime(pid: $0) }

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

    internal func handleClient(
        socket clientSocket: Int32,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil
    ) {
        defer { close(clientSocket) }

        if let clientHandler = self.clientHandler, self.requestHandler == nil {
            clientHandler(clientSocket, clientPid ?? 0, nil)
            return
        }

        guard let requestHandler = self.requestHandler else { return }

        let connection = AgentConnectionState()
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

            let response = requestHandler(
                payload,
                clientPid,
                clientExecutablePath,
                clientStartTime,
                clientSocket,
                connection,
                { self.controlPeerValidator(clientSocket) }
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

    public func configureTimeouts(for socket: Int32, timeoutInterval: TimeInterval) -> Bool {
        let seconds = floor(timeoutInterval)
        var timeout = timeval(
            tv_sec: Int(seconds),
            tv_usec: Int32((timeoutInterval - seconds) * 1_000_000)
        )
        let timeoutSize = socklen_t(MemoryLayout<timeval>.size)
        return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeoutSize) == 0 &&
            setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeoutSize) == 0
    }

    public func readFullBytes(from fd: Int32, buffer: UnsafeMutableRawPointer, count: Int) -> Bool {
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

    public func writeFullBytes(to fd: Int32, buffer: UnsafeRawPointer, count: Int) -> Bool {
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

    /// Tests whether an active SSH agent server is listening on the given AF_UNIX socket.
    public static func isSocketListening(atPath path: String) -> Bool {
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

    /// Returns true if an errno indicates a permanent failure of the listening socket.
    public static func isPermanentSocketError(_ errorCode: Int32) -> Bool {
        errorCode == EBADF || errorCode == EINVAL || errorCode == ENOTSOCK
    }
}
