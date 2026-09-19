import Foundation
import Network

public class SSHAgentServer {
    public static let shared = SSHAgentServer()
    public static let sharedInstance = shared
    public static let defaultSocketPath = NSString(string: "~/.ssh/clavis.sock").expandingTildeInPath

    private let socketPath: String
    private let maxConcurrentClients: Int
    private let clientIdleTimeout: TimeInterval
    private let stateLock = NSLock()
    private var _serverSocket: Int32 = -1
    private var _isRunning = false
    private var _activeClientCount = 0
    private let queue = DispatchQueue(label: "com.clavis.ssh-agent", attributes: .concurrent)

    public init(
        socketPath: String = SSHAgentServer.defaultSocketPath,
        maxConcurrentClients: Int = 32,
        clientIdleTimeout: TimeInterval = 30
    ) {
        self.socketPath = socketPath
        self.maxConcurrentClients = max(1, maxConcurrentClients)
        self.clientIdleTimeout = max(0.1, clientIdleTimeout)
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
        let fileManager = FileManager.default
        unlink(socketPath)

        let dir = (socketPath as NSString).deletingLastPathComponent
        if !fileManager.fileExists(atPath: dir) {
            try fileManager.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } else {
            try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
        }

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"])
        }

        var nosigpipe = 1
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))

        self.serverSocket = sock

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Socket path too long"])
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
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "Failed to bind socket at \(socketPath)"])
        }

        // Enforce strict 0600 permissions on the created socket file (read/write only by owner)
        chmod(socketPath, S_IRUSR | S_IWUSR)

        guard listen(sock, 5) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "Failed to listen on socket"])
        }

        isRunning = true
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

                var optval: Int32 = 1
                setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &optval, socklen_t(MemoryLayout<Int32>.size))

                guard reserveClientSlot() else {
                    ClavisLogger.log("SSH_AGENT_LIMIT", "Rejected connection because the concurrent client limit was reached.")
                    close(clientSocket)
                    continue
                }

                configureTimeouts(for: clientSocket)
                queue.async {
                    defer { self.releaseClientSlot() }
                    self.handleClient(
                        socket: clientSocket,
                        clientPid: clientPid,
                        clientExecutablePath: clientExecutablePath
                    )
                }
            }
        }
    }

    private func reserveClientSlot() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard _activeClientCount < maxConcurrentClients else { return false }
        _activeClientCount += 1
        return true
    }

    private func releaseClientSlot() {
        stateLock.lock()
        _activeClientCount = max(0, _activeClientCount - 1)
        stateLock.unlock()
    }

    private func configureTimeouts(for socket: Int32) {
        let seconds = floor(clientIdleTimeout)
        var timeout = timeval(
            tv_sec: Int(seconds),
            tv_usec: Int32((clientIdleTimeout - seconds) * 1_000_000)
        )
        let timeoutSize = socklen_t(MemoryLayout<timeval>.size)
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeoutSize)
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeoutSize)
    }

    private func handleClient(
        socket clientSocket: Int32,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil
    ) {
        defer { close(clientSocket) }

        while isRunning {
            var lengthHeader = UInt32(0)
            if !readFullBytes(from: clientSocket, buffer: &lengthHeader, count: 4) {
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
                clientExecutablePath: clientExecutablePath
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

    internal func processAgentRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil
    ) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]
        ClavisLogger.log("SSH_AGENT_REQ", "Received SSH Agent request type \(msgType)")

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            return handleRequestIdentities(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath
            )
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
        let keys = (try? KeychainManager.shared.listKeys()) ?? []
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
              let _ = reader.readUInt32() else { // Consumes 4-byte flags parameter
            ClavisLogger.log("SSH_AGENT_SIGN", "Failed to parse sign request wire payload.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        let keys = (try? KeychainManager.shared.listKeys()) ?? []
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

        let prompt = "Touch ID to approve SSH signature for key '\(matchingKey.label)' requested by \(clientDesc)"
        ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key '\(matchingKey.label)' requested by \(clientDesc)...")
        do {
            let sigBlob = try KeychainManager.shared.signSSH(
                key: matchingKey,
                data: dataToSign,
                prompt: prompt,
                useCache: false
            )

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
}
