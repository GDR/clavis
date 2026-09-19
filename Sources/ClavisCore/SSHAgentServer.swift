import Foundation
import Network

public class SSHAgentServer {
    public static let shared = SSHAgentServer()
    public static let sharedInstance = shared
    public static let defaultSocketPath = NSString(string: "~/.ssh/clavis.sock").expandingTildeInPath

    private let socketPath: String
    private let stateLock = NSLock()
    private var _serverSocket: Int32 = -1
    private var _isRunning = false
    private let queue = DispatchQueue(label: "com.clavis.ssh-agent", attributes: .concurrent)

    public init(socketPath: String = SSHAgentServer.defaultSocketPath) {
        self.socketPath = socketPath
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
            try fileManager.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: nil)
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

    private func acceptLoop() {
        while isRunning {
            let listeningSock = serverSocket
            guard listeningSock >= 0 else { break }
            let clientSocket = accept(listeningSock, nil, nil)
            if clientSocket >= 0 {
                var optval: Int32 = 1
                setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &optval, socklen_t(MemoryLayout<Int32>.size))
                queue.async {
                    self.handleClient(socket: clientSocket)
                }
            }
        }
    }

    private func handleClient(socket clientSocket: Int32) {
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

            let response = processAgentRequest(payload: payload)
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

    internal func processAgentRequest(payload: Data) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]
        ClavisLogger.log("SSH_AGENT_REQ", "Received SSH Agent request type \(msgType)")

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            return handleRequestIdentities()
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(payload: Data(payload.dropFirst()))
        default:
            ClavisLogger.log("SSH_AGENT_REQ", "Unsupported SSH Agent request type \(msgType)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    internal func handleRequestIdentities() -> Data {
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "Listing active SSH identities...")
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

    internal func handleSignRequest(payload: Data) -> Data {
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

        ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key '\(matchingKey.label)'...")
        do {
            let sigBlob = try KeychainManager.shared.signSSH(
                key: matchingKey,
                data: dataToSign,
                prompt: "Touch ID to approve SSH signature for key '\(matchingKey.label)'"
            )

            var response = Data()
            response.append(14) // SSH2_AGENT_SIGN_RESPONSE
            response.appendWireData(sigBlob)
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature completed successfully for '\(matchingKey.label)'.")
            return response
        } catch {
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature failed for '\(matchingKey.label)': \(error.localizedDescription)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }
}

public struct DataReader {
    private let data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    public mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.endIndex else { return nil }
        var value: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &value) { ptr in
            data.copyBytes(to: ptr, from: offset..<offset+4)
        }
        offset += 4
        return UInt32(bigEndian: value)
    }

    public mutating func readWireData() -> Data? {
        guard let length32 = readUInt32() else { return nil }
        let length = Int(length32)
        guard length >= 0, offset + length <= data.endIndex else { return nil }
        let result = Data(data.subdata(in: offset..<offset+length))
        offset += length
        return result
    }

    public mutating func readWireString() -> String? {
        guard let data = readWireData() else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
