import Foundation
import Network

public class SSHAgentServer {
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
        isRunning = false
        let sock = serverSocket
        if sock >= 0 {
            close(sock)
            serverSocket = -1
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
                var nosigpipe = 1
                setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))
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
            let success = payload.withUnsafeMutableBytes { ptr -> Bool in
                guard let base = ptr.baseAddress else { return false }
                return readFullBytes(from: clientSocket, buffer: base, count: msgLength)
            }
            if !success { break }

            let response = processAgentRequest(payload: payload)
            var responseLen = UInt32(response.count).bigEndian
            Swift.withUnsafeBytes(of: &responseLen) { ptr in
                _ = write(clientSocket, ptr.baseAddress!, 4)
            }
            _ = response.withUnsafeBytes { ptr in
                write(clientSocket, ptr.baseAddress!, response.count)
            }
        }
    }

    private func readFullBytes(from fd: Int32, buffer: UnsafeMutableRawPointer, count: Int) -> Bool {
        var bytesRead = 0
        while bytesRead < count {
            let result = read(fd, buffer.advanced(by: bytesRead), count - bytesRead)
            if result <= 0 { return false }
            bytesRead += result
        }
        return true
    }

    private func processAgentRequest(payload: Data) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            return handleRequestIdentities()
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(payload: payload.dropFirst())
        default:
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    private func handleRequestIdentities() -> Data {
        let keys = (try? KeychainManager.shared.listKeys()) ?? []
        var response = Data()
        response.append(12) // SSH2_AGENT_IDENTITIES_ANSWER

        var count = UInt32(keys.count).bigEndian
        Swift.withUnsafeBytes(of: &count) { response.append(contentsOf: $0) }

        for key in keys {
            response.appendWireData(key.publicKeyBlob)
            response.appendWireString(key.label)
        }
        return response
    }

    private func handleSignRequest(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let keyBlob = reader.readWireData(),
              let dataToSign = reader.readWireData() else {
            return Data([5])
        }
        _ = reader.readUInt32() // Consume uint32 flags parameter

        let keys = (try? KeychainManager.shared.listKeys()) ?? []
        guard let matchingKey = keys.first(where: { $0.publicKeyBlob == keyBlob }) else {
            return Data([5])
        }

        do {
            let signature = try KeychainManager.shared.sign(
                label: matchingKey.label,
                data: dataToSign,
                prompt: "Touch ID to approve SSH signature for key '\(matchingKey.label)'"
            )

            var sigBlob = Data()
            sigBlob.appendWireString("ssh-ed25519")
            sigBlob.appendWireData(signature)

            var response = Data()
            response.append(14) // SSH2_AGENT_SIGN_RESPONSE
            response.appendWireData(sigBlob)
            return response
        } catch {
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }
}

public struct DataReader {
    private let data: Data
    private var offset: Int = 0

    public init(data: Data) {
        self.data = data
    }

    public mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        let value = data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        offset += 4
        return value
    }

    public mutating func readWireData() -> Data? {
        guard offset + 4 <= data.count else { return nil }
        let length = Int(data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
        offset += 4

        guard offset + length <= data.count else { return nil }
        let result = data.subdata(in: offset..<offset+length)
        offset += length
        return result
    }
}
