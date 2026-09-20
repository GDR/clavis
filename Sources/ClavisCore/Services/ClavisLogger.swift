import Foundation

public struct ClavisLogger {
    private static let lock = NSLock()
    private static let defaultMaximumLogFileSize: UInt64 = 1_048_576
    private static let retainedLogFileCount = 3
    private static let maximumMessageBytes = 8_192
    private static var _customLogFileURL: URL?
    private static var _customMaximumLogFileSize: UInt64?

    public static var customLogFileURL: URL? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _customLogFileURL
        }
        set {
            lock.lock()
            _customLogFileURL = newValue
            lock.unlock()
        }
    }

    internal static var customMaximumLogFileSize: UInt64? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _customMaximumLogFileSize
        }
        set {
            lock.lock()
            _customMaximumLogFileSize = newValue
            lock.unlock()
        }
    }

    public static var logFileURL: URL {
        lock.lock()
        defer { lock.unlock() }
        return resolvedLogFileURL()
    }

    private static func resolvedLogFileURL() -> URL {
        if let customLogFileURL = _customLogFileURL { return customLogFileURL }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        return dir.appendingPathComponent("clavis.log")
    }

    public enum Category: String {
        case security = "SECURITY"
        case sshAgent = "SSH_AGENT"
        case sshAgentReq = "SSH_AGENT_REQ"
        case sshAgentSign = "SSH_AGENT_SIGN"
        case sshAgentIdentities = "SSH_AGENT_IDENTITIES"
        case sshAgentLimit = "SSH_AGENT_LIMIT"
        case agentDaemon = "AGENT_DAEMON"
        case keychainWrite = "KEYCHAIN_WRITE"
        case keychainMigrate = "KEYCHAIN_MIGRATE"
        case fetchKey = "FETCH_KEY"
        case fetchKeySuccess = "FETCH_KEY_SUCCESS"
        case keyList = "KEY_LIST"
        case keyDelete = "KEY_DELETE"
        case seedStore = "SEED_STORE"
        case gitGrace = "GIT_GRACE"
        case lock = "LOCK"
        case touchIdPrompt = "TOUCH_ID_PROMPT"
        case touchIdResult = "TOUCH_ID_RESULT"
        case securityAlert = "SECURITY_ALERT"
    }

    public static func log(_ category: Category, _ message: String) {
        log(category.rawValue, message)
    }

    public static func log(_ category: String, _ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let timestamp = formatter.string(from: Date())
        let safeCategory = singleLine(category)
        let safeMessage = String(decoding: singleLine(message).utf8.prefix(maximumMessageBytes), as: UTF8.self)
        let line = "[\(timestamp)] [\(safeCategory)] \(safeMessage)\n"
        print(line, terminator: "")

        let data = Data(line.utf8)
        lock.lock()
        defer { lock.unlock() }

        let url = resolvedLogFileURL()
        guard prepareLogDirectory(for: url) else { return }
        rotateIfNeeded(
            url: url,
            incomingByteCount: UInt64(data.count),
            maximumFileSize: _customMaximumLogFileSize ?? defaultMaximumLogFileSize
        )

        let descriptor = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }

        fchmod(descriptor, S_IRUSR | S_IWUSR)
        data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            var written = 0
            while written < bytes.count {
                let result = write(descriptor, baseAddress.advanced(by: written), bytes.count - written)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { break }
                written += result
            }
        }
    }

    private static func singleLine(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n")
    }

    private static func prepareLogDirectory(for url: URL) -> Bool {
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            return true
        } catch {
            return false
        }
    }

    private static func rotateIfNeeded(url: URL, incomingByteCount: UInt64, maximumFileSize: UInt64) {
        let fileSize = ((try? FileManager.default.attributesOfItem(atPath: url.path)[.size]) as? NSNumber)?.uint64Value ?? 0
        guard fileSize > 0, fileSize + incomingByteCount > maximumFileSize else { return }

        let fileManager = FileManager.default
        let oldestURL = rotatedURL(for: url, index: retainedLogFileCount)
        try? fileManager.removeItem(at: oldestURL)

        if retainedLogFileCount > 1 {
            for index in stride(from: retainedLogFileCount - 1, through: 1, by: -1) {
                let source = rotatedURL(for: url, index: index)
                let destination = rotatedURL(for: url, index: index + 1)
                if fileManager.fileExists(atPath: source.path) {
                    try? fileManager.moveItem(at: source, to: destination)
                }
            }
        }

        if fileManager.fileExists(atPath: url.path) {
            try? fileManager.moveItem(at: url, to: rotatedURL(for: url, index: 1))
        }
    }

    private static func rotatedURL(for url: URL, index: Int) -> URL {
        URL(fileURLWithPath: "\(url.path).\(index)")
    }
}
