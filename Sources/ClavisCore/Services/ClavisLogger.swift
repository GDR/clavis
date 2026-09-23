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

        var checkStat = stat()
        if lstat(url.path, &checkStat) == 0 {
            guard (checkStat.st_mode & S_IFMT) == S_IFREG else { return }
        }

        rotateIfNeeded(
            url: url,
            incomingByteCount: UInt64(data.count),
            maximumFileSize: effectiveMaximumLogFileSize
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

    public static var effectiveMaximumLogFileSize: UInt64 {
        if let custom = _customMaximumLogFileSize { return custom }
        if let envStr = ProcessInfo.processInfo.environment["CLAVIS_MAX_LOG_SIZE"],
           let envVal = UInt64(envStr), envVal >= 1024 {
            return envVal
        }
        return defaultMaximumLogFileSize
    }

    public static func rotatedLogFiles() -> [URL] {
        lock.lock()
        defer { lock.unlock() }
        let url = resolvedLogFileURL()
        let fm = FileManager.default
        var files: [URL] = []
        if fm.fileExists(atPath: url.path) {
            files.append(url)
        }
        for index in 1...retainedLogFileCount {
            let rotURL = rotatedURL(for: url, index: index)
            if fm.fileExists(atPath: rotURL.path) {
                files.append(rotURL)
            }
        }
        return files
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
        var statBuf = stat()
        guard lstat(url.path, &statBuf) == 0 else { return }
        guard (statBuf.st_mode & S_IFMT) == S_IFREG else { return }

        let fileSize = UInt64(statBuf.st_size)
        guard fileSize > 0, fileSize + incomingByteCount > maximumFileSize else { return }

        let lockPath = url.path + ".lock"
        let lockFd = open(lockPath, O_WRONLY | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        if lockFd >= 0 {
            flock(lockFd, LOCK_EX)
            defer {
                flock(lockFd, LOCK_UN)
                close(lockFd)
            }

            var currentStat = stat()
            guard lstat(url.path, &currentStat) == 0,
                  (currentStat.st_mode & S_IFMT) == S_IFREG else { return }
            let currentSize = UInt64(currentStat.st_size)
            guard currentSize > 0, currentSize + incomingByteCount > maximumFileSize else { return }

            performRotation(url: url)
        }
    }

    private static func performRotation(url: URL) {
        let fileManager = FileManager.default
        let oldestURL = rotatedURL(for: url, index: retainedLogFileCount)
        try? fileManager.removeItem(at: oldestURL)

        if retainedLogFileCount > 1 {
            for index in stride(from: retainedLogFileCount - 1, through: 1, by: -1) {
                let source = rotatedURL(for: url, index: index)
                let destination = rotatedURL(for: url, index: index + 1)
                if fileManager.fileExists(atPath: source.path) {
                    try? fileManager.moveItem(at: source, to: destination)
                    try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
                }
            }
        }

        if fileManager.fileExists(atPath: url.path) {
            let firstRotated = rotatedURL(for: url, index: 1)
            try? fileManager.moveItem(at: url, to: firstRotated)
            try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: firstRotated.path)
        }
    }

    private static func rotatedURL(for url: URL, index: Int) -> URL {
        URL(fileURLWithPath: "\(url.path).\(index)")
    }
}
