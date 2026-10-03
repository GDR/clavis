import Foundation

public struct ClavisLogger {
    private static let lock = NSLock()
    private static let defaultMaximumLogFileSize: UInt64 = 1_048_576
    private static let retainedLogFileCount = 3
    /// The security audit log retains up to 10 rotated files (each bounded by `effectiveMaximumLogFileSize`).
    /// It only mirrors high-value security events (alerts, locks, git grace sessions, key deletions,
    /// authentication outcomes, and authorized signature initiations/completions). Unauthenticated requests
    /// and routine operational traffic are excluded. Repeated identical mirrored events within a 60-second window
    /// are collapsed to guarantee that high-frequency noise cannot rotate critical security audit evidence away.
    private static let retainedSecurityLogFileCount = 10
    private static let maximumMessageBytes = 8_192
    private static var _customLogFileURL: URL?
    private static var _customMaximumLogFileSize: UInt64?

    private struct MirroredRepeatKey: Hashable {
        let category: String
        let message: String
    }

    private struct MirroredRepeatState {
        var count: Int
        var firstSeen: Date
        var lastSeen: Date
    }

    private static let defaultRepeatWindowSeconds: TimeInterval = 60.0
    internal static var customRepeatWindow: TimeInterval?
    private static var effectiveRepeatWindow: TimeInterval {
        customRepeatWindow ?? defaultRepeatWindowSeconds
    }
    private static let maxTrackedRepeatEntries = 64

    private static var activeRepeats: [MirroredRepeatKey: MirroredRepeatState] = [:]
    private static var lastMirroredKey: MirroredRepeatKey?
    private static var repeatExpiryWorkItem: DispatchWorkItem?

    public static var customLogFileURL: URL? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _customLogFileURL
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _customLogFileURL = newValue
            if newValue == nil {
                resetStateLocked()
            }
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

    /// Categories mirrored into the separate, longer-retained security log.
    private static let securityCategories: Set<String> = [
        "SECURITY", "SECURITY_ALERT", "LOCK", "GIT_GRACE",
        "TOUCH_ID_RESULT", "KEY_DELETE"
    ]

    private static func isMirroredSecurityEvent(category: String, message: String) -> Bool {
        if category == "SSH_AGENT_SIGN" {
            return message.hasPrefix("Signature completed successfully") || message.hasPrefix("Initiating signature")
        }
        return securityCategories.contains(category)
    }

    /// High-frequency, low-value categories. These are dropped unless verbose logging is on, so
    /// they cannot flood the log or leak per-request metadata by default.
    private static let verboseOnlyCategories: Set<String> = [
        "SSH_AGENT_REQ", "SSH_AGENT_IDENTITIES", "KEY_LIST"
    ]

    /// Enabled with `CLAVIS_VERBOSE_LOG=1` for troubleshooting.
    public static var isVerboseLoggingEnabled: Bool {
        if let override = _customVerbose { return override }
        return ProcessInfo.processInfo.environment["CLAVIS_VERBOSE_LOG"] == "1"
    }

    private static var _customVerbose: Bool?
    internal static var customVerbose: Bool? {
        get { lock.lock(); defer { lock.unlock() }; return _customVerbose }
        set { lock.lock(); _customVerbose = newValue; lock.unlock() }
    }

    public static var securityLogFileURL: URL {
        lock.lock()
        defer { lock.unlock() }
        return securityURL(for: resolvedLogFileURL())
    }

    private static func securityURL(for generalURL: URL) -> URL {
        let base = generalURL.deletingPathExtension().lastPathComponent
        return generalURL.deletingLastPathComponent().appendingPathComponent("\(base).security.log")
    }

    public enum Category: String {
        case security = "SECURITY"
        case sshAgent = "SSH_AGENT"
        case sshAgentReq = "SSH_AGENT_REQ"
        case sshAgentSign = "SSH_AGENT_SIGN"
        case sshAgentReject = "SSH_AGENT_REJECT"
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
        if verboseOnlyCategories.contains(category) && !isVerboseLoggingEnabled { return }

        let now = Date()
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let timestamp = formatter.string(from: now)
        let safeCategory = singleLine(category)
        let safeMessage = String(decoding: singleLine(message).utf8.prefix(maximumMessageBytes), as: UTF8.self)
        let line = "[\(timestamp)] [\(safeCategory)] \(safeMessage)\n"
        print(line, terminator: "")

        let data = Data(line.utf8)
        let isSecurityEvent = isMirroredSecurityEvent(category: safeCategory, message: safeMessage)

        lock.lock()
        defer { lock.unlock() }

        let url = resolvedLogFileURL()
        append(data, to: url, retainedFiles: retainedLogFileCount)
        if isSecurityEvent {
            handleMirroredSecurityEventLocked(
                category: safeCategory,
                message: safeMessage,
                data: data,
                timestamp: now,
                secURL: securityURL(for: url)
            )
        }
    }

    /// Must be called with `lock` held.
    private static func append(_ data: Data, to url: URL, retainedFiles: Int) {
        guard prepareLogDirectory(for: url) else { return }

        var checkStat = stat()
        if lstat(url.path, &checkStat) == 0 {
            guard (checkStat.st_mode & S_IFMT) == S_IFREG else { return }
        }

        rotateIfNeeded(
            url: url,
            incomingByteCount: UInt64(data.count),
            maximumFileSize: effectiveMaximumLogFileSize,
            retainedFiles: retainedFiles
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

    public static func rotatedSecurityLogFiles() -> [URL] {
        lock.lock()
        defer { lock.unlock() }
        flushAllPendingRepeatsLocked()

        let url = securityURL(for: resolvedLogFileURL())
        let fm = FileManager.default
        var files: [URL] = []
        if fm.fileExists(atPath: url.path) {
            files.append(url)
        }
        for index in 1...retainedSecurityLogFileCount {
            let rotURL = rotatedURL(for: url, index: index)
            if fm.fileExists(atPath: rotURL.path) {
                files.append(rotURL)
            }
        }
        return files
    }

    public static func flush() {
        lock.lock()
        defer { lock.unlock() }
        flushAllPendingRepeatsLocked()
    }

    /// Must be called with `lock` held.
    private static func handleMirroredSecurityEventLocked(
        category: String,
        message: String,
        data: Data,
        timestamp: Date,
        secURL: URL
    ) {
        flushExpiredRepeatsLocked(currentTime: timestamp, to: secURL)

        let key = MirroredRepeatKey(category: category, message: message)
        let window = effectiveRepeatWindow

        // If the last mirrored message was different and had repetitions, flush its summary now.
        if let last = lastMirroredKey, last != key {
            if let lastState = activeRepeats[last], lastState.count > 0 {
                writeRepeatSummaryLocked(key: last, count: lastState.count, timestamp: timestamp, to: secURL)
            }
            activeRepeats.removeValue(forKey: last)
        }

        if var existing = activeRepeats[key], timestamp.timeIntervalSince(existing.firstSeen) < window {
            // Drop identical message within the window and increment count.
            existing.count += 1
            existing.lastSeen = timestamp
            activeRepeats[key] = existing
            lastMirroredKey = key
            scheduleExpiryTimerLocked(after: window)
            return
        }

        // If key existed but its window expired, write any pending repeat summary before writing new line
        if let existing = activeRepeats[key], existing.count > 0 {
            writeRepeatSummaryLocked(key: key, count: existing.count, timestamp: timestamp, to: secURL)
            activeRepeats.removeValue(forKey: key)
        }

        // Write first occurrence to security log
        append(data, to: secURL, retainedFiles: retainedSecurityLogFileCount)
        activeRepeats[key] = MirroredRepeatState(count: 0, firstSeen: timestamp, lastSeen: timestamp)
        lastMirroredKey = key

        // Enforce bounded dictionary size
        if activeRepeats.count > maxTrackedRepeatEntries {
            if let (oldestKey, oldestState) = activeRepeats.min(by: { $0.value.firstSeen < $1.value.firstSeen }) {
                if oldestState.count > 0 {
                    writeRepeatSummaryLocked(key: oldestKey, count: oldestState.count, timestamp: timestamp, to: secURL)
                }
                activeRepeats.removeValue(forKey: oldestKey)
                if lastMirroredKey == oldestKey {
                    lastMirroredKey = nil
                }
            }
        }

        scheduleExpiryTimerLocked(after: window)
    }

    /// Must be called with `lock` held.
    private static func flushExpiredRepeatsLocked(currentTime: Date, to secURL: URL) {
        let window = effectiveRepeatWindow
        var expiredKeys: [MirroredRepeatKey] = []
        for (key, state) in activeRepeats {
            if currentTime.timeIntervalSince(state.firstSeen) >= window {
                if state.count > 0 {
                    writeRepeatSummaryLocked(key: key, count: state.count, timestamp: currentTime, to: secURL)
                }
                expiredKeys.append(key)
            }
        }
        for key in expiredKeys {
            activeRepeats.removeValue(forKey: key)
            if lastMirroredKey == key {
                lastMirroredKey = nil
            }
        }
    }

    /// Must be called with `lock` held.
    private static func writeRepeatSummaryLocked(key: MirroredRepeatKey, count: Int, timestamp: Date, to secURL: URL) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let timestampStr = formatter.string(from: timestamp)
        let summaryLine = "[\(timestampStr)] [\(key.category)] ... (repeated \(count) times)\n"
        let data = Data(summaryLine.utf8)
        append(data, to: secURL, retainedFiles: retainedSecurityLogFileCount)
    }

    /// Must be called with `lock` held.
    private static func scheduleExpiryTimerLocked(after interval: TimeInterval) {
        repeatExpiryWorkItem?.cancel()
        let workItem = DispatchWorkItem {
            lock.lock()
            defer { lock.unlock() }
            let now = Date()
            let url = securityURL(for: resolvedLogFileURL())
            flushExpiredRepeatsLocked(currentTime: now, to: url)
        }
        repeatExpiryWorkItem = workItem
        DispatchQueue.global().asyncAfter(deadline: .now() + interval, execute: workItem)
    }

    /// Must be called with `lock` held.
    private static func flushAllPendingRepeatsLocked() {
        repeatExpiryWorkItem?.cancel()
        repeatExpiryWorkItem = nil
        let now = Date()
        let url = securityURL(for: resolvedLogFileURL())
        for (key, state) in activeRepeats {
            if state.count > 0 {
                writeRepeatSummaryLocked(key: key, count: state.count, timestamp: now, to: url)
            }
        }
        activeRepeats.removeAll()
        lastMirroredKey = nil
    }

    private static func resetStateLocked() {
        repeatExpiryWorkItem?.cancel()
        repeatExpiryWorkItem = nil
        activeRepeats.removeAll()
        lastMirroredKey = nil
        customRepeatWindow = nil
    }

    internal static func resetForTesting() {
        lock.lock()
        defer { lock.unlock() }
        resetStateLocked()
    }



    public static func singleLine(_ value: String) -> String {
        var result = ""
        result.reserveCapacity(value.utf8.count)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x0A: // newline
                result.append("\\n")
            case 0x0D: // carriage return
                result.append("\\r")
            case 0x09: // horizontal tab
                result.append("\\t")
            default:
                if isControlOrFormat(scalar) {
                    result.append(String(format: "\\u{%04X}", scalar.value))
                } else {
                    result.append(Character(scalar))
                }
            }
        }
        return result
    }

    /// Returns true if `scalar` is a control character, Unicode format character (Cf),
    /// or Unicode bidi/line/paragraph separator.
    public static func isControlOrFormat(_ scalar: Unicode.Scalar) -> Bool {
        let cat = scalar.properties.generalCategory
        if cat == .control || cat == .format || cat == .lineSeparator || cat == .paragraphSeparator {
            return true
        }
        switch scalar.value {
        case 0x0000...0x001F, 0x007F...0x009F:
            return true
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return true
        case 0x2028, 0x2029:
            return true
        default:
            return false
        }
    }

    /// Sanitizes multi-line log output for terminal or CLI display, preserving normal newlines
    /// while escaping embedded control characters, bidi overrides, and format separators.
    public static func sanitizeLogContent(_ content: String) -> String {
        let lines = content.components(separatedBy: "\n")
        return lines.map { singleLine($0) }.joined(separator: "\n")
    }

    private static func prepareLogDirectory(for url: URL) -> Bool {
        let directory = url.deletingLastPathComponent()
        do {
            try SecureFS.createDirectory(at: directory)
            return SecureFS.isDirectorySecure(at: directory)
        } catch {
            return false
        }
    }

    private static func rotateIfNeeded(url: URL, incomingByteCount: UInt64, maximumFileSize: UInt64, retainedFiles: Int) {
        var statBuf = stat()
        guard lstat(url.path, &statBuf) == 0 else { return }
        guard (statBuf.st_mode & S_IFMT) == S_IFREG else { return }

        let fileSize = UInt64(statBuf.st_size)
        guard fileSize > 0, fileSize + incomingByteCount > maximumFileSize else { return }

        let lockPath = url.path + ".lock"
        let lockFd = SecureFS.openLockFile(path: lockPath, flags: O_WRONLY | O_CREAT, mode: S_IRUSR | S_IWUSR)
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

            performRotation(url: url, retainedFiles: retainedFiles)
        }
    }

    private static func performRotation(url: URL, retainedFiles: Int) {
        let fileManager = FileManager.default
        let oldestURL = rotatedURL(for: url, index: retainedFiles)
        try? fileManager.removeItem(at: oldestURL)

        if retainedFiles > 1 {
            for index in stride(from: retainedFiles - 1, through: 1, by: -1) {
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
