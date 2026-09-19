import Foundation
import CryptoKit
import AppKit
import Darwin

public enum SessionCacheError: LocalizedError, Equatable {
    case disabled
    case invalidated

    public var errorDescription: String? {
        switch self {
        case .disabled:
            return "Session caching is disabled; choose a timeout before unlocking a key"
        case .invalidated:
            return "The key operation was cancelled because the session was locked"
        }
    }
}

public class SessionCacheManager {
    public static let shared = SessionCacheManager()

    private var cache: [String: (buffer: SecureBuffer, expiresAt: Date, monotonicDeadline: DispatchTime)] = [:]
    private var p256Cache: [String: (key: CachedP256SigningKey, expiresAt: Date, monotonicDeadline: DispatchTime)] = [:]
    private var unlockedSessions: [String: (expiresAt: Date, monotonicDeadline: DispatchTime)] = [:]
    private let lock = NSLock()
    private let defaults: UserDefaults
    private var generation: UInt64 = 0

    private let timerQueue = DispatchQueue(label: "com.clavis.sessioncache.timer", qos: .userInitiated)
    private var cleanupTimer: DispatchSourceTimer?

    private static let userDefaultsKey = "com.clavis.sessionTimeout"

    private var _currentTimeout: SessionTimeout
    public var currentTimeout: SessionTimeout {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _currentTimeout
        }
        set {
            lock.lock()
            let oldTimeout = _currentTimeout
            _currentTimeout = newValue
            defaults.set(newValue.rawValue, forKey: Self.userDefaultsKey)
            lock.unlock()

            let shouldClear: Bool
            if newValue == .never {
                shouldClear = true
            } else if oldTimeout == .never {
                shouldClear = false
            } else {
                let oldInterval = oldTimeout.timeInterval ?? .infinity
                let newInterval = newValue.timeInterval ?? .infinity
                shouldClear = newInterval < oldInterval
            }

            if shouldClear {
                clearCache()
            }
        }
    }

    public init(defaults: UserDefaults = .standard, observeSystemEvents: Bool = true) {
        self.defaults = defaults
        if let saved = defaults.string(forKey: Self.userDefaultsKey),
           let timeout = SessionTimeout(rawValue: saved) {
            self._currentTimeout = timeout
        } else {
            self._currentTimeout = .fiveMinutes
        }

        // Single persistent timer created and resumed once for the entire lifetime of SessionCacheManager
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.setEventHandler { [weak self] in
            self?.purgeExpiredEntries()
        }
        timer.schedule(deadline: .distantFuture)
        timer.resume()
        self.cleanupTimer = timer

        if observeSystemEvents {
            DistributedNotificationCenter.default().addObserver(
                self,
                selector: #selector(clearCache),
                name: NSNotification.Name("com.apple.screenIsLocked"),
                object: nil,
                suspensionBehavior: .deliverImmediately
            )
            NSWorkspace.shared.notificationCenter.addObserver(
                self,
                selector: #selector(clearCache),
                name: NSWorkspace.willSleepNotification,
                object: nil
            )
        }
    }

    deinit {
        // 1. Exclude new timer operations
        cleanupTimer?.setEventHandler(handler: nil)

        // 2. Promptly wipe all remaining secrets from RAM
        for (_, entry) in cache {
            entry.buffer.wipe()
        }
        for (_, entry) in p256Cache {
            entry.key.wipe()
        }
        cache.removeAll()
        p256Cache.removeAll()
        unlockedSessions.removeAll()

        // 3. Cancel timer
        cleanupTimer?.cancel()
        cleanupTimer = nil

        // 4. Deregister all notification observers
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
    }

    @objc public func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        cleanupTimer?.schedule(deadline: .distantFuture)

        for (_, entry) in cache {
            entry.buffer.wipe()
        }
        for (_, entry) in p256Cache {
            entry.key.wipe()
        }
        cache.removeAll()
        p256Cache.removeAll()
        unlockedSessions.removeAll()
    }

    public func remove(label: String) {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        if let entry = cache.removeValue(forKey: label) {
            entry.buffer.wipe()
        }
        if let entry = p256Cache.removeValue(forKey: label) {
            entry.key.wipe()
        }
        unlockedSessions.removeValue(forKey: label)
        rescheduleCleanupTimerLocked()
    }

    public func isKeyUnlocked(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        let monoNow = DispatchTime.now()
        if let entry = cache[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow, !entry.buffer.isWiped {
            return true
        }
        if let entry = p256Cache[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped { return true }
            case .secureEnclave:
                return true
            }
        }
        if let entry = unlockedSessions[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow {
            return true
        }
        return false
    }

    public func remainingTime(label: String) -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        let monoNow = DispatchTime.now()
        if let entry = cache[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow, !entry.buffer.isWiped {
            return entry.expiresAt.timeIntervalSince(now)
        }
        if let entry = p256Cache[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped {
                    return entry.expiresAt.timeIntervalSince(now)
                }
            case .secureEnclave:
                return entry.expiresAt.timeIntervalSince(now)
            }
        }
        if let entry = unlockedSessions[label], entry.expiresAt > now, entry.monotonicDeadline > monoNow {
            return entry.expiresAt.timeIntervalSince(now)
        }
        return nil
    }

    public func unlockKey(label: String, duration: TimeInterval = 900) {
        lock.lock()
        defer { lock.unlock() }
        let expires = Date().addingTimeInterval(duration)
        let deadline = DispatchTime.now() + duration
        unlockedSessions[label] = (expires, deadline)
        rescheduleCleanupTimerLocked()
    }

    func getBuffer(label: String) -> SecureBuffer? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = cache[label] else { return nil }
        let now = Date()
        let monoNow = DispatchTime.now()
        if now > entry.expiresAt || monoNow >= entry.monotonicDeadline {
            entry.buffer.wipe()
            cache.removeValue(forKey: label)
            rescheduleCleanupTimerLocked()
            return nil
        }
        return entry.buffer
    }

    /// Runs an operation against a cached seed while holding the cache lock.
    /// A concurrent lock/expiry event therefore either happens before this
    /// method starts, or waits until the already-started operation completes.
    func withCachedBuffer<Result>(
        label: String,
        operation: (UnsafeRawBufferPointer) throws -> Result
    ) throws -> Result? {
        lock.lock()
        defer { lock.unlock() }

        guard _currentTimeout != .never, let entry = cache[label] else {
            return nil
        }

        let now = Date()
        let monoNow = DispatchTime.now()
        guard entry.expiresAt > now, entry.monotonicDeadline > monoNow else {
            cache.removeValue(forKey: label)
            unlockedSessions.removeValue(forKey: label)
            generation &+= 1
            entry.buffer.wipe()
            rescheduleCleanupTimerLocked()
            return nil
        }

        guard let result = try entry.buffer.withUnsafeBytes(operation) else {
            throw SessionCacheError.invalidated
        }
        return result
    }

    /// Atomically validates the generation, stores a seed buffer, and starts
    /// the first operation. Lock events cannot slip between those steps.
    func setAndWithBuffer<Result>(
        label: String,
        buffer: SecureBuffer,
        expectedGeneration: UInt64,
        operation: (UnsafeRawBufferPointer) throws -> Result
    ) throws -> Result {
        lock.lock()
        defer { lock.unlock() }

        guard expectedGeneration == generation, let timeout = _currentTimeout.timeInterval else {
            buffer.wipe()
            throw SessionCacheError.invalidated
        }

        if let old = cache.removeValue(forKey: label) {
            old.buffer.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        let deadline = DispatchTime.now() + timeout
        cache[label] = (buffer, expires, deadline)
        unlockedSessions[label] = (expires, deadline)
        rescheduleCleanupTimerLocked()

        guard let result = try buffer.withUnsafeBytes(operation) else {
            throw SessionCacheError.invalidated
        }
        return result
    }

    /// Serializes a non-cached operation with session invalidation.
    func performIfGenerationCurrent<Result>(
        _ expectedGeneration: UInt64,
        operation: () throws -> Result
    ) throws -> Result {
        lock.lock()
        defer { lock.unlock() }
        guard expectedGeneration == generation else {
            throw SessionCacheError.invalidated
        }
        return try operation()
    }

    public func generationSnapshot() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }

    public func isGenerationCurrent(_ expectedGeneration: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generation == expectedGeneration
    }

    @discardableResult
    func set(
        label: String,
        buffer: SecureBuffer,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        setInternal(label: label, buffer: buffer, expectedGeneration: expectedGeneration, timeoutOverride: nil)
    }

    @discardableResult
    func setInternal(
        label: String,
        buffer: SecureBuffer,
        expectedGeneration: UInt64? = nil,
        timeoutOverride: TimeInterval? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let expectedGeneration, expectedGeneration != generation {
            buffer.wipe()
            return false
        }
        guard let timeout = timeoutOverride ?? _currentTimeout.timeInterval else {
            buffer.wipe()
            return true
        }
        if let old = cache.removeValue(forKey: label) {
            old.buffer.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        let deadline = DispatchTime.now() + timeout
        cache[label] = (buffer, expires, deadline)
        unlockedSessions[label] = (expires, deadline)
        rescheduleCleanupTimerLocked()
        return true
    }

    @discardableResult
    func set(
        label: String,
        key: Curve25519.Signing.PrivateKey,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        setInternal(label: label, key: key, expectedGeneration: expectedGeneration, timeoutOverride: nil)
    }

    @discardableResult
    func setInternal(
        label: String,
        key: Curve25519.Signing.PrivateKey,
        expectedGeneration: UInt64? = nil,
        timeoutOverride: TimeInterval? = nil
    ) -> Bool {
        var raw = key.rawRepresentation
        defer {
            raw.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    SecureMemory.zero(base, byteCount: ptr.count)
                }
            }
        }
        guard let buffer = SecureBuffer(data: raw) else { return false }
        return setInternal(label: label, buffer: buffer, expectedGeneration: expectedGeneration, timeoutOverride: timeoutOverride)
    }

    func getP256(label: String) -> CachedP256SigningKey? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = p256Cache[label] else { return nil }
        let now = Date()
        let monoNow = DispatchTime.now()
        if now > entry.expiresAt || monoNow >= entry.monotonicDeadline {
            entry.key.wipe()
            p256Cache.removeValue(forKey: label)
            rescheduleCleanupTimerLocked()
            return nil
        }
        return entry.key
    }

    func withCachedP256<Result>(
        label: String,
        operation: (CachedP256SigningKey) throws -> Result
    ) throws -> Result? {
        lock.lock()
        defer { lock.unlock() }

        guard _currentTimeout != .never, let entry = p256Cache[label] else {
            return nil
        }

        let now = Date()
        let monoNow = DispatchTime.now()
        guard entry.expiresAt > now, entry.monotonicDeadline > monoNow else {
            p256Cache.removeValue(forKey: label)
            unlockedSessions.removeValue(forKey: label)
            generation &+= 1
            entry.key.wipe()
            rescheduleCleanupTimerLocked()
            return nil
        }

        return try operation(entry.key)
    }

    func setAndWithP256<Result>(
        label: String,
        key: CachedP256SigningKey,
        expectedGeneration: UInt64,
        operation: (CachedP256SigningKey) throws -> Result
    ) throws -> Result {
        lock.lock()
        defer { lock.unlock() }

        guard expectedGeneration == generation, let timeout = _currentTimeout.timeInterval else {
            key.wipe()
            throw SessionCacheError.invalidated
        }

        if let old = p256Cache.removeValue(forKey: label) {
            old.key.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        let deadline = DispatchTime.now() + timeout
        p256Cache[label] = (key, expires, deadline)
        unlockedSessions[label] = (expires, deadline)
        rescheduleCleanupTimerLocked()
        return try operation(key)
    }

    @discardableResult
    func setP256(
        label: String,
        key: CachedP256SigningKey,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        setP256Internal(label: label, key: key, expectedGeneration: expectedGeneration, timeoutOverride: nil)
    }

    @discardableResult
    func setP256Internal(
        label: String,
        key: CachedP256SigningKey,
        expectedGeneration: UInt64? = nil,
        timeoutOverride: TimeInterval? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let expectedGeneration, expectedGeneration != generation {
            key.wipe()
            return false
        }
        guard let timeout = timeoutOverride ?? _currentTimeout.timeInterval else {
            key.wipe()
            return true
        }
        if let old = p256Cache.removeValue(forKey: label) {
            old.key.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        let deadline = DispatchTime.now() + timeout
        p256Cache[label] = (key, expires, deadline)
        unlockedSessions[label] = (expires, deadline)
        rescheduleCleanupTimerLocked()
        return true
    }

    public var cachedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return 0 }
        let now = Date()
        let monoNow = DispatchTime.now()
        var activeLabels = Set<String>()
        for (lbl, entry) in cache where entry.expiresAt > now && entry.monotonicDeadline > monoNow && !entry.buffer.isWiped {
            activeLabels.insert(lbl)
        }
        for (lbl, entry) in p256Cache where entry.expiresAt > now && entry.monotonicDeadline > monoNow {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped { activeLabels.insert(lbl) }
            case .secureEnclave:
                activeLabels.insert(lbl)
            }
        }
        for (lbl, entry) in unlockedSessions where entry.expiresAt > now && entry.monotonicDeadline > monoNow {
            activeLabels.insert(lbl)
        }
        return activeLabels.count
    }

    public func purgeExpiredEntries() {
        lock.lock()
        defer { lock.unlock() }
        rescheduleCleanupTimerLocked()
    }

    private func rescheduleCleanupTimerLocked() {
        let now = DispatchTime.now()
        var expiredBuffers: [SecureBuffer] = []
        var expiredKeys: [CachedP256SigningKey] = []
        var didEvict = false

        for (label, entry) in cache where entry.monotonicDeadline <= now {
            expiredBuffers.append(entry.buffer)
            cache.removeValue(forKey: label)
            didEvict = true
        }
        for (label, entry) in p256Cache where entry.monotonicDeadline <= now {
            expiredKeys.append(entry.key)
            p256Cache.removeValue(forKey: label)
            didEvict = true
        }
        for (label, entry) in unlockedSessions where entry.monotonicDeadline <= now {
            unlockedSessions.removeValue(forKey: label)
            didEvict = true
        }

        if didEvict {
            generation &+= 1
        }

        for buffer in expiredBuffers {
            buffer.wipe()
        }
        for key in expiredKeys {
            key.wipe()
        }

        var earliestDeadline: DispatchTime? = nil

        for (_, entry) in cache {
            if let current = earliestDeadline {
                if entry.monotonicDeadline < current { earliestDeadline = entry.monotonicDeadline }
            } else {
                earliestDeadline = entry.monotonicDeadline
            }
        }
        for (_, entry) in p256Cache {
            if let current = earliestDeadline {
                if entry.monotonicDeadline < current { earliestDeadline = entry.monotonicDeadline }
            } else {
                earliestDeadline = entry.monotonicDeadline
            }
        }
        for (_, entry) in unlockedSessions {
            if let current = earliestDeadline {
                if entry.monotonicDeadline < current { earliestDeadline = entry.monotonicDeadline }
            } else {
                earliestDeadline = entry.monotonicDeadline
            }
        }

        if let deadline = earliestDeadline {
            cleanupTimer?.schedule(deadline: deadline)
        } else {
            cleanupTimer?.schedule(deadline: .distantFuture)
        }
    }
}

enum CachedP256SigningKey {
    case software(SecureBuffer)
    case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)

    func wipe() {
        if case .software(let buffer) = self {
            buffer.wipe()
        }
    }

    func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
        switch self {
        case .software(let buffer):
            let res = try buffer.withUnsafeBytes { raw -> P256.Signing.ECDSASignature in
                let key = try P256.Signing.PrivateKey(rawRepresentation: raw)
                return try key.signature(for: data)
            }
            guard let signature = res else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key buffer has been wiped"])
            }
            return signature
        case .secureEnclave(let key):
            return try key.signature(for: data)
        }
    }
}
