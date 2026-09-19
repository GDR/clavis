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

    private var cache: [String: (buffer: SecureBuffer, expiresAt: Date)] = [:]
    private var p256Cache: [String: (key: CachedP256SigningKey, expiresAt: Date)] = [:]
    private var unlockedSessions: [String: Date] = [:]
    private let lock = NSLock()
    private let defaults: UserDefaults
    private var generation: UInt64 = 0

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

    @objc public func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
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
    }

    public func isKeyUnlocked(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        if let entry = cache[label], entry.expiresAt > now, !entry.buffer.isWiped {
            return true
        }
        if let entry = p256Cache[label], entry.expiresAt > now {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped { return true }
            case .secureEnclave:
                return true
            }
        }
        if let expiresAt = unlockedSessions[label], expiresAt > now {
            return true
        }
        return false
    }

    public func remainingTime(label: String) -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        if let entry = cache[label], entry.expiresAt > now, !entry.buffer.isWiped {
            return entry.expiresAt.timeIntervalSince(now)
        }
        if let entry = p256Cache[label], entry.expiresAt > now {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped {
                    return entry.expiresAt.timeIntervalSince(now)
                }
            case .secureEnclave:
                return entry.expiresAt.timeIntervalSince(now)
            }
        }
        if let expiresAt = unlockedSessions[label], expiresAt > now {
            return expiresAt.timeIntervalSince(now)
        }
        return nil
    }

    public func unlockKey(label: String, duration: TimeInterval = 900) {
        lock.lock()
        defer { lock.unlock() }
        unlockedSessions[label] = Date().addingTimeInterval(duration)
    }

    public func get(label: String) -> Curve25519.Signing.PrivateKey? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = cache[label] else { return nil }
        if Date() > entry.expiresAt {
            entry.buffer.wipe()
            cache.removeValue(forKey: label)
            return nil
        }
        return entry.buffer.withUnsafeBytes { raw in
            try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        } ?? nil
    }

    public func getBuffer(label: String) -> SecureBuffer? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = cache[label] else { return nil }
        if Date() > entry.expiresAt {
            entry.buffer.wipe()
            cache.removeValue(forKey: label)
            return nil
        }
        return entry.buffer
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
    public func set(
        label: String,
        buffer: SecureBuffer,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let expectedGeneration, expectedGeneration != generation {
            buffer.wipe()
            return false
        }
        guard let timeout = _currentTimeout.timeInterval else {
            buffer.wipe()
            return true
        }
        if let old = cache.removeValue(forKey: label) {
            old.buffer.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        cache[label] = (buffer, expires)
        unlockedSessions[label] = expires
        return true
    }

    @discardableResult
    public func set(
        label: String,
        key: Curve25519.Signing.PrivateKey,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        var raw = key.rawRepresentation
        defer {
            raw.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    memset_s(base, ptr.count, 0, ptr.count)
                }
            }
        }
        guard let buffer = SecureBuffer(data: raw) else { return false }
        return set(label: label, buffer: buffer, expectedGeneration: expectedGeneration)
    }

    func getP256(label: String) -> CachedP256SigningKey? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = p256Cache[label] else { return nil }
        if Date() > entry.expiresAt {
            entry.key.wipe()
            p256Cache.removeValue(forKey: label)
            return nil
        }
        return entry.key
    }

    @discardableResult
    func setP256(
        label: String,
        key: CachedP256SigningKey,
        expectedGeneration: UInt64? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let expectedGeneration, expectedGeneration != generation {
            key.wipe()
            return false
        }
        guard let timeout = _currentTimeout.timeInterval else {
            key.wipe()
            return true
        }
        if let old = p256Cache.removeValue(forKey: label) {
            old.key.wipe()
        }
        let expires = Date().addingTimeInterval(timeout)
        p256Cache[label] = (key, expires)
        unlockedSessions[label] = expires
        return true
    }

    public var cachedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return 0 }
        let now = Date()
        var activeLabels = Set<String>()
        for (lbl, entry) in cache where entry.expiresAt > now && !entry.buffer.isWiped {
            activeLabels.insert(lbl)
        }
        for (lbl, entry) in p256Cache where entry.expiresAt > now {
            switch entry.key {
            case .software(let buf):
                if !buf.isWiped { activeLabels.insert(lbl) }
            case .secureEnclave:
                activeLabels.insert(lbl)
            }
        }
        for (lbl, expiresAt) in unlockedSessions where expiresAt > now {
            activeLabels.insert(lbl)
        }
        return activeLabels.count
    }
}

public enum CachedP256SigningKey {
    case software(SecureBuffer)
    case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)

    public func wipe() {
        if case .software(let buffer) = self {
            buffer.wipe()
        }
    }

    public func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
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
