import Foundation
import CryptoKit
import AppKit

public class SessionCacheManager {
    public static let shared = SessionCacheManager()

    private var cache: [String: (key: Curve25519.Signing.PrivateKey, expiresAt: Date)] = [:]
    private var p256Cache: [String: (key: CachedP256SigningKey, expiresAt: Date)] = [:]
    private var unlockedSessions: [String: Date] = [:]
    private let lock = NSLock()

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
            UserDefaults.standard.set(newValue.rawValue, forKey: Self.userDefaultsKey)
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

    private init() {
        if let saved = UserDefaults.standard.string(forKey: Self.userDefaultsKey),
           let timeout = SessionTimeout(rawValue: saved) {
            self._currentTimeout = timeout
        } else {
            self._currentTimeout = .fiveMinutes
        }

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

    @objc public func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        cache.removeAll()
        p256Cache.removeAll()
        unlockedSessions.removeAll()
    }

    public func remove(label: String) {
        lock.lock()
        defer { lock.unlock() }
        cache.removeValue(forKey: label)
        p256Cache.removeValue(forKey: label)
        unlockedSessions.removeValue(forKey: label)
    }

    public func isKeyUnlocked(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        if let entry = cache[label], entry.expiresAt > now {
            return true
        }
        if let entry = p256Cache[label], entry.expiresAt > now {
            return true
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
        if let entry = cache[label], entry.expiresAt > now {
            return entry.expiresAt.timeIntervalSince(now)
        }
        if let entry = p256Cache[label], entry.expiresAt > now {
            return entry.expiresAt.timeIntervalSince(now)
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
            cache.removeValue(forKey: label)
            return nil
        }
        return entry.key
    }

    public func set(label: String, key: Curve25519.Signing.PrivateKey) {
        lock.lock()
        let timeout = _currentTimeout.timeInterval
        lock.unlock()
        guard let validTimeout = timeout else { return }

        lock.lock()
        defer { lock.unlock() }
        let expires = Date().addingTimeInterval(validTimeout)
        cache[label] = (key, expires)
        unlockedSessions[label] = expires
    }

    func getP256(label: String) -> CachedP256SigningKey? {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return nil }
        guard let entry = p256Cache[label] else { return nil }
        if Date() > entry.expiresAt {
            p256Cache.removeValue(forKey: label)
            return nil
        }
        return entry.key
    }

    func setP256(label: String, key: CachedP256SigningKey) {
        lock.lock()
        defer { lock.unlock() }
        guard let timeout = _currentTimeout.timeInterval else { return }
        let expires = Date().addingTimeInterval(timeout)
        p256Cache[label] = (key, expires)
        unlockedSessions[label] = expires
    }

    public var cachedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return 0 }
        let now = Date()
        var activeLabels = Set<String>()
        for (lbl, entry) in cache where entry.expiresAt > now {
            activeLabels.insert(lbl)
        }
        for (lbl, entry) in p256Cache where entry.expiresAt > now {
            activeLabels.insert(lbl)
        }
        for (lbl, expiresAt) in unlockedSessions where expiresAt > now {
            activeLabels.insert(lbl)
        }
        return activeLabels.count
    }
}

enum CachedP256SigningKey {
    case software(P256.Signing.PrivateKey)
    case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)

    func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
        switch self {
        case .software(let key):
            return try key.signature(for: data)
        case .secureEnclave(let key):
            return try key.signature(for: data)
        }
    }
}
