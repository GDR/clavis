import Foundation
import Security
import CryptoKit
import LocalAuthentication
import AppKit

public class SessionCacheManager {
    public static let shared = SessionCacheManager()

    private var cache: [String: (key: Curve25519.Signing.PrivateKey, expiresAt: Date)] = [:]
    private var unlockedSessions: [String: Date] = [:]
    private let lock = NSLock()

    private var _currentTimeout: SessionTimeout = .never
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
        unlockedSessions.removeAll()
    }

    public func remove(label: String) {
        lock.lock()
        defer { lock.unlock() }
        cache.removeValue(forKey: label)
        unlockedSessions.removeValue(forKey: label)
    }

    public func isKeyUnlocked(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        if let entry = cache[label], entry.expiresAt > now {
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

    public var cachedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        guard _currentTimeout != .never else { return 0 }
        let now = Date()
        var activeLabels = Set<String>()
        for (lbl, entry) in cache where entry.expiresAt > now {
            activeLabels.insert(lbl)
        }
        for (lbl, expiresAt) in unlockedSessions where expiresAt > now {
            activeLabels.insert(lbl)
        }
        return activeLabels.count
    }
}

public struct PublicKeyStore {
    private static var storageURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("keys.json")
    }

    public static func loadAll() -> [Ed25519KeyInfo] {
        guard let data = try? Data(contentsOf: storageURL),
              let keys = try? JSONDecoder().decode([Ed25519KeyInfo].self, from: data) else {
            return []
        }
        return keys.sorted(by: { $0.label < $1.label })
    }

    public static func save(_ info: Ed25519KeyInfo) {
        var current = loadAll().filter { $0.label != info.label }
        current.append(info)
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
    }

    public static func remove(label: String) {
        let current = loadAll().filter { $0.label != label }
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
    }
}

public struct ClavisLogger {
    public static var logFileURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("clavis.log")
    }

    public static func log(_ category: String, _ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let timestamp = formatter.string(from: Date())
        let line = "[\(timestamp)] [\(category)] \(message)\n"
        print(line, terminator: "")
        if let data = line.data(using: .utf8) {
            if let handle = try? FileHandle(forWritingTo: logFileURL) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            } else {
                try? data.write(to: logFileURL, options: .atomic)
            }
        }
    }
}

public struct SeedStore {
    private static var seedsDirectory: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis/seeds", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }

    public static func seedFileURL(label: String) -> URL {
        let safeLabel = label.replacingOccurrences(of: "/", with: "_")
        return seedsDirectory.appendingPathComponent("\(safeLabel).key")
    }

    public static func save(label: String, seedData: Data) throws {
        let url = seedFileURL(label: label)
        try seedData.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        ClavisLogger.log("SEED_STORE", "Saved private seed for '\(label)' to \(url.path) (POSIX 0600)")
    }

    public static func load(label: String) -> Data? {
        let url = seedFileURL(label: label)
        guard let data = try? Data(contentsOf: url) else { return nil }
        ClavisLogger.log("SEED_STORE", "Loaded private seed for '\(label)' from local storage \(url.path)")
        return data
    }

    public static func remove(label: String) {
        let url = seedFileURL(label: label)
        try? FileManager.default.removeItem(at: url)
        ClavisLogger.log("SEED_STORE", "Removed seed file for '\(label)' at \(url.path)")
    }
}

public class KeychainManager {
    public static let privateServiceName = "com.clavis.ed25519"
    public static let publicServiceName = "com.clavis.ed25519.pub"
    public static let shared = KeychainManager()

    private init() {}

    // Generate new Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(label: String, algorithm: String = "Ed25519", storageType: KeyStorageType = .keychain) throws -> Ed25519KeyInfo {
        if try fetchKeyInfo(label: label) != nil {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before generating a new key with this label."])
        }

        if algorithm == "ECDSA P-256" {
            let pubKeyData: Data
            if storageType == .secureEnclave {
                guard SecureEnclave.isAvailable else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Apple Secure Enclave is not available on this device."])
                }
                let seKey = try SecureEnclave.P256.Signing.PrivateKey()
                try SeedStore.save(label: label, seedData: seKey.dataRepresentation)
                pubKeyData = seKey.publicKey.x963Representation
            } else {
                let privateKey = P256.Signing.PrivateKey()
                try SeedStore.save(label: label, seedData: privateKey.rawRepresentation)
                pubKeyData = privateKey.publicKey.x963Representation
            }

            let keyType = "ecdsa-sha2-nistp256"
            let curveId = "nistp256"

            var blob = Data()
            blob.appendWireString(keyType)
            blob.appendWireString(curveId)
            blob.appendWireData(pubKeyData)

            let b64 = blob.base64EncodedString()
            let openSSH = "\(keyType) \(b64) \(label)"
            let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")

            let keyInfo = Ed25519KeyInfo(
                label: label,
                publicKeyOpenSSH: openSSH,
                publicKeyBlob: blob,
                fingerprint: fingerprint,
                createdAt: Date(),
                algorithmName: algorithm,
                storage: storageType
            )
            PublicKeyStore.save(keyInfo)
            return keyInfo
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        return try storeKey(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType)
    }

    // Import existing Ed25519 seed (32 bytes)
    @discardableResult
    public func importKey(label: String, seedData: Data, algorithm: String = "Ed25519", storageType: KeyStorageType = .keychain) throws -> Ed25519KeyInfo {
        if try fetchKeyInfo(label: label) != nil {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before importing a new key with this label."])
        }
        guard seedData.count == 32 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid Ed25519 seed length (must be 32 bytes)"])
        }
        var mutableSeed = seedData
        defer {
            mutableSeed.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: mutableSeed)
        return try storeKey(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType)
    }

    private func storeKey(label: String, privateKey: Curve25519.Signing.PrivateKey, algorithm: String = "Ed25519", storageType: KeyStorageType = .keychain) throws -> Ed25519KeyInfo {
        ClavisLogger.log("KEYCHAIN_WRITE", "Storing private seed for '\(label)'...")
        var rawSeed = privateKey.rawRepresentation
        defer {
            rawSeed.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }
        
        // Save private seed securely in SeedStore (POSIX mode 0600)
        try SeedStore.save(label: label, seedData: rawSeed)

        // Delete legacy Keychain items
        let deletePrivateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(deletePrivateQuery as CFDictionary)

        let deletePublicQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(deletePublicQuery as CFDictionary)

        // Save public key metadata
        let keyInfo = try makeKeyInfo(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType)
        PublicKeyStore.save(keyInfo)
        return keyInfo
    }

    // List all public key metadata WITHOUT triggering Touch ID or Keychain prompts
    public func listKeys() throws -> [Ed25519KeyInfo] {
        ClavisLogger.log("KEY_LIST", "Fetching key list from local store...")
        return PublicKeyStore.loadAll()
    }

    public func fetchKeyInfo(label: String) throws -> Ed25519KeyInfo? {
        return PublicKeyStore.loadAll().first(where: { $0.label == label })
    }

    // Delete key (both private seed and public metadata)
    public func deleteKey(label: String) throws {
        ClavisLogger.log("KEY_DELETE", "Deleting key '\(label)'...")
        SeedStore.remove(label: label)
        PublicKeyStore.remove(label: label)
        SessionCacheManager.shared.remove(label: label)

        let privateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(privateQuery as CFDictionary)
    }

    // Retrieve private key seed with Touch ID / Apple Watch / Password fallback authentication
    public func fetchPrivateKey(label: String, prompt: String) throws -> Curve25519.Signing.PrivateKey {
        ClavisLogger.log("FETCH_KEY", "Access request for key '\(label)'")
        if let cached = SessionCacheManager.shared.get(label: label) {
            ClavisLogger.log("SESSION_CACHE", "Serving key '\(label)' from active session cache (0 prompts)")
            return cached
        }

        if NSClassFromString("XCTestCase") == nil && ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
            ClavisLogger.log("TOUCH_ID_PROMPT", "Displaying Touch ID prompt: \"\(prompt)\"")
            let laContext = LAContext()
            laContext.localizedReason = prompt

            var authError: NSError?
            let sema = DispatchSemaphore(value: 0)
            var authSuccess = false

            DispatchQueue.main.async {
                laContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt) { success, error in
                    authSuccess = success
                    authError = error as NSError?
                    sema.signal()
                }
            }
            _ = sema.wait(timeout: .now() + 60)

            if authSuccess {
                ClavisLogger.log("TOUCH_ID_RESULT", "Touch ID fingerprint authentication SUCCESS")
            } else {
                ClavisLogger.log("TOUCH_ID_RESULT", "Touch ID FAILED: \(authError?.localizedDescription ?? "user cancelled")")
                throw authError ?? NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed or cancelled: \(authError?.localizedDescription ?? "unknown error")"])
            }
        }

        // Fetch private seed from SeedStore (with fallback migration from legacy Keychain)
        var seedData = SeedStore.load(label: label)
        if seedData == nil {
            ClavisLogger.log("KEYCHAIN_QUERY", "Seed not in local SeedStore, checking legacy Keychain for '\(label)'...")
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: KeychainManager.privateServiceName,
                kSecAttrAccount as String: label,
                kSecReturnData as String: true
            ]

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            ClavisLogger.log("KEYCHAIN_RESULT", "SecItemCopyMatching returned status \(status) (\(status == 0 ? "errSecSuccess" : "errSecItemNotFound"))")
            if status == errSecSuccess, let resultData = result as? Data {
                seedData = resultData
                try? SeedStore.save(label: label, seedData: resultData)
                SecItemDelete(query as CFDictionary)
                ClavisLogger.log("KEYCHAIN_MIGRATE", "Migrated legacy Keychain item '\(label)' to SeedStore and deleted Keychain copy.")
            }
        }

        guard let sensitiveData = seedData else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key seed not found for label '\(label)'"])
        }

        var mutableData = sensitiveData
        defer {
            mutableData.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: mutableData)
        SessionCacheManager.shared.set(label: label, key: privateKey)
        ClavisLogger.log("FETCH_KEY_SUCCESS", "Key '\(label)' loaded and placed into session cache.")
        return privateKey
    }

    // Sign challenge data using Ed25519 private key
    public func sign(label: String, data: Data, prompt: String) throws -> Data {
        let privateKey = try fetchPrivateKey(label: label, prompt: prompt)
        return try privateKey.signature(for: data)
    }

    // Helper to format an integer as an SSH mpint (RFC 4251 section 5)
    public static func encodeSSHMPint(_ bytes: Data) -> Data {
        var d = bytes
        while d.count > 1 && d.first == 0 {
            d.removeFirst()
        }
        var res = Data()
        if let first = d.first, first & 0x80 != 0 {
            var withZero = Data([0x00])
            withZero.append(d)
            var len = UInt32(withZero.count).bigEndian
            Swift.withUnsafeBytes(of: &len) { res.append(contentsOf: $0) }
            res.append(withZero)
        } else {
            var len = UInt32(d.count).bigEndian
            Swift.withUnsafeBytes(of: &len) { res.append(contentsOf: $0) }
            res.append(d)
        }
        return res
    }

    // Sign challenge data for SSH Agent returning wire format signature blob
    public func signSSH(key: Ed25519KeyInfo, data: Data, prompt: String) throws -> Data {
        if key.algorithm == "ECDSA P-256" {
            if !SessionCacheManager.shared.isKeyUnlocked(label: key.label) {
                if NSClassFromString("XCTestCase") == nil && ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
                    let laContext = LAContext()
                    laContext.localizedReason = prompt
                    var authError: NSError?
                    let sema = DispatchSemaphore(value: 0)
                    var authSuccess = false
                    DispatchQueue.main.async {
                        laContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt) { success, error in
                            authSuccess = success
                            authError = error as NSError?
                            sema.signal()
                        }
                    }
                    _ = sema.wait(timeout: .now() + 60)
                    if !authSuccess {
                        throw authError ?? NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed or cancelled"])
                    }
                }
            }

            guard let storedData = SeedStore.load(label: key.label) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key data not found for '\(key.label)'"])
            }

            let ecdsaSig: P256.Signing.ECDSASignature
            if key.storageType == .secureEnclave {
                let seKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: storedData)
                ecdsaSig = try seKey.signature(for: data)
            } else {
                let swKey = try P256.Signing.PrivateKey(rawRepresentation: storedData)
                ecdsaSig = try swKey.signature(for: data)
            }

            let rawSig = ecdsaSig.rawRepresentation
            let r = rawSig.prefix(32)
            let s = rawSig.suffix(32)

            var innerBlob = Data()
            innerBlob.append(KeychainManager.encodeSSHMPint(r))
            innerBlob.append(KeychainManager.encodeSSHMPint(s))

            var sigBlob = Data()
            sigBlob.appendWireString("ecdsa-sha2-nistp256")
            sigBlob.appendWireData(innerBlob)
            return sigBlob
        }

        let signature = try sign(label: key.label, data: data, prompt: prompt)
        var sigBlob = Data()
        sigBlob.appendWireString("ssh-ed25519")
        sigBlob.appendWireData(signature)
        return sigBlob
    }

    // Unlock a key with Touch ID / password and place in session cache
    public func unlock(label: String, prompt: String? = nil) async throws {
        let reason = prompt ?? "Touch ID to unlock '\(label)'"

        if NSClassFromString("XCTestCase") == nil && ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
            let laContext = LAContext()
            laContext.localizedReason = reason
            let success = try await laContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            guard success else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed or cancelled"])
            }
        }

        if SessionCacheManager.shared.currentTimeout == .never {
            SessionCacheManager.shared.currentTimeout = .fifteenMinutes
        }

        let timeout = SessionCacheManager.shared.currentTimeout.timeInterval ?? 900
        SessionCacheManager.shared.unlockKey(label: label, duration: timeout)

        if let seedData = SeedStore.load(label: label), seedData.count == 32 {
            if let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: seedData) {
                SessionCacheManager.shared.set(label: label, key: privateKey)
            }
        }
        ClavisLogger.log("KEY_UNLOCK", "Key '\(label)' unlocked successfully for \(Int(timeout))s.")
    }

    // Lock a key immediately
    public func lockKey(label: String) {
        SessionCacheManager.shared.remove(label: label)
        ClavisLogger.log("KEY_LOCK", "Key '\(label)' locked.")
    }

    // Convert Curve25519.Signing.PrivateKey to OpenSSH public key format & wire representation
    public func makeKeyInfo(label: String, privateKey: Curve25519.Signing.PrivateKey, algorithm: String = "Ed25519", storageType: KeyStorageType = .keychain) throws -> Ed25519KeyInfo {
        let pubKeyData = privateKey.publicKey.rawRepresentation
        let keyType = "ssh-ed25519"

        var blob = Data()
        blob.appendWireString(keyType)
        blob.appendWireData(pubKeyData)

        let b64 = blob.base64EncodedString()
        let openSSH = "\(keyType) \(b64) \(label)"

        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return Ed25519KeyInfo(label: label, publicKeyOpenSSH: openSSH, publicKeyBlob: blob, fingerprint: fingerprint, createdAt: Date(), algorithmName: algorithm, storage: storageType)
    }
}

public extension Data {
    mutating func appendWireString(_ string: String) {
        let data = Data(string.utf8)
        appendWireData(data)
    }

    mutating func appendWireData(_ data: Data) {
        var length = UInt32(data.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { append(contentsOf: $0) }
        append(data)
    }
}
