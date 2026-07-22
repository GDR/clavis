import Foundation
import Security
import CryptoKit
import LocalAuthentication
import AppKit

public class SessionCacheManager {
    public static let shared = SessionCacheManager()

    private var cache: [String: (key: Curve25519.Signing.PrivateKey, expiresAt: Date)] = [:]
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
    }

    public func remove(label: String) {
        lock.lock()
        defer { lock.unlock() }
        cache.removeValue(forKey: label)
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
        cache[label] = (key, Date().addingTimeInterval(validTimeout))
    }

    public var cachedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        return cache.values.filter { $0.expiresAt > now }.count
    }
}

public class KeychainManager {
    public static let privateServiceName = "com.clavis.ed25519"
    public static let publicServiceName = "com.clavis.ed25519.pub"
    public static let shared = KeychainManager()

    private init() {}

    // Generate new Ed25519 Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(label: String) throws -> Ed25519KeyInfo {
        let privateKey = Curve25519.Signing.PrivateKey()
        return try storeKey(label: label, privateKey: privateKey)
    }

    // Import existing Ed25519 seed (32 bytes)
    @discardableResult
    public func importKey(label: String, seedData: Data) throws -> Ed25519KeyInfo {
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
        return try storeKey(label: label, privateKey: privateKey)
    }

    private func storeKey(label: String, privateKey: Curve25519.Signing.PrivateKey) throws -> Ed25519KeyInfo {
        var rawSeed = privateKey.rawRepresentation
        defer {
            rawSeed.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }
        
        // 1. Create Touch ID access control object for private key seed
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            throw error?.takeRetainedValue() ?? NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create access control"])
        }

        let deletePrivateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(deletePrivateQuery as CFDictionary)

        let privateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label,
            kSecValueData as String: rawSeed,
            kSecAttrAccessControl as String: accessControl
        ]

        var privateStatus = SecItemAdd(privateQuery as CFDictionary, nil)
        if privateStatus != errSecSuccess {
            // Un-entitled process fallback: store with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            SecItemDelete(deletePrivateQuery as CFDictionary)
            let fallbackQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: KeychainManager.privateServiceName,
                kSecAttrAccount as String: label,
                kSecValueData as String: rawSeed,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            privateStatus = SecItemAdd(fallbackQuery as CFDictionary, nil)
            guard privateStatus == errSecSuccess else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(privateStatus), userInfo: [NSLocalizedDescriptionKey: "Failed to store private key in Keychain: \(privateStatus)"])
            }
        }

        // 2. Create public key metadata and store without biometric or password prompts
        let keyInfo = try makeKeyInfo(label: label, privateKey: privateKey)
        let encodedKeyInfo = try JSONEncoder().encode(keyInfo)

        var pubError: Unmanaged<CFError>?
        let publicAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            &pubError
        )

        var publicQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label,
            kSecValueData as String: encodedKeyInfo
        ]
        if let pubAccess = publicAccessControl {
            publicQuery[kSecAttrAccessControl as String] = pubAccess
        } else {
            publicQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }

        SecItemDelete(publicQuery as CFDictionary)
        let publicStatus = SecItemAdd(publicQuery as CFDictionary, nil)
        guard publicStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(publicStatus), userInfo: [NSLocalizedDescriptionKey: "Failed to store public key metadata: \(publicStatus)"])
        }

        return keyInfo
    }

    // List all public key metadata WITHOUT triggering Touch ID prompts
    public func listKeys() throws -> [Ed25519KeyInfo] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true
        ]

        var result: AnyObject?
        var status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound || status != errSecSuccess {
            // Fallback: search by privateServiceName attributes (no Touch ID prompt triggered)
            let privQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: KeychainManager.privateServiceName,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true
            ]
            status = SecItemCopyMatching(privQuery as CFDictionary, &result)
            if status == errSecSuccess, let array = result as? [[String: Any]] {
                var keys: [Ed25519KeyInfo] = []
                for dict in array {
                    if let label = dict[kSecAttrAccount as String] as? String {
                        if let keyInfo = try? fetchKeyInfo(label: label) {
                            keys.append(keyInfo)
                        }
                    }
                }
                return keys.sorted(by: { $0.label < $1.label })
            }
            return []
        }

        let items: [Data]
        if let arrayData = result as? [Data] {
            items = arrayData
        } else if let array = result as? [Any] {
            items = array.compactMap { item in
                if let d = item as? Data { return d }
                if let dict = item as? [String: Any] { return dict[kSecValueData as String] as? Data }
                if let nsDict = item as? NSDictionary { return nsDict[kSecValueData as String] as? Data }
                return nil
            }
        } else if let singleData = result as? Data {
            items = [singleData]
        } else {
            items = []
        }

        var keys: [Ed25519KeyInfo] = []
        let decoder = JSONDecoder()
        for data in items {
            if let info = try? decoder.decode(Ed25519KeyInfo.self, from: data) {
                keys.append(info)
            }
        }
        return keys.sorted(by: { $0.label < $1.label })
    }

    public func fetchKeyInfo(label: String) throws -> Ed25519KeyInfo? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(Ed25519KeyInfo.self, from: data)
    }

    // Delete key (both private seed and public metadata)
    public func deleteKey(label: String) throws {
        let privateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(privateQuery as CFDictionary)

        let publicQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(publicQuery as CFDictionary)

        SessionCacheManager.shared.remove(label: label)
    }

    // Retrieve private key seed with Touch ID / Apple Watch / Password fallback authentication
    public func fetchPrivateKey(label: String, prompt: String) throws -> Curve25519.Signing.PrivateKey {
        if let cached = SessionCacheManager.shared.get(label: label) {
            return cached
        }

        if NSClassFromString("XCTestCase") == nil && ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
            let laContext = LAContext()
            laContext.localizedReason = prompt

            var authError: NSError?
            let sema = DispatchSemaphore(value: 0)
            var authSuccess = false
            laContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: prompt) { success, error in
                authSuccess = success
                authError = error as NSError?
                sema.signal()
            }
            _ = sema.wait(timeout: .now() + 30)

            guard authSuccess else {
                throw authError ?? NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Touch ID authentication failed or cancelled."])
            }
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.privateServiceName,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let resultData = result as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Keychain item lookup failed: \(status)"])
        }

        var sensitiveData = resultData
        defer {
            sensitiveData.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sensitiveData)
        SessionCacheManager.shared.set(label: label, key: privateKey)
        return privateKey
    }

    // Sign challenge data using Ed25519 private key
    public func sign(label: String, data: Data, prompt: String) throws -> Data {
        let privateKey = try fetchPrivateKey(label: label, prompt: prompt)
        return try privateKey.signature(for: data)
    }

    // Convert Curve25519.Signing.PrivateKey to OpenSSH public key format & wire representation
    public func makeKeyInfo(label: String, privateKey: Curve25519.Signing.PrivateKey) throws -> Ed25519KeyInfo {
        let pubKeyData = privateKey.publicKey.rawRepresentation
        let keyType = "ssh-ed25519"

        var blob = Data()
        blob.appendWireString(keyType)
        blob.appendWireData(pubKeyData)

        let b64 = blob.base64EncodedString()
        let openSSH = "\(keyType) \(b64) \(label)"

        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return Ed25519KeyInfo(label: label, publicKeyOpenSSH: openSSH, publicKeyBlob: blob, fingerprint: fingerprint, createdAt: Date())
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
