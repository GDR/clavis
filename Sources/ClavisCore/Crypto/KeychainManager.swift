import Foundation
import Security
import CryptoKit
import LocalAuthentication
import AppKit

public class KeychainManager {
    public static let privateServiceName = "com.clavis.ed25519"
    public static let publicServiceName = "com.clavis.ed25519.pub"
    public static let shared = KeychainManager(migrateLegacyStorage: true)

    private let authenticator: UserAuthenticating
    private let privateKeyStore: PrivateKeyStoring
    private let sessionCache: SessionCacheManager

    init(
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        privateKeyStore: PrivateKeyStoring = KeychainPrivateKeyStore(),
        sessionCache: SessionCacheManager = .shared,
        migrateLegacyStorage: Bool = false
    ) {
        self.authenticator = authenticator
        self.privateKeyStore = privateKeyStore
        self.sessionCache = sessionCache
        if migrateLegacyStorage {
            migrateLegacySeedFiles()
        }
    }

    // Generate new Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(label: String, algorithm: String = "Ed25519", storageType: KeyStorageType = .keychain) throws -> Ed25519KeyInfo {
        try validateLabel(label)
        if try fetchKeyInfo(label: label) != nil {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before generating a new key with this label."])
        }

        if algorithm == "ECDSA P-256" {
            let pubKeyData: Data
            if storageType == .secureEnclave {
                guard SecureEnclave.isAvailable else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Apple Secure Enclave is not available on this device."])
                }
                let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage, .userPresence])
                let seKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
                try privateKeyStore.save(label: label, data: seKey.dataRepresentation)
                pubKeyData = seKey.publicKey.x963Representation
            } else {
                let privateKey = P256.Signing.PrivateKey()
                try privateKeyStore.save(label: label, data: privateKey.rawRepresentation)
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
        try validateLabel(label)
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
        
        try privateKeyStore.save(label: label, data: rawSeed)

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
        try privateKeyStore.remove(label: label)
        PublicKeyStore.remove(label: label)
        sessionCache.remove(label: label)
    }

    // Private scoped execution over the Ed25519 seed bytes held in a locked SecureBuffer.
    // Lexically scopes access to audited call sites (sign, unwrapAgeFileKey).
    private func withEd25519Seed<T>(
        label: String,
        prompt: String,
        operation: (UnsafeRawBufferPointer) throws -> T
    ) throws -> T {
        ClavisLogger.log("FETCH_KEY", "Access request for key '\(label)'")

        let cacheGeneration = sessionCache.generationSnapshot()

        // 1. Check session cache
        if let cachedBuffer = sessionCache.getBuffer(label: label) {
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                throw SessionCacheError.invalidated
            }
            ClavisLogger.log("SESSION_CACHE", "Serving key '\(label)' from active session cache (0 prompts)")
            let res = try cachedBuffer.withUnsafeBytes(operation)
            guard let result = res else {
                throw SessionCacheError.invalidated
            }
            return result
        }

        // 2. Cache miss: authenticate user
        ClavisLogger.log("TOUCH_ID_PROMPT", "Displaying user authentication prompt: \"\(prompt)\"")
        do {
            let context = try authenticator.authenticate(reason: prompt)
            ClavisLogger.log("TOUCH_ID_RESULT", "User authentication SUCCESS")

            // Verify generation hasn't changed during authentication prompt
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                throw SessionCacheError.invalidated
            }

            guard var sensitiveData = try privateKeyStore.load(label: label, context: context, prompt: prompt) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key seed not found for label '\(label)'"])
            }
            defer {
                sensitiveData.withUnsafeMutableBytes { ptr in
                    if let baseAddress = ptr.baseAddress {
                        _ = memset_s(baseAddress, ptr.count, 0, ptr.count)
                    }
                }
            }

            guard let secureBuffer = SecureBuffer(consuming: &sensitiveData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
            }

            // Verify generation again before saving or operating
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                secureBuffer.wipe()
                throw SessionCacheError.invalidated
            }

            if sessionCache.currentTimeout != .never {
                guard sessionCache.set(
                    label: label,
                    buffer: secureBuffer,
                    expectedGeneration: cacheGeneration
                ) else {
                    secureBuffer.wipe()
                    throw SessionCacheError.invalidated
                }
                ClavisLogger.log("FETCH_KEY_SUCCESS", "Key '\(label)' loaded from Keychain and placed into session cache.")

                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    throw SessionCacheError.invalidated
                }

                let res = try secureBuffer.withUnsafeBytes(operation)
                guard let result = res else {
                    throw SessionCacheError.invalidated
                }
                return result
            } else {
                // Caching is disabled (.never): keep buffer purely local and wipe in defer
                defer {
                    secureBuffer.wipe()
                }
                ClavisLogger.log("FETCH_KEY_SUCCESS", "Key '\(label)' loaded from Keychain for single-shot operation (cache disabled).")

                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    throw SessionCacheError.invalidated
                }

                let res = try secureBuffer.withUnsafeBytes(operation)
                guard let result = res else {
                    throw SessionCacheError.invalidated
                }
                return result
            }
        } catch {
            ClavisLogger.log("TOUCH_ID_RESULT", "User authentication FAILED: \(error.localizedDescription)")
            throw error
        }
    }

    // Sign challenge data using Ed25519 private key within scoped seed buffer
    public func sign(label: String, data: Data, prompt: String) throws -> Data {
        try withEd25519Seed(label: label, prompt: prompt) { seedBytes in
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
            return try privateKey.signature(for: data)
        }
    }

    // Unwrap age file key directly using Ed25519 seed bytes without allocating intermediate Data or PrivateKey
    public func unwrapAgeFileKey(label: String, prompt: String, wrappedKey: Data, epkB64: String) throws -> Data {
        try withEd25519Seed(label: label, prompt: prompt) { seedBytes in
            try AgePluginCrypto.unwrapFileKey(
                wrappedKey: wrappedKey,
                epkB64: epkB64,
                seedBytes: seedBytes
            )
        }
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
            let cacheGeneration = sessionCache.generationSnapshot()
            var localKeyToWipe: CachedP256SigningKey? = nil
            defer {
                localKeyToWipe?.wipe()
            }

            let signingKey: CachedP256SigningKey
            if let cachedKey = sessionCache.getP256(label: key.label) {
                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    throw SessionCacheError.invalidated
                }
                ClavisLogger.log("SESSION_CACHE", "Serving key '\(key.label)' (ECDSA P-256) from active session cache (0 prompts)")
                signingKey = cachedKey
            } else {
                let context = try authenticator.authenticate(reason: prompt)
                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    throw SessionCacheError.invalidated
                }

                guard var storedData = try privateKeyStore.load(label: key.label, context: context, prompt: prompt) else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key data not found for '\(key.label)'"])
                }
                defer {
                    if key.storageType != .secureEnclave {
                        storedData.withUnsafeMutableBytes { ptr in
                            if let base = ptr.baseAddress {
                                _ = memset_s(base, ptr.count, 0, ptr.count)
                            }
                        }
                    }
                }

                if key.storageType == .secureEnclave {
                    let seKey = try SecureEnclave.P256.Signing.PrivateKey(
                        dataRepresentation: storedData,
                        authenticationContext: context
                    )
                    signingKey = .secureEnclave(seKey)
                } else {
                    guard let buf = SecureBuffer(consuming: &storedData) else {
                        throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(key.label)'"])
                    }
                    signingKey = .software(buf)
                }

                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    signingKey.wipe()
                    throw SessionCacheError.invalidated
                }

                if sessionCache.currentTimeout != .never {
                    guard sessionCache.setP256(
                        label: key.label,
                        key: signingKey,
                        expectedGeneration: cacheGeneration
                    ) else {
                        signingKey.wipe()
                        throw SessionCacheError.invalidated
                    }
                } else {
                    localKeyToWipe = signingKey
                }
            }

            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                throw SessionCacheError.invalidated
            }
            let ecdsaSig = try signingKey.signature(for: data)

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
        guard sessionCache.currentTimeout.timeInterval != nil else {
            throw SessionCacheError.disabled
        }
        let cacheGeneration = sessionCache.generationSnapshot()

        let context = try await authenticator.authenticate(reason: reason)
        guard sessionCache.isGenerationCurrent(cacheGeneration) else {
            throw SessionCacheError.invalidated
        }

        guard let timeout = sessionCache.currentTimeout.timeInterval else {
            throw SessionCacheError.disabled
        }
        guard let keyInfo = try fetchKeyInfo(label: label),
              var storedData = try privateKeyStore.load(label: label, context: context, prompt: reason) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key not found for '\(label)'"])
        }
        defer {
            if keyInfo.storageType != .secureEnclave {
                storedData.withUnsafeMutableBytes { ptr in
                    if let base = ptr.baseAddress {
                        _ = memset_s(base, ptr.count, 0, ptr.count)
                    }
                }
            }
        }

        if keyInfo.algorithm == "ECDSA P-256" {
            let signingKey: CachedP256SigningKey
            if keyInfo.storageType == .secureEnclave {
                signingKey = .secureEnclave(try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: storedData,
                    authenticationContext: context
                ))
            } else {
                guard let buf = SecureBuffer(consuming: &storedData) else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
                }
                signingKey = .software(buf)
            }
            guard sessionCache.setP256(
                label: label,
                key: signingKey,
                expectedGeneration: cacheGeneration
            ) else {
                signingKey.wipe()
                throw SessionCacheError.invalidated
            }
        } else if storedData.count == 32 {
            guard let buf = SecureBuffer(consuming: &storedData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
            }
            guard sessionCache.set(
                label: label,
                buffer: buf,
                expectedGeneration: cacheGeneration
            ) else {
                buf.wipe()
                throw SessionCacheError.invalidated
            }
        }
        ClavisLogger.log("KEY_UNLOCK", "Key '\(label)' unlocked successfully for \(Int(timeout))s.")
    }

    // Lock a key immediately
    public func lockKey(label: String) {
        sessionCache.remove(label: label)
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

    private func migrateLegacySeedFiles() {
        for keyInfo in PublicKeyStore.loadAll() where SeedStore.hasSeedFile(label: keyInfo.label) {
            do {
                if !privateKeyStore.contains(label: keyInfo.label) {
                    guard let keyData = SeedStore.load(label: keyInfo.label) else {
                        ClavisLogger.log("KEYCHAIN_MIGRATE", "Could not decrypt legacy seed for '\(keyInfo.label)'; keeping the original file.")
                        continue
                    }
                    try privateKeyStore.save(label: keyInfo.label, data: keyData)
                }
                SeedStore.remove(label: keyInfo.label)
                ClavisLogger.log("KEYCHAIN_MIGRATE", "Migrated '\(keyInfo.label)' from disk storage to a user-presence Keychain item.")
            } catch {
                ClavisLogger.log("KEYCHAIN_MIGRATE", "Failed to migrate '\(keyInfo.label)': \(error.localizedDescription)")
            }
        }
        SeedStore.removeMasterKeyIfUnused()
    }

    private func validateLabel(_ label: String) throws {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasControlCharacters = label.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        guard !label.isEmpty,
              label == trimmed,
              label.utf8.count <= 128,
              !hasControlCharacters else {
            throw NSError(
                domain: "Clavis",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Key label must be 1-128 bytes and contain no leading, trailing, or control characters."]
            )
        }
    }
}
