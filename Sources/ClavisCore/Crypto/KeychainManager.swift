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
    private let secureBufferFactory: (inout Data) -> SecureBuffer?
    private let agentGrantRevoker: (String) throws -> Void

    init(
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        privateKeyStore: PrivateKeyStoring = KeychainPrivateKeyStore(),
        sessionCache: SessionCacheManager = .shared,
        secureBufferFactory: @escaping (inout Data) -> SecureBuffer? = { data in
            SecureBuffer(consuming: &data)
        },
        agentGrantRevoker: @escaping (String) throws -> Void = { label in
            try AgentLifecycleManager.shared.invalidateAgentGrant(label: label)
        },
        migrateLegacyStorage: Bool = false
    ) {
        self.authenticator = authenticator
        self.privateKeyStore = privateKeyStore
        self.sessionCache = sessionCache
        self.secureBufferFactory = secureBufferFactory
        self.agentGrantRevoker = agentGrantRevoker
        if migrateLegacyStorage {
            migrateLegacySeedFiles()
        }
    }

    // Generate new Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(
        label: String,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        try validateLabel(label)
        try validateGenerationConfiguration(algorithm: algorithm, storageType: storageType)
        if try fetchKeyInfo(label: label) != nil || privateKeyStore.contains(label: label) {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before generating a new key with this label."])
        }

        if algorithm == "ECDSA P-256" {
            let pubKeyData: Data
            let effectivePolicy: BiometricPolicy?
            if storageType == .secureEnclave {
                guard SecureEnclave.isAvailable else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Apple Secure Enclave is not available on this device."])
                }
                let policy = biometricPolicy ?? .userPresence
                effectivePolicy = policy
                let accessControl = try PrivateKeyAccessControl.make(flags: policy.accessControlFlags)
                let seKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)

                var record = StoredPrivateKeyRecord(
                    label: label,
                    algorithm: .ecdsaP256,
                    storageType: .secureEnclave,
                    biometricPolicy: policy,
                    keyPurpose: keyPurpose,
                    keyData: seKey.dataRepresentation
                )
                defer { record.wipe() }
                var recordData = try record.encode()
                defer { Self.wipeData(&recordData) }
                try privateKeyStore.save(label: label, data: recordData, accessControlFlags: policy.accessControlFlags)
                pubKeyData = seKey.publicKey.x963Representation
            } else {
                effectivePolicy = nil
                let privateKey = P256.Signing.PrivateKey()
                var record = StoredPrivateKeyRecord(
                    label: label,
                    algorithm: .ecdsaP256,
                    storageType: .keychain,
                    biometricPolicy: nil,
                    keyPurpose: keyPurpose,
                    keyData: privateKey.rawRepresentation
                )
                defer { record.wipe() }
                var recordData = try record.encode()
                defer { Self.wipeData(&recordData) }
                try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [.userPresence])
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
                storage: storageType,
                biometricPolicy: effectivePolicy,
                keyPurpose: keyPurpose
            )
            PublicKeyStore.save(keyInfo)
            return keyInfo
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        return try storeKey(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType, keyPurpose: keyPurpose)
    }

    // Import existing Ed25519 seed (32 bytes)
    @discardableResult
    public func importKey(
        label: String,
        consuming seedData: inout Data,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        defer {
            seedData.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    SecureMemory.zero(baseAddress, byteCount: ptr.count)
                }
            }
            seedData.removeAll(keepingCapacity: false)
        }
        try validateLabel(label)
        guard algorithm == "Ed25519", storageType == .keychain else {
            throw NSError(
                domain: "Clavis",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Imported seeds support only Ed25519 in Login Keychain storage."]
            )
        }
        if try fetchKeyInfo(label: label) != nil || privateKeyStore.contains(label: label) {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before importing a new key with this label."])
        }
        guard seedData.count == 32 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid Ed25519 seed length (must be 32 bytes)"])
        }
        let privateKey = try seedData.withUnsafeBytes { raw in
            try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
        }
        return try storeKey(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType, keyPurpose: keyPurpose)
    }

    private func validateGenerationConfiguration(algorithm: String, storageType: KeyStorageType) throws {
        let isSupported = algorithm == "ECDSA P-256" ||
            (algorithm == "Ed25519" && storageType == .keychain)
        guard isSupported else {
            throw NSError(
                domain: "Clavis",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Unsupported key algorithm or storage combination: \(algorithm) / \(storageType.rawValue)."]
            )
        }
    }

    private func storeKey(
        label: String,
        privateKey: Curve25519.Signing.PrivateKey,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        ClavisLogger.log("KEYCHAIN_WRITE", "Storing private seed for '\(label)'...")
        var rawSeed = privateKey.rawRepresentation
        defer {
            rawSeed.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    SecureMemory.zero(baseAddress, byteCount: ptr.count)
                }
            }
        }

        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: keyPurpose,
            keyData: rawSeed
        )
        defer { record.wipe() }
        var recordData = try record.encode()
        defer { Self.wipeData(&recordData) }
        try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [.userPresence])

        let keyInfo = try makeKeyInfo(label: label, privateKey: privateKey, algorithm: algorithm, storageType: storageType, keyPurpose: keyPurpose)
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
        let prompt = "Authenticate to permanently delete key '\(label)'"
        let context = try authenticator.authenticate(reason: prompt)
        try revokeKeyCapabilities(label: label)
        try privateKeyStore.remove(label: label, context: context, prompt: prompt)
        SeedStore.remove(label: label)
        PublicKeyStore.remove(label: label)
    }

    // MARK: - Authenticated Private Key Records & Verification

    // Derives the OpenSSH wire format public key blob directly from an authenticated private record.
    public static func derivePublicKeyBlob(record: StoredPrivateKeyRecord, context: LAContext? = nil) throws -> Data {
        switch record.algorithm {
        case .ed25519:
            guard record.keyData.count == 32 else {
                throw PrivateKeyRecordError.corruptedRecord("Invalid Ed25519 seed length: \(record.keyData.count) bytes (expected 32)")
            }
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: record.keyData)
            let pubKeyData = privateKey.publicKey.rawRepresentation
            var blob = Data()
            blob.appendWireString("ssh-ed25519")
            blob.appendWireData(pubKeyData)
            return blob

        case .ecdsaP256:
            let pubKeyData: Data
            if record.storageType == .secureEnclave {
                let authContext = context ?? LAContext()
                let seKey = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: record.keyData,
                    authenticationContext: authContext
                )
                pubKeyData = seKey.publicKey.x963Representation
            } else {
                guard record.keyData.count == 32 else {
                    throw PrivateKeyRecordError.corruptedRecord("Invalid P-256 scalar length: \(record.keyData.count) bytes (expected 32)")
                }
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: record.keyData)
                pubKeyData = privateKey.publicKey.x963Representation
            }

            var blob = Data()
            blob.appendWireString("ecdsa-sha2-nistp256")
            blob.appendWireString("nistp256")
            blob.appendWireData(pubKeyData)
            return blob
        }
    }

    private func validateAuthenticatedRecord(
        _ record: StoredPrivateKeyRecord,
        against key: Ed25519KeyInfo,
        context: LAContext
    ) throws {
        guard record.label == key.label else {
            throw PrivateKeyRecordError.labelMismatch(expected: key.label, actual: record.label)
        }
        guard record.algorithm.rawValue == key.algorithm else {
            throw PrivateKeyRecordError.algorithmMismatch(expected: key.algorithm, actual: record.algorithm.rawValue)
        }
        guard record.storageType == key.storageType else {
            throw PrivateKeyRecordError.storageMismatch(expected: key.storageType.rawValue, actual: record.storageType.rawValue)
        }
        guard record.purpose == key.purpose else {
            ClavisLogger.log("SECURITY_ALERT", "Key purpose mismatch: record='\(record.purpose.rawValue)', metadata='\(key.purpose.rawValue)'")
            throw PrivateKeyRecordError.purposeMismatch(
                expected: key.purpose.rawValue,
                actual: record.purpose.rawValue
            )
        }

        let derivedPublicBlob = try Self.derivePublicKeyBlob(record: record, context: context)
        guard derivedPublicBlob == key.publicKeyBlob else {
            ClavisLogger.log("SECURITY_ALERT", "Public key mismatch for '\(key.label)'! Possible metadata tampering.")
            throw PrivateKeyRecordError.publicKeyMismatch
        }
    }

    // Loads an authenticated record from Keychain.
    // If a legacy record is encountered, migrates it transparently using expected metadata,
    // saves the versioned StoredPrivateKeyRecord back to Keychain, and returns it.
    private func loadAuthenticatedRecord(
        label: String,
        context: LAContext,
        prompt: String,
        expectedKeyInfo: Ed25519KeyInfo?
    ) throws -> StoredPrivateKeyRecord {
        guard var rawData = try privateKeyStore.load(label: label, context: context, prompt: prompt) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key not found for '\(label)'"])
        }
        defer {
            rawData.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    SecureMemory.zero(base, byteCount: ptr.count)
                }
            }
        }

        // 1. Decode a modern record without downgrading malformed or future data to legacy.
        do {
            let record = try StoredPrivateKeyRecord.decode(from: rawData)
            guard record.label == label else {
                throw PrivateKeyRecordError.labelMismatch(expected: label, actual: record.label)
            }
            return record
        } catch let error as PrivateKeyRecordError {
            throw error
        } catch {
            let firstNonWhitespace = rawData.first { byte in
                byte != 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D
            }
            if firstNonWhitespace == 0x7B || firstNonWhitespace == 0x5B {
                throw PrivateKeyRecordError.corruptedRecord("Malformed versioned private-key record")
            }
        }

        // 2. Legacy records are accepted only when authoritative public metadata
        // identifies an exact supported format.
        ClavisLogger.log("KEYCHAIN_MIGRATE", "Migrating legacy Keychain record for '\(label)' to StoredPrivateKeyRecord (v\(StoredPrivateKeyRecord.currentVersion))...")
        guard let expected = expectedKeyInfo else {
            throw PrivateKeyRecordError.legacyRecordUnmigrated(label)
        }
        let algorithm: KeyAlgorithm
        let storageType: KeyStorageType
        let policy: BiometricPolicy?

        if expected.algorithm == "Ed25519", expected.storageType == .keychain, rawData.count == 32 {
            algorithm = .ed25519
            storageType = .keychain
            policy = nil
        } else if expected.algorithm == "ECDSA P-256", expected.storageType == .keychain, rawData.count == 32 {
            algorithm = .ecdsaP256
            storageType = .keychain
            policy = nil
        } else if expected.algorithm == "ECDSA P-256", expected.storageType == .secureEnclave {
            algorithm = .ecdsaP256
            storageType = .secureEnclave
            policy = expected.biometricPolicy ?? .userPresence
        } else {
            throw PrivateKeyRecordError.legacyRecordUnmigrated(label)
        }

        let record = StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: policy,
            keyPurpose: expected.keyPurpose,
            keyData: rawData,
            createdAt: expected.createdAt
        )

        let derivedPublicBlob = try Self.derivePublicKeyBlob(record: record, context: context)
        guard derivedPublicBlob == expected.publicKeyBlob else {
            throw PrivateKeyRecordError.publicKeyMismatch
        }

        // Save migrated record back to Keychain. Failure is propagated so the
        // caller never proceeds under an unpersisted migration assumption.
        let flags = policy?.accessControlFlags ?? [.userPresence]
        var encoded = try record.encode()
        defer {
            encoded.withUnsafeMutableBytes { raw in
                if let base = raw.baseAddress { SecureMemory.zero(base, byteCount: raw.count) }
            }
            encoded.removeAll(keepingCapacity: false)
        }
        try privateKeyStore.save(label: label, data: encoded, accessControlFlags: flags)
        ClavisLogger.log("KEYCHAIN_MIGRATE", "Successfully saved migrated record for '\(label)' to Keychain.")

        return record
    }

    private static func wipeData(_ data: inout Data) {
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { SecureMemory.zero(base, byteCount: raw.count) }
        }
        data.removeAll(keepingCapacity: false)
    }

    // Private scoped execution over the Ed25519 seed bytes held in a locked SecureBuffer.
    // Lexically scopes access to audited call sites (sign, unwrapAgeFileKey).
    private func withEd25519Seed<T>(
        label: String,
        prompt: String,
        useCache: Bool,
        requiredPurpose: KeyPurpose,
        operation: (UnsafeRawBufferPointer) throws -> T
    ) throws -> T {
        ClavisLogger.log("FETCH_KEY", "Access request for key '\(label)'")

        // 1. Check session cache
        if useCache, let result = try sessionCache.withCachedBuffer(
            label: label,
            expectedPurpose: requiredPurpose,
            operation: operation
        ) {
            ClavisLogger.log("SESSION_CACHE", "Served key '\(label)' from active session cache (0 prompts)")
            return result
        }

        let cacheGeneration = sessionCache.generationSnapshot()

        // 2. Cache miss: authenticate user
        ClavisLogger.log("TOUCH_ID_PROMPT", "Displaying user authentication prompt: \"\(prompt)\"")
        do {
            let context = try authenticator.authenticate(reason: prompt)
            ClavisLogger.log("TOUCH_ID_RESULT", "User authentication SUCCESS")

            // Verify generation hasn't changed during authentication prompt
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                throw SessionCacheError.invalidated
            }

            var record = try loadAuthenticatedRecord(
                label: label,
                context: context,
                prompt: prompt,
                expectedKeyInfo: try fetchKeyInfo(label: label)
            )
            defer { record.wipe() }

            // Security invariant: only software Ed25519 keys can be accessed as Ed25519 seeds
            guard record.algorithm == .ed25519 && record.storageType == .keychain else {
                throw PrivateKeyRecordError.algorithmMismatch(
                    expected: "Ed25519",
                    actual: "\(record.algorithm.rawValue) / \(record.storageType.rawValue)"
                )
            }
            guard record.purpose == requiredPurpose else {
                throw PrivateKeyRecordError.purposeNotAllowed(
                    purpose: record.purpose.rawValue,
                    operation: requiredPurpose == .general ? "general signing or Age decryption" : "the requested operation"
                )
            }

            var sensitiveData = record.keyData
            guard let secureBuffer = secureBufferFactory(&sensitiveData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
            }

            // Verify generation again before saving or operating
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                secureBuffer.wipe()
                throw SessionCacheError.invalidated
            }

            if useCache && sessionCache.currentTimeout != .never {
                let result = try sessionCache.setAndWithBuffer(
                    label: label,
                    buffer: secureBuffer,
                    purpose: record.purpose,
                    expectedGeneration: cacheGeneration,
                    operation: operation
                )
                ClavisLogger.log("FETCH_KEY_SUCCESS", "Key '\(label)' loaded from Keychain and placed into session cache.")
                return result
            } else {
                // Caching is disabled (.never): keep buffer purely local and wipe in defer
                defer {
                    secureBuffer.wipe()
                }
                ClavisLogger.log("FETCH_KEY_SUCCESS", "Key '\(label)' loaded from Keychain for a single-shot operation.")

                return try sessionCache.performIfGenerationCurrent(cacheGeneration) {
                    guard let result = try secureBuffer.withUnsafeBytes(operation) else {
                        throw SessionCacheError.invalidated
                    }
                    return result
                }
            }
        } catch {
            ClavisLogger.log("TOUCH_ID_RESULT", "User authentication FAILED: \(error.localizedDescription)")
            throw error
        }
    }

    // Sign challenge data using Ed25519 private key within scoped seed buffer
    public func sign(label: String, data: Data, prompt: String, useCache: Bool = true) throws -> Data {
        try withEd25519Seed(label: label, prompt: prompt, useCache: useCache, requiredPurpose: .general) { seedBytes in
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
            return try privateKey.signature(for: data)
        }
    }

    // Unwrap age file key directly using Ed25519 seed bytes without allocating intermediate Data or PrivateKey
    public func unwrapAgeFileKey(label: String, prompt: String, wrappedKey: Data, epkB64: String) throws -> Data {
        try withEd25519Seed(label: label, prompt: prompt, useCache: true, requiredPurpose: .general) { seedBytes in
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
    public func signSSH(
        key: Ed25519KeyInfo,
        data: Data,
        prompt: String,
        useCache: Bool = true
    ) throws -> Data {
        try signSSH(
            key: key,
            data: data,
            prompt: prompt,
            useCache: useCache,
            existingContext: nil
        )
    }

    internal func signSSH(
        key: Ed25519KeyInfo,
        data: Data,
        prompt: String,
        useCache: Bool,
        existingContext: LAContext?
    ) throws -> Data {
        let isGitSigningRequest = SSHSIGPayload.parse(from: data) != nil
        if key.purpose == .gitSigningOnly && !isGitSigningRequest {
            throw PrivateKeyRecordError.purposeNotAllowed(
                purpose: key.purpose.rawValue,
                operation: "non-Git SSH signing"
            )
        }

        // Fast path for software keys already present in session cache
        if useCache && existingContext == nil && key.storageType != .secureEnclave {
            if key.algorithm == "ECDSA P-256" {
                if let cachedSig = try sessionCache.withCachedP256(
                    label: key.label,
                    expectedPurpose: key.purpose,
                    operation: { try $0.signature(for: data) }
                ) {
                    ClavisLogger.log("SESSION_CACHE", "Served key '\(key.label)' (ECDSA P-256) from active session cache (0 prompts)")
                    return Self.formatECDSASignatureBlob(cachedSig)
                }
            } else if key.algorithm == "Ed25519" {
                if let cachedSig = try sessionCache.withCachedBuffer(label: key.label, expectedPurpose: key.purpose, operation: { seedBytes in
                    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
                    return try privateKey.signature(for: data)
                }) {
                    ClavisLogger.log("SESSION_CACHE", "Served key '\(key.label)' from active session cache (0 prompts)")
                    var sigBlob = Data()
                    sigBlob.appendWireString("ssh-ed25519")
                    sigBlob.appendWireData(cachedSig)
                    return sigBlob
                }
            }
        }

        let cacheGeneration = sessionCache.generationSnapshot()
        let context: LAContext
        if let existing = existingContext {
            context = existing
        } else {
            context = try authenticator.authenticate(reason: prompt)
        }
        guard sessionCache.isGenerationCurrent(cacheGeneration) else {
            throw SessionCacheError.invalidated
        }

        // 1. Load authoritative record from Keychain
        var record = try loadAuthenticatedRecord(
            label: key.label,
            context: context,
            prompt: prompt,
            expectedKeyInfo: key
        )
        defer { record.wipe() }

        // 2. Validate every policy field against the authenticated record.
        try validateAuthenticatedRecord(record, against: key, context: context)
        if record.purpose == .gitSigningOnly && !isGitSigningRequest {
            throw PrivateKeyRecordError.purposeNotAllowed(
                purpose: record.purpose.rawValue,
                operation: "non-Git SSH signing"
            )
        }

        // 3. Execute signature based strictly on authoritative record attributes
        switch record.algorithm {
        case .ecdsaP256:
            var localKeyToWipe: CachedP256SigningKey? = nil
            defer { localKeyToWipe?.wipe() }

            let ecdsaSig: P256.Signing.ECDSASignature
            if record.storageType == .secureEnclave {
                let seKey = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: record.keyData,
                    authenticationContext: context
                )
                localKeyToWipe = .secureEnclave(seKey)
                guard let signingKey = localKeyToWipe else { throw SessionCacheError.invalidated }
                ecdsaSig = try sessionCache.performIfGenerationCurrent(cacheGeneration) {
                    try signingKey.signature(for: data)
                }
            } else {
                var scalarData = record.keyData
                guard let buf = secureBufferFactory(&scalarData) else {
                    throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(key.label)'"])
                }
                localKeyToWipe = .software(buf)
                guard let signingKey = localKeyToWipe else { throw SessionCacheError.invalidated }
                guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                    signingKey.wipe()
                    throw SessionCacheError.invalidated
                }

                if useCache && sessionCache.currentTimeout != .never {
                    localKeyToWipe = nil
                    ecdsaSig = try sessionCache.setAndWithP256(
                        label: key.label,
                        key: signingKey,
                        purpose: record.purpose,
                        expectedGeneration: cacheGeneration,
                        operation: { try $0.signature(for: data) }
                    )
                } else {
                    ecdsaSig = try sessionCache.performIfGenerationCurrent(cacheGeneration) {
                        try signingKey.signature(for: data)
                    }
                }
            }
            return Self.formatECDSASignatureBlob(ecdsaSig)

        case .ed25519:
            guard record.storageType == .keychain else {
                throw PrivateKeyRecordError.storageMismatch(expected: KeyStorageType.keychain.rawValue, actual: record.storageType.rawValue)
            }

            var seedData = record.keyData
            guard let secureBuffer = secureBufferFactory(&seedData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(key.label)'"])
            }
            guard sessionCache.isGenerationCurrent(cacheGeneration) else {
                secureBuffer.wipe()
                throw SessionCacheError.invalidated
            }

            let signature: Data
            if useCache && sessionCache.currentTimeout != .never {
                signature = try sessionCache.setAndWithBuffer(
                    label: key.label,
                    buffer: secureBuffer,
                    purpose: record.purpose,
                    expectedGeneration: cacheGeneration,
                    operation: { seedBytes in
                        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
                        return try privateKey.signature(for: data)
                    }
                )
            } else {
                defer { secureBuffer.wipe() }
                signature = try sessionCache.performIfGenerationCurrent(cacheGeneration) {
                    guard let res = try secureBuffer.withUnsafeBytes({ seedBytes in
                        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
                        return try privateKey.signature(for: data)
                    }) else {
                        throw SessionCacheError.invalidated
                    }
                    return res
                }
            }

            var sigBlob = Data()
            sigBlob.appendWireString("ssh-ed25519")
            sigBlob.appendWireData(signature)
            return sigBlob
        }
    }

    /// Authorizes a 5-minute Git signing grant via Touch ID, returning an active grant.
    @discardableResult
    internal func authorizeGitSigningGrant(
        key: Ed25519KeyInfo,
        prompt: String,
        clientIdentity: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200
    ) throws -> GitSigningGrant {
        let context = try authenticator.authenticate(reason: prompt)
        var record = try loadAuthenticatedRecord(
            label: key.label,
            context: context,
            prompt: prompt,
            expectedKeyInfo: key
        )
        defer { record.wipe() }

        try validateAuthenticatedRecord(record, against: key, context: context)

        return GitSigningGraceManager.shared.recordGrant(
            keyLabel: key.label,
            clientIdentity: clientIdentity,
            duration: duration,
            maxOperations: maxOperations,
            context: context
        )
    }

    public static func formatECDSASignatureBlob(_ ecdsaSig: P256.Signing.ECDSASignature) -> Data {
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

    // Unlock a key with Touch ID / password and place in session cache
    public func unlock(label: String, prompt: String? = nil) async throws {
        // Fast preliminary check: if public metadata says hardware, fail fast
        if let keyInfo = try fetchKeyInfo(label: label), keyInfo.storageType == .secureEnclave {
            throw SessionCacheError.hardwareNotCacheable
        }

        let reason = prompt ?? "Touch ID to unlock '\(label)'"
        guard sessionCache.currentTimeout.timeInterval != nil else {
            throw SessionCacheError.disabled
        }
        let cacheGeneration = sessionCache.generationSnapshot()

        let context = try await authenticator.authenticate(reason: reason)
        guard sessionCache.isGenerationCurrent(cacheGeneration) else {
            throw SessionCacheError.invalidated
        }

        // Load authoritative record from Keychain
        var record = try loadAuthenticatedRecord(
            label: label,
            context: context,
            prompt: reason,
            expectedKeyInfo: try fetchKeyInfo(label: label)
        )
        defer { record.wipe() }

        // Hard invariant: never unlock hardware keys into session cache,
        // regardless of what keys.json claimed!
        guard record.storageType != .secureEnclave else {
            throw SessionCacheError.hardwareNotCacheable
        }

        guard let timeout = sessionCache.currentTimeout.timeInterval else {
            throw SessionCacheError.disabled
        }

        switch record.algorithm {
        case .ecdsaP256:
            var scalarData = record.keyData
            guard let buf = secureBufferFactory(&scalarData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
            }
            let signingKey = CachedP256SigningKey.software(buf)
            guard sessionCache.setP256(
                label: label,
                key: signingKey,
                purpose: record.purpose,
                expectedGeneration: cacheGeneration
            ) else {
                signingKey.wipe()
                throw SessionCacheError.invalidated
            }

        case .ed25519:
            guard record.keyData.count == 32 else {
                throw PrivateKeyRecordError.corruptedRecord("Invalid Ed25519 seed length: \(record.keyData.count)")
            }
            var seedData = record.keyData
            guard let buf = secureBufferFactory(&seedData) else {
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to allocate secure buffer for key '\(label)'"])
            }
            guard sessionCache.set(
                label: label,
                buffer: buf,
                purpose: record.purpose,
                expectedGeneration: cacheGeneration
            ) else {
                buf.wipe()
                throw SessionCacheError.invalidated
            }
        }
        ClavisLogger.log("KEY_UNLOCK", "Key '\(label)' unlocked successfully for \(Int(timeout))s.")
    }

    // Lock a key immediately
    public func lockKey(label: String) throws {
        try revokeKeyCapabilities(label: label)
        ClavisLogger.log("KEY_LOCK", "Key '\(label)' locked.")
    }

    private func revokeKeyCapabilities(label: String) throws {
        sessionCache.remove(label: label)
        GitSigningGraceManager.shared.invalidate(keyLabel: label)
        try agentGrantRevoker(label)
    }

    // Convert Curve25519.Signing.PrivateKey to OpenSSH public key format & wire representation
    public func makeKeyInfo(
        label: String,
        privateKey: Curve25519.Signing.PrivateKey,
        algorithm: String = "Ed25519",
        storageType: KeyStorageType = .keychain,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        let pubKeyData = privateKey.publicKey.rawRepresentation
        let keyType = "ssh-ed25519"

        var blob = Data()
        blob.appendWireString(keyType)
        blob.appendWireData(pubKeyData)

        let b64 = blob.base64EncodedString()
        let openSSH = "\(keyType) \(b64) \(label)"

        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: openSSH,
            publicKeyBlob: blob,
            fingerprint: fingerprint,
            createdAt: Date(),
            algorithmName: algorithm,
            storage: storageType,
            keyPurpose: keyPurpose
        )
    }

    private func migrateLegacySeedFiles() {
        for keyInfo in PublicKeyStore.loadAll() where SeedStore.hasSeedFile(label: keyInfo.label) {
            do {
                if !privateKeyStore.contains(label: keyInfo.label) {
                    guard var keyData = SeedStore.load(label: keyInfo.label) else {
                        ClavisLogger.log("KEYCHAIN_MIGRATE", "Could not decrypt legacy seed for '\(keyInfo.label)'; keeping the original file.")
                        continue
                    }
                    defer {
                        keyData.withUnsafeMutableBytes { raw in
                            if let base = raw.baseAddress {
                                SecureMemory.zero(base, byteCount: raw.count)
                            }
                        }
                        keyData.removeAll(keepingCapacity: false)
                    }

                    var record = StoredPrivateKeyRecord(
                        label: keyInfo.label,
                        algorithm: (keyInfo.algorithm == "ECDSA P-256") ? .ecdsaP256 : .ed25519,
                        storageType: keyInfo.storageType,
                        biometricPolicy: keyInfo.biometricPolicy,
                        keyData: keyData
                    )
                    defer { record.wipe() }
                    let recordData = try record.encode()
                    try privateKeyStore.save(label: keyInfo.label, data: recordData, accessControlFlags: keyInfo.effectiveBiometricPolicy.accessControlFlags)
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
