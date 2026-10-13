import Foundation
import Security
import CryptoKit
import LocalAuthentication
import AppKit

public class KeychainManager {
    public static let privateServiceName = "com.clavis.private-record.v2"
    public static let publicServiceName = "com.clavis.ed25519.pub"
    public static let shared = KeychainManager()
    public static var customSigningProvider: SecureEnclaveSigningProviding? = nil

    private let authenticator: UserAuthenticating
    private let privateKeyStore: PrivateKeyStoring
    private let agentGrantRevoker: (String) throws -> Void
    private let auditRecorder: AuditRecording
    private let instanceSigningProvider: SecureEnclaveSigningProviding?

    public var activeSigningProvider: SecureEnclaveSigningProviding {
        instanceSigningProvider ?? Self.customSigningProvider ?? ProductionSecureEnclaveSigningProvider()
    }

    public init(
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        privateKeyStore: PrivateKeyStoring = KeychainPrivateKeyStore(),
        agentGrantRevoker: @escaping (String) throws -> Void = { label in
            try AgentLifecycleManager.shared.invalidateAgentGrant(label: label)
        },
        auditRecorder: AuditRecording = AuditRecorder.shared,
        signingProvider: SecureEnclaveSigningProviding? = nil
    ) {
        self.authenticator = authenticator
        self.privateKeyStore = privateKeyStore
        self.agentGrantRevoker = agentGrantRevoker
        self.auditRecorder = auditRecorder
        self.instanceSigningProvider = signingProvider
    }

    // Generate new Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(
        label: String,
        algorithm: String = "ECDSA P-256",
        storageType: KeyStorageType = .secureEnclave,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general
    ) throws -> Ed25519KeyInfo {
        try validateLabel(label)
        try validateGenerationConfiguration(algorithm: algorithm, storageType: storageType)
        if try fetchKeyInfo(label: label) != nil || privateKeyStore.contains(label: label) {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' already exists. Delete it first before generating a new key with this label."])
        }
        _ = try EncryptedVaultStore.shared.ensureMasterKey()

        guard activeSigningProvider.isAvailable else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Apple Secure Enclave is not available on this device."])
        }

        let policy = biometricPolicy ?? .userPresence
        let accessControl = try PrivateKeyAccessControl.make(flags: policy.accessControlFlags)
        let (dataRepresentation, pubKeyData) = try activeSigningProvider.generateKey(accessControl: accessControl)

        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: policy,
            keyPurpose: keyPurpose,
            keyData: dataRepresentation
        )
        defer { record.wipe() }
        var recordData = try record.encode()
        defer { Self.wipeData(&recordData) }
        // The serialized value is an opaque Secure Enclave reference.
        // The hardware key keeps its own biometric policy above; user
        // presence here only protects the handle from other processes.
        try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [.userPresence])
        do {
            try EncryptedVaultStore.shared.saveRecord(record)
        } catch {
            ClavisLogger.log("VAULT_WARNING", "Failed to backup private record to shadow vault: \(error.localizedDescription)")
            try? privateKeyStore.remove(label: label)
            throw error
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
            biometricPolicy: policy,
            keyPurpose: keyPurpose
        )
        do {
            try PublicKeyStore.saveChecked(keyInfo)
        } catch {
            try? privateKeyStore.remove(label: label)
            EncryptedVaultStore.shared.removeRecord(label: label)
            throw error
        }
        auditRecorder.record(
            AuditEvent(
                type: .keyCreate,
                result: .allowed,
                keyFingerprint: keyInfo.fingerprint,
                keyKind: .personal,
                sensitive: AuditSensitive(keyLabel: keyInfo.label, processChain: [], host: nil)
            )
        )
        return keyInfo
    }

    private func validateGenerationConfiguration(algorithm: String, storageType: KeyStorageType) throws {
        let isSupported = (algorithm == "ECDSA P-256" || algorithm == KeyAlgorithm.ecdsaP256.rawValue) &&
            storageType == .secureEnclave
        guard isSupported else {
            throw NSError(
                domain: "Clavis",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Unsupported key algorithm or storage combination: \(algorithm) / \(storageType.rawValue)."]
            )
        }
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
        let fingerprint = (try? fetchKeyInfo(label: label))?.fingerprint
        ClavisLogger.log("KEY_DELETE", "Deleting key '\(label)'...")
        let prompt = "Authenticate to permanently delete key '\(label)'"
        ClavisLogger.promptDebug("clavis-code", "KeychainManager: prompting for key deletion '\(label)': \"\(prompt)\"")
        let context: LAContext
        do {
            context = try authenticator.authenticate(reason: prompt)
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .keyDelete,
                    result: .denied,
                    reason: .authenticationFailed,
                    keyFingerprint: fingerprint,
                    keyKind: .personal,
                    sensitive: AuditSensitive(keyLabel: label, processChain: [], host: nil)
                )
            )
            throw error
        }

        var revocationError: Error?
        do {
            try revokeKeyCapabilities(label: label)
        } catch {
            revocationError = error
            ClavisLogger.log("KEY_DELETE", "Revocation notice: \(error.localizedDescription). Proceeding with local key removal.")
        }

        // A same-user process can replace the Keychain item with a well-formed record for a
        // different key. Only drop the vault copy when that item is absent or is the same key
        // the user just authenticated to delete. Always try to remove the Keychain item itself.
        let removeVault = shouldRemoveVaultRecord(label: label, context: context, prompt: prompt)
        do {
            try privateKeyStore.remove(label: label, context: context, prompt: prompt)
        } catch {
            ClavisLogger.log("KEY_DELETE", "Warning: Keychain private key removal encountered error (\(error.localizedDescription)). Proceeding with metadata cleanup.")
        }
        if removeVault {
            EncryptedVaultStore.shared.removeRecord(label: label)
            try PublicKeyStore.removeChecked(label: label)
            ClavisLogger.log("KEY_DELETE", "Key '\(label)' deleted successfully.")
            auditRecorder.record(
                AuditEvent(
                    type: .keyDelete,
                    result: .allowed,
                    keyFingerprint: fingerprint,
                    keyKind: .personal,
                    sensitive: AuditSensitive(keyLabel: label, processChain: [], host: nil)
                )
            )
        } else {
            if let revocationError {
                ClavisLogger.log(
                    "SECURITY_ALERT",
                    "Failed to revoke SSH agent grant during partial deletion of key '\(label)': \(revocationError.localizedDescription)"
                )
            }
            ClavisLogger.log(
                "KEY_DELETE",
                "Removed the Keychain item for '\(label)' but left the encrypted vault record in place because it did not match the authenticated key."
            )
            auditRecorder.record(
                AuditEvent(
                    type: .keyDelete,
                    result: .failed,
                    reason: .partialDeletion,
                    keyFingerprint: fingerprint,
                    keyKind: .personal,
                    sensitive: AuditSensitive(keyLabel: label, processChain: [], host: nil)
                )
            )
            throw KeyDeletionError.partial(label: label)
        }

        if let revocationError {
            throw revocationError
        }
    }

    // MARK: - Authenticated Private Key Records & Verification

    // Derives the OpenSSH wire format public key blob directly from an authenticated private record.
    public static func derivePublicKeyBlob(
        record: StoredPrivateKeyRecord,
        context: LAContext? = nil,
        provider: SecureEnclaveSigningProviding? = nil
    ) throws -> Data {
        guard record.algorithm == .ecdsaP256 && record.storageType == .secureEnclave else {
            throw PrivateKeyRecordError.corruptedRecord("Unsupported key algorithm or storage type")
        }
        let activeProvider = provider ?? customSigningProvider ?? ProductionSecureEnclaveSigningProvider()
        let pubKeyData = try activeProvider.derivePublicKey(dataRepresentation: record.keyData, context: context)

        var blob = Data()
        blob.appendWireString("ecdsa-sha2-nistp256")
        blob.appendWireString("nistp256")
        blob.appendWireData(pubKeyData)
        return blob
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
            if record.purpose == .agent || key.purpose == .agent {
                throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
            }
            ClavisLogger.log("SECURITY_ALERT", "Key purpose mismatch: record='\(record.purpose.rawValue)', metadata='\(key.purpose.rawValue)'")
            throw PrivateKeyRecordError.purposeMismatch(
                expected: key.purpose.rawValue,
                actual: record.purpose.rawValue
            )
        }

        // The authentication policy used to prompt the user was chosen from the public index, which is an
        // unauthenticated display cache. Refuse to proceed if the authoritative record disagrees,
        // so a tampered index can only cause a refusal, never a weaker effective policy.
        let recordPolicy = record.biometricPolicy ?? .userPresence
        guard recordPolicy == key.effectiveBiometricPolicy else {
            ClavisLogger.log("SECURITY_ALERT", "Biometric policy mismatch for '\(key.label)': record='\(recordPolicy.rawValue)', metadata='\(key.effectiveBiometricPolicy.rawValue)'")
            throw PrivateKeyRecordError.metadataMismatch(
                field: "biometricPolicy",
                expected: key.effectiveBiometricPolicy.rawValue,
                actual: recordPolicy.rawValue
            )
        }

        let derivedPublicBlob = try Self.derivePublicKeyBlob(record: record, context: context, provider: activeSigningProvider)
        guard derivedPublicBlob == key.publicKeyBlob else {
            ClavisLogger.log("SECURITY_ALERT", "Public key mismatch for '\(key.label)'! Possible metadata tampering.")
            throw PrivateKeyRecordError.publicKeyMismatch
        }
    }

    /// True only when deleting the vault record removes the same key the user authenticated.
    /// A decoded Keychain item whose public key does not match the index is left in the vault.
    private func shouldRemoveVaultRecord(label: String, context: LAContext, prompt: String) -> Bool {
        let loaded: Data?
        do {
            loaded = try privateKeyStore.load(label: label, context: context, prompt: prompt)
        } catch {
            ClavisLogger.log("KEY_DELETE", "Could not read the Keychain record for '\(label)' (\(error.localizedDescription)). Preserving the vault copy.")
            return false
        }

        guard var rawData = loaded else {
            return true
        }
        defer { Self.wipeData(&rawData) }

        guard var record = try? StoredPrivateKeyRecord.decode(from: rawData) else {
            ClavisLogger.log("KEY_DELETE", "Keychain record for '\(label)' did not decode. Preserving the vault copy.")
            return false
        }
        defer { record.wipe() }

        guard record.label == label else {
            return false
        }

        if let index = try? fetchKeyInfo(label: label) {
            guard let derived = try? Self.derivePublicKeyBlob(record: record, context: context, provider: activeSigningProvider) else {
                return false
            }
            if derived != index.publicKeyBlob {
                ClavisLogger.log("SECURITY_ALERT", "Refusing to delete the vault record for '\(label)' because the Keychain public key does not match the index.")
                return false
            }
            return true
        }

        let vaultRecord: StoredPrivateKeyRecord?
        do {
            vaultRecord = try EncryptedVaultStore.shared.loadRecord(label: label, context: context)
        } catch {
            ClavisLogger.log("KEY_DELETE", "Could not read the vault record for '\(label)' (\(error.localizedDescription)). Preserving it.")
            return false
        }
        guard var vaultRecord else {
            return true
        }
        defer { vaultRecord.wipe() }
        guard vaultRecord.label == label,
              let keychainBlob = try? Self.derivePublicKeyBlob(record: record, context: context, provider: activeSigningProvider),
              let vaultBlob = try? Self.derivePublicKeyBlob(record: vaultRecord, context: context) else {
            return false
        }
        return keychainBlob == vaultBlob
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
            return try restoreRecordFromVault(
                label: label,
                context: context,
                expectedKeyInfo: expectedKeyInfo,
                logMessage: "Restored missing Keychain record for '\(label)' from encrypted shadow vault."
            )
        }
        defer { Self.wipeData(&rawData) }

        do {
            var record = try StoredPrivateKeyRecord.decode(from: rawData)
            if let expectedKeyInfo {
                do {
                    try validateAuthenticatedRecord(record, against: expectedKeyInfo, context: context)
                    return record
                } catch let validationError {
                    record.wipe()
                    if let keyPurposeError = validationError as? KeyPurposeError {
                        throw keyPurposeError
                    }
                    ClavisLogger.log(
                        "SECURITY_ALERT",
                        "Keychain record validation failed for '\(label)': \(validationError.localizedDescription). Attempting restore from encrypted shadow vault."
                    )
                    do {
                        return try restoreRecordFromVault(
                            label: label,
                            context: context,
                            expectedKeyInfo: expectedKeyInfo,
                            logMessage: "Restored mismatched Keychain record for '\(label)' from encrypted shadow vault."
                        )
                    } catch {
                        throw validationError
                    }
                }
            }
            guard record.label == label else {
                let actual = record.label
                record.wipe()
                throw PrivateKeyRecordError.labelMismatch(expected: label, actual: actual)
            }
            return record
        } catch let error as KeyPurposeError {
            throw error
        } catch let error as PrivateKeyRecordError {
            throw error
        } catch {
            do {
                return try restoreRecordFromVault(
                    label: label,
                    context: context,
                    expectedKeyInfo: expectedKeyInfo,
                    logMessage: "Restored corrupted Keychain record for '\(label)' from encrypted shadow vault."
                )
            } catch let error as KeyPurposeError {
                throw error
            } catch let error as PrivateKeyRecordError {
                throw error
            } catch {
                throw PrivateKeyRecordError.corruptedRecord("Malformed private-key record: \(error.localizedDescription)")
            }
        }
    }

    private func restoreRecordFromVault(
        label: String,
        context: LAContext,
        expectedKeyInfo: Ed25519KeyInfo?,
        logMessage: String
    ) throws -> StoredPrivateKeyRecord {
        guard var restoredRecord = try EncryptedVaultStore.shared.loadRecord(label: label, context: context) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key not found for '\(label)'"])
        }

        do {
            if let expectedKeyInfo {
                try validateAuthenticatedRecord(restoredRecord, against: expectedKeyInfo, context: context)
            } else {
                guard restoredRecord.label == label else {
                    throw PrivateKeyRecordError.labelMismatch(expected: label, actual: restoredRecord.label)
                }
            }
        } catch {
            restoredRecord.wipe()
            throw error
        }

        ClavisLogger.log("KEYCHAIN_RESTORE", logMessage)
        if var bytes = try? restoredRecord.encode() {
            defer { Self.wipeData(&bytes) }
            do {
                try privateKeyStore.save(label: label, data: bytes, accessControlFlags: [.userPresence])
            } catch let error as PrivateKeyStoreError {
                if case .protectionUnavailable = error {
                    throw error
                }
            } catch {
                // Non-fatal if keychain restore write fails for other reasons
            }
        }
        return restoredRecord
    }

    @discardableResult
    public func repairVault(
        replacePin: Bool = false,
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, fingerprint: String) {
        try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: replacePin, context: context)
    }

    private static func wipeData(_ data: inout Data) {
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { SecureMemory.zero(base, byteCount: raw.count) }
        }
        data.removeAll(keepingCapacity: false)
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
            existingContext: nil,
            allowedPurposes: AgentSocketRole.personal.allowedPurposes
        )
    }

    internal func signSSH(
        key: Ed25519KeyInfo,
        data: Data,
        prompt: String,
        useCache: Bool,
        existingContext: LAContext?,
        allowedPurposes: Set<KeyPurpose> = AgentSocketRole.personal.allowedPurposes
    ) throws -> Data {
        guard allowedPurposes.contains(key.purpose) else {
            throw KeyPurposeError.notAllowedOnThisPath(key.purpose)
        }

        let isGitSigningRequest = SSHSIGPayload.parse(from: data) != nil
        if key.purpose == .gitSigningOnly && !isGitSigningRequest {
            throw PrivateKeyRecordError.purposeNotAllowed(
                purpose: key.purpose.rawValue,
                operation: "non-Git SSH signing"
            )
        }

        let context: LAContext
        if let existing = existingContext {
            context = existing
        } else {
            let laPolicy: LAPolicy = key.effectiveBiometricPolicy.laPolicy
            ClavisLogger.promptDebug("clavis-code", "KeychainManager: prompting for SSH signature '\(key.label)' (storage: \(key.storageType.rawValue), policy: \(key.biometricPolicy?.rawValue ?? "default")): \"\(prompt)\"")
            context = try authenticator.authenticate(reason: prompt, policy: laPolicy)
        }

        // 1. Load authoritative record from Keychain
        var record = try loadAuthenticatedRecord(
            label: key.label,
            context: context,
            prompt: prompt,
            expectedKeyInfo: key
        )
        defer { record.wipe() }

        guard allowedPurposes.contains(record.purpose) else {
            throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
        }

        // 2. Validate every policy field against the authenticated record.
        try validateAuthenticatedRecord(record, against: key, context: context)
        if record.purpose == .gitSigningOnly && !isGitSigningRequest {
            throw PrivateKeyRecordError.purposeNotAllowed(
                purpose: record.purpose.rawValue,
                operation: "non-Git SSH signing"
            )
        }

        // 3. Execute signature based strictly on authoritative record attributes
        guard record.algorithm == .ecdsaP256 && record.storageType == .secureEnclave else {
            throw PrivateKeyRecordError.storageMismatch(expected: KeyStorageType.secureEnclave.rawValue, actual: record.storageType.rawValue)
        }
        let ecdsaSig = try activeSigningProvider.signature(for: data, dataRepresentation: record.keyData, context: context)
        return Self.formatECDSASignatureBlob(ecdsaSig)
    }

    /// Authorizes a 5-minute Git signing grant via Touch ID, returning an active grant.
    @discardableResult
    internal func authorizeGitSigningGrant(
        key: Ed25519KeyInfo,
        prompt: String,
        clientIdentity: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        approvedProcess: GitApprovedProcess? = nil
    ) throws -> GitSigningGrant {
        guard key.purpose != .agent else {
            throw KeyPurposeError.notAllowedOnThisPath(.agent)
        }

        // Match signSSH: strict biometric keys must not accept a password fallback.
        // The returned context is reused for later signatures, so a weaker policy here
        // would quietly downgrade every signature under the grant.
        let laPolicy: LAPolicy = (key.biometricPolicy == .biometryCurrentSet)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        let context = try authenticator.authenticate(reason: prompt, policy: laPolicy)
        var record: StoredPrivateKeyRecord
        do {
            record = try loadAuthenticatedRecord(
                label: key.label,
                context: context,
                prompt: prompt,
                expectedKeyInfo: key
            )
        } catch {
            // loadAuthenticatedRecord rejects a public-index policy that is weaker than the
            // record. Invalidate that context here so it cannot be reused for a grant.
            if laPolicy != .deviceOwnerAuthenticationWithBiometrics,
               case PrivateKeyRecordError.metadataMismatch(let field, _, _) = error,
               field == "biometricPolicy" {
                context.invalidate()
            }
            if error is KeyPurposeError {
                context.invalidate()
            }
            throw error
        }
        defer { record.wipe() }

        guard record.purpose != .agent else {
            context.invalidate()
            throw KeyPurposeError.notAllowedOnThisPath(.agent)
        }

        try validateAuthenticatedRecord(record, against: key, context: context)

        // the public index chose the LocalAuthentication policy above and is not authenticated.
        // If the Keychain record requires the current biometric set, refuse a context
        // that was evaluated with a weaker policy and do not record the grant.
        let recordPolicy = record.biometricPolicy ?? .userPresence
        if recordPolicy == .biometryCurrentSet && laPolicy != .deviceOwnerAuthenticationWithBiometrics {
            context.invalidate()
            ClavisLogger.log("SECURITY_ALERT", "Refusing Git signing grant for '\(key.label)': record requires biometryCurrentSet but the authentication context was not evaluated with biometrics.")
            throw PrivateKeyRecordError.metadataMismatch(
                field: "biometricPolicy",
                expected: BiometricPolicy.userPresence.rawValue,
                actual: recordPolicy.rawValue
            )
        }

        try validateAuthenticatedRecord(record, against: key, context: context)

        context.interactionNotAllowed = true

        guard record.storageType == .secureEnclave else {
            context.invalidate()
            throw PrivateKeyRecordError.storageMismatch(expected: KeyStorageType.secureEnclave.rawValue, actual: record.storageType.rawValue)
        }

        let provider = activeSigningProvider
        let keyData = record.keyData
        let hardwareSigner: @Sendable (Data) throws -> Data = { dataToSign in
            let ecdsaSig = try provider.signature(for: dataToSign, dataRepresentation: keyData, context: context)
            return KeychainManager.formatECDSASignatureBlob(ecdsaSig)
        }
        return GitSigningGraceManager.shared.recordGrant(
            keyLabel: key.label,
            clientIdentity: clientIdentity,
            duration: duration,
            maxOperations: maxOperations,
            context: context,
            approvedProcess: approvedProcess,
            hardwareSigner: hardwareSigner
        )
    }

    /// Authorizes an agent session via Touch ID, returning an active grant.
    internal func authorizeAgentSession(
        key: Ed25519KeyInfo,
        prompt: String
    ) throws -> AgentSessionGrant {
        guard key.purpose == .agent else {
            throw KeyPurposeError.notAllowedOnThisPath(key.purpose)
        }

        let laPolicy: LAPolicy = (key.biometricPolicy == .biometryCurrentSet)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        ClavisLogger.promptDebug("clavis-code", "KeychainManager: prompting for agent session authorization '\(key.label)': \"\(prompt)\"")
        let context = try authenticator.authenticate(reason: prompt, policy: laPolicy)
        var record: StoredPrivateKeyRecord
        do {
            record = try loadAuthenticatedRecord(
                label: key.label,
                context: context,
                prompt: prompt,
                expectedKeyInfo: key
            )
        } catch {
            if laPolicy != .deviceOwnerAuthenticationWithBiometrics,
               case PrivateKeyRecordError.metadataMismatch(let field, _, _) = error,
               field == "biometricPolicy" {
                context.invalidate()
            }
            if error is KeyPurposeError {
                context.invalidate()
            }
            throw error
        }
        defer { record.wipe() }

        guard record.purpose == .agent else {
            context.invalidate()
            throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
        }

        let recordPolicy = record.biometricPolicy ?? .userPresence
        if recordPolicy == .biometryCurrentSet && laPolicy != .deviceOwnerAuthenticationWithBiometrics {
            context.invalidate()
            ClavisLogger.log("SECURITY_ALERT", "Refusing agent session for '\(key.label)': record requires biometryCurrentSet but the authentication context was not evaluated with biometrics.")
            throw PrivateKeyRecordError.metadataMismatch(
                field: "biometricPolicy",
                expected: BiometricPolicy.userPresence.rawValue,
                actual: recordPolicy.rawValue
            )
        }

        try validateAuthenticatedRecord(record, against: key, context: context)

        context.interactionNotAllowed = true

        guard record.storageType == .secureEnclave else {
            context.invalidate()
            throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
        }

        let provider = activeSigningProvider
        let keyData = record.keyData
        let hardwareSigner: @Sendable (Data) throws -> Data = { dataToSign in
            let ecdsaSig = try provider.signature(for: dataToSign, dataRepresentation: keyData, context: context)
            return KeychainManager.formatECDSASignatureBlob(ecdsaSig)
        }
        return AgentSessionGrant(
            key: key,
            context: context,
            hardwareSigner: hardwareSigner
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

    // Lock a key immediately
    public func lockKey(label: String) throws {
        try revokeKeyCapabilities(label: label)
        ClavisLogger.log("KEY_LOCK", "Key '\(label)' locked.")
    }

    private func revokeKeyCapabilities(label: String) throws {
        GitSigningGraceManager.shared.invalidate(keyLabel: label)
        try agentGrantRevoker(label)
    }

    /// Change key purpose between general and agent. Requires user presence authentication.
    public func changeKind(label: String, to newPurpose: KeyPurpose, prompt: String? = nil) throws {
        guard let key = try fetchKeyInfo(label: label) else {
            throw NSError(
                domain: "Clavis",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Key with label '\(label)' not found."]
            )
        }

        let currentPurpose = key.purpose
        guard (currentPurpose == .general && newPurpose == .agent) || (currentPurpose == .agent && newPurpose == .general) else {
            throw KeyPurposeError.kindChangeNotAllowed
        }

        let laPolicy: LAPolicy = (key.biometricPolicy == .biometryCurrentSet)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication

        let reason = prompt ?? "Touch ID to change key kind for '\(label)'"
        let context: LAContext
        do {
            context = try authenticator.authenticate(reason: reason, policy: laPolicy)
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .keyKindChange,
                    result: .denied,
                    reason: .authenticationFailed,
                    keyFingerprint: key.fingerprint,
                    keyKind: newPurpose.auditKind,
                    sensitive: AuditSensitive(keyLabel: label, processChain: [], host: nil)
                )
            )
            throw error
        }

        var record: StoredPrivateKeyRecord
        do {
            record = try loadAuthenticatedRecord(
                label: label,
                context: context,
                prompt: reason,
                expectedKeyInfo: key
            )
        } catch {
            if laPolicy != .deviceOwnerAuthenticationWithBiometrics,
               case PrivateKeyRecordError.metadataMismatch(let field, _, _) = error,
               field == "biometricPolicy" {
                context.invalidate()
            }
            if error is KeyPurposeError {
                context.invalidate()
            }
            throw error
        }
        defer { record.wipe() }

        try validateAuthenticatedRecord(record, against: key, context: context)

        let recordPolicy = record.biometricPolicy ?? .userPresence
        if recordPolicy == .biometryCurrentSet && laPolicy != .deviceOwnerAuthenticationWithBiometrics {
            context.invalidate()
            ClavisLogger.log("SECURITY_ALERT", "Refusing key kind change for '\(key.label)': record requires biometryCurrentSet but the authentication context was not evaluated with biometrics.")
            throw PrivateKeyRecordError.metadataMismatch(
                field: "biometricPolicy",
                expected: BiometricPolicy.userPresence.rawValue,
                actual: recordPolicy.rawValue
            )
        }

        guard (record.purpose == .general && newPurpose == .agent) || (record.purpose == .agent && newPurpose == .general) else {
            throw KeyPurposeError.kindChangeNotAllowed
        }

        var updatedRecord = StoredPrivateKeyRecord(
            version: record.version,
            label: record.label,
            algorithm: record.algorithm,
            storageType: record.storageType,
            biometricPolicy: record.biometricPolicy,
            keyPurpose: newPurpose,
            keyData: record.keyData,
            createdAt: record.createdAt
        )
        defer { updatedRecord.wipe() }

        let hasVaultRecord = EncryptedVaultStore.shared.hasRecord(label: label)
        if hasVaultRecord {
            try EncryptedVaultStore.shared.saveRecord(updatedRecord)
        }

        var recordData = try updatedRecord.encode()
        defer { Self.wipeData(&recordData) }

        do {
            try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [.userPresence])
        } catch {
            if hasVaultRecord {
                try? EncryptedVaultStore.shared.saveRecord(record)
            }
            throw error
        }

        let updatedKeyInfo = Ed25519KeyInfo(
            label: key.label,
            publicKeyOpenSSH: key.publicKeyOpenSSH,
            publicKeyBlob: key.publicKeyBlob,
            fingerprint: key.fingerprint,
            createdAt: key.createdAt,
            algorithmName: key.algorithmName,
            storage: key.storageType,
            biometricPolicy: key.biometricPolicy,
            keyPurpose: newPurpose
        )

        do {
            try PublicKeyStore.saveChecked(updatedKeyInfo)
        } catch {
            if var originalRecordData = try? record.encode() {
                defer { Self.wipeData(&originalRecordData) }
                try? privateKeyStore.save(label: label, data: originalRecordData, accessControlFlags: [.userPresence])
            }
            if hasVaultRecord {
                try? EncryptedVaultStore.shared.saveRecord(record)
            }
            throw error
        }

        try revokeKeyCapabilities(label: label)

        auditRecorder.record(
            AuditEvent(
                type: .keyKindChange,
                result: .allowed,
                keyFingerprint: key.fingerprint,
                keyKind: newPurpose.auditKind,
                sensitive: AuditSensitive(keyLabel: label, processChain: [], host: nil)
            )
        )
        ClavisLogger.log("KEY_CHANGE_KIND", "Changed purpose of '\(label)' from '\(currentPurpose.rawValue)' to '\(newPurpose.rawValue)'.")
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

public enum KeyDeletionError: LocalizedError, Equatable {
    case partial(label: String)

    public var errorDescription: String? {
        switch self {
        case .partial(let label):
            return "Failed to safely remove vault record for key '\(label)': key mismatch detected. Public metadata and vault record preserved."
        }
    }
}
