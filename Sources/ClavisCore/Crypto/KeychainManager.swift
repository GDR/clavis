import Foundation
import Security
import CryptoKit
import LocalAuthentication

public class KeychainManager {
    public static let privateServiceName = "com.clavis.private-record.v2"
    public static let publicServiceName = "com.clavis.ed25519.pub"
    public static let shared = KeychainManager()
    internal static var customSigningProvider: SecureEnclaveSigningProviding? = nil

    private let authenticator: UserAuthenticating
    private let privateKeyStore: PrivateKeyStoring
    private let agentGrantRevoker: (String) throws -> Void
    private let auditRecorder: AuditRecording
    private let instanceSigningProvider: SecureEnclaveSigningProviding?
    private let gitSigningGraceManager: GitSigningGraceManager
    public let signerRegistry: KeySignerRegistry
    #if DEBUG
    public let testContext: TestContext?
    #endif

    public var activeSigningProvider: SecureEnclaveSigningProviding {
        #if DEBUG
        if let instance = instanceSigningProvider {
            return instance
        }
        if let context = TestContextScope.current, let provider = context.signingProvider {
            return provider
        }
        if let context = testContext, let provider = context.signingProvider {
            return provider
        }
        if let custom = Self.customSigningProvider {
            return custom
        }
        if ClavisEnvironment.isTesting {
            return InMemorySecureEnclaveSigningProvider()
        }
        return ProductionSecureEnclaveSigningProvider()
        #else
        return instanceSigningProvider ?? ProductionSecureEnclaveSigningProvider()
        #endif
    }

    private let vaultStore: EncryptedVaultStore

    public init(
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        privateKeyStore: PrivateKeyStoring = KeychainPrivateKeyStore(),
        vaultStore: EncryptedVaultStore = .shared,
        agentGrantRevoker: @escaping (String) throws -> Void = { label in
            try AgentLifecycleManager.shared.invalidateAgentGrant(label: label)
        },
        auditRecorder: AuditRecording = AuditRecorder.shared,
        signingProvider: SecureEnclaveSigningProviding? = nil,
        gitSigningGraceManager: GitSigningGraceManager = .shared,
        signerRegistry: KeySignerRegistry = .shared,
        testContext: TestContext? = nil
    ) {
        self.authenticator = authenticator
        self.privateKeyStore = privateKeyStore
        self.vaultStore = vaultStore
        self.agentGrantRevoker = agentGrantRevoker
        self.auditRecorder = auditRecorder
        self.instanceSigningProvider = signingProvider
        self.gitSigningGraceManager = gitSigningGraceManager
        self.signerRegistry = signerRegistry
        #if DEBUG
        self.testContext = testContext ?? TestContextScope.current
        #endif
    }

    // Generate new Key and save private seed (guarded by Touch ID) and public metadata (unencrypted)
    @discardableResult
    public func generateKey(
        label: String,
        algorithm: String = "ECDSA P-256",
        storageType: KeyStorageType = .secureEnclave,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general,
        accessProfile: KeyAccessProfile? = nil
    ) throws -> SSHKeyInfo {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.generateKey(label: label, algorithm: algorithm, storageType: storageType, biometricPolicy: biometricPolicy, keyPurpose: keyPurpose, accessProfile: accessProfile)
            }
        }
        #endif
        try validateLabel(label)
        try validateGenerationConfiguration(algorithm: algorithm, storageType: storageType)
        let signer = try signerRegistry.signer(forAlgorithmName: algorithm)
        if try fetchKeyInfo(label: label) != nil || privateKeyStore.contains(label: label) {
            throw KeychainManagerError.keyAlreadyExists(label: label)
        }
        _ = try vaultStore.ensureMasterKey()

        guard activeSigningProvider.isAvailable else {
            throw KeychainManagerError.secureEnclaveUnavailable
        }

        let policy = biometricPolicy ?? .userPresence
        let accessControl = try PrivateKeyAccessControl.make(flags: policy.accessControlFlags)
        let keyPair = try signer.generateKeyPair(
            label: label,
            accessControl: accessControl,
            provider: activeSigningProvider
        )

        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: signer.algorithm,
            storageType: storageType,
            biometricPolicy: policy,
            keyPurpose: keyPurpose,
            accessProfile: accessProfile,
            keyData: keyPair.keyData
        )
        defer { record.wipe() }
        var recordData = try record.encode()
        defer { Self.wipeData(&recordData) }
        // The serialized value is an opaque Secure Enclave reference.
        // The hardware key enforces its own biometric policy in SEP; store the
        // metadata record as device-bound Login Keychain data so unprovisioned
        // local builds do not hit errSecMissingEntitlement (-34018).
        try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [])
        do {
            try vaultStore.saveRecord(record)
        } catch {
            ClavisLogger.log("VAULT_WARNING", "Failed to backup private record to shadow vault: \(error.localizedDescription)")
            try? privateKeyStore.remove(label: label)
            throw error
        }

        let blob = keyPair.publicKeyBlob
        let openSSH = signer.formatOpenSSHPublicKey(publicKeyBlob: blob, label: label)
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")

        let keyInfo = SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: openSSH,
            publicKeyBlob: blob,
            fingerprint: fingerprint,
            createdAt: Date(),
            algorithmName: algorithm,
            storage: storageType,
            biometricPolicy: policy,
            keyPurpose: keyPurpose,
            accessProfile: record.accessProfile
        )
        do {
            try PublicKeyStore.saveChecked(keyInfo)
        } catch {
            try? privateKeyStore.remove(label: label)
            vaultStore.removeRecord(label: label)
            throw error
        }
        auditRecorder.record(
            AuditEvent(
                type: .keyCreate,
                result: .allowed,
                keyFingerprint: keyInfo.fingerprint,
                keyKind: record.accessProfile.type == .bot ? .agent : .personal,
                sensitive: AuditSensitive(keyLabel: keyInfo.label, processChain: [], host: nil)
            )
        )
        return keyInfo
    }

    private func validateGenerationConfiguration(algorithm: String, storageType: KeyStorageType) throws {
        guard storageType == .secureEnclave else {
            throw KeychainManagerError.unsupportedConfiguration(
                algorithm: algorithm,
                storageType: storageType.rawValue
            )
        }
        _ = try signerRegistry.signer(forAlgorithmName: algorithm)
    }

    // List all public key metadata WITHOUT triggering Touch ID or Keychain prompts
    public func listKeys() throws -> [SSHKeyInfo] {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.listKeys()
            }
        }
        #endif
        ClavisLogger.log("KEY_LIST", "Fetching key list from local store...")
        return PublicKeyStore.loadAll()
    }

    public func fetchKeyInfo(label: String) throws -> SSHKeyInfo? {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.fetchKeyInfo(label: label)
            }
        }
        #endif
        return PublicKeyStore.loadAll().first(where: { $0.label == label })
    }

    // Delete key (both private seed and public metadata)
    public func deleteKey(label: String) throws {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.deleteKey(label: label)
            }
        }
        #endif
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
            vaultStore.removeRecord(label: label)
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
    public func derivePublicKeyBlob(
        record: StoredPrivateKeyRecord,
        context: LAContext? = nil
    ) throws -> Data {
        let signer = try signerRegistry.signer(for: record.algorithm)
        return try signer.derivePublicKeyBlob(record: record, context: context, provider: activeSigningProvider)
    }

    public static func derivePublicKeyBlob(
        record: StoredPrivateKeyRecord,
        context: LAContext? = nil,
        provider: SecureEnclaveSigningProviding? = nil
    ) throws -> Data {
        #if DEBUG
        let activeProvider: SecureEnclaveSigningProviding = provider
            ?? customSigningProvider
            ?? (TestContextScope.current?.signingProvider)
            ?? (ClavisEnvironment.isTesting ? InMemorySecureEnclaveSigningProvider() : ProductionSecureEnclaveSigningProvider())
        #else
        let activeProvider = provider ?? ProductionSecureEnclaveSigningProvider()
        #endif
        let signer = try KeySignerRegistry.shared.signer(for: record.algorithm)
        return try signer.derivePublicKeyBlob(record: record, context: context, provider: activeProvider)
    }

    private func validateAuthenticatedRecord(
        _ record: StoredPrivateKeyRecord,
        against key: SSHKeyInfo,
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

        guard record.accessProfile == key.effectiveAccessProfile else {
            throw KeyAccessError.profileMismatch
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

        let signer = try signerRegistry.signer(for: record.algorithm)
        try signer.verifyPublicKey(record: record, against: key, context: context, provider: activeSigningProvider)
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
            guard let derived = try? derivePublicKeyBlob(record: record, context: context) else {
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
            vaultRecord = try vaultStore.loadRecord(label: label, context: context)
        } catch {
            ClavisLogger.log("KEY_DELETE", "Could not read the vault record for '\(label)' (\(error.localizedDescription)). Preserving it.")
            return false
        }
        guard var vaultRecord else {
            return true
        }
        defer { vaultRecord.wipe() }
        guard vaultRecord.label == label,
              let keychainBlob = try? derivePublicKeyBlob(record: record, context: context),
              let vaultBlob = try? derivePublicKeyBlob(record: vaultRecord, context: context) else {
            return false
        }
        return keychainBlob == vaultBlob
    }

    // Loads an authenticated record from Keychain.
    private func loadAuthenticatedRecord(
        label: String,
        context: LAContext,
        prompt: String,
        expectedKeyInfo: SSHKeyInfo?
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

        var record: StoredPrivateKeyRecord
        do {
            record = try StoredPrivateKeyRecord.decode(from: rawData)
        } catch {
            ClavisLogger.log(
                "SECURITY_ALERT",
                "Keychain record corrupted for '\(label)': \(error.localizedDescription). Attempting restore from encrypted shadow vault."
            )
            return try restoreRecordFromVault(
                label: label,
                context: context,
                expectedKeyInfo: expectedKeyInfo,
                logMessage: "Restored corrupted Keychain record for '\(label)' from encrypted shadow vault."
            )
        }

        if let expectedKeyInfo {
            do {
                try validateAuthenticatedRecord(record, against: expectedKeyInfo, context: context)
                return record
            } catch let validationError {
                record.wipe()
                if let keyPurposeError = validationError as? KeyPurposeError {
                    throw keyPurposeError
                }
                // Policy disagreement is not record corruption. A stale backup must
                // never restore broader capabilities to satisfy the public cache.
                if let accessError = validationError as? KeyAccessError {
                    throw accessError
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
    }

    private func restoreRecordFromVault(
        label: String,
        context: LAContext,
        expectedKeyInfo: SSHKeyInfo?,
        logMessage: String
    ) throws -> StoredPrivateKeyRecord {
        guard var restoredRecord = try vaultStore.loadRecord(label: label, context: context) else {
            throw KeychainManagerError.privateKeyNotFound(label: label)
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
                try privateKeyStore.save(label: label, data: bytes, accessControlFlags: [])
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
        try vaultStore.repairMasterKeyPin(replacePin: replacePin, context: context)
    }

    private static func wipeData(_ data: inout Data) {
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { SecureMemory.zero(base, byteCount: raw.count) }
        }
        data.removeAll(keepingCapacity: false)
    }

    private func withVerifiedPrivateKeyRecord<T>(
        for key: SSHKeyInfo,
        prompt: String,
        existingContext: LAContext? = nil,
        invalidateContextOnMismatch: Bool = true,
        auditOnAuthFailure: Bool = false,
        auditKeyKind: AuditKeyKind? = nil,
        auditSessionID: String? = nil,
        _ body: (LAContext, StoredPrivateKeyRecord) throws -> T
    ) throws -> T {
        let laPolicy = key.effectiveBiometricPolicy.laPolicy
        let authContext: LAContext
        if let existingContext {
            authContext = existingContext
        } else {
            do {
                authContext = try authenticator.authenticate(reason: prompt, policy: laPolicy)
            } catch {
                if auditOnAuthFailure {
                    auditRecorder.record(
                        AuditEvent(
                            type: .keyKindChange,
                            result: .denied,
                            reason: .authenticationFailed,
                            keyFingerprint: key.fingerprint,
                            keyKind: auditKeyKind,
                            sessionID: auditSessionID,
                            sensitive: AuditSensitive(keyLabel: key.label, processChain: [], host: nil)
                        )
                    )
                }
                throw error
            }
        }

        var record: StoredPrivateKeyRecord
        do {
            record = try loadAuthenticatedRecord(
                label: key.label,
                context: authContext,
                prompt: prompt,
                expectedKeyInfo: key
            )
        } catch {
            // loadAuthenticatedRecord rejects a public-index policy that is weaker than the
            // record. Invalidate that context here so it cannot be reused for a grant.
            if invalidateContextOnMismatch {
                if laPolicy != .deviceOwnerAuthenticationWithBiometrics,
                   case PrivateKeyRecordError.metadataMismatch(let field, _, _) = error,
                   field == "biometricPolicy" {
                    authContext.invalidate()
                }
                if error is KeyPurposeError {
                    authContext.invalidate()
                }
            }
            throw error
        }
        defer { record.wipe() }

        let recordPolicy = record.biometricPolicy ?? .userPresence
        if invalidateContextOnMismatch && recordPolicy == .biometryCurrentSet && laPolicy != .deviceOwnerAuthenticationWithBiometrics {
            authContext.invalidate()
            ClavisLogger.log("SECURITY_ALERT", "Refusing operation for '\(key.label)': record requires biometryCurrentSet but the authentication context was not evaluated with biometrics.")
            throw PrivateKeyRecordError.metadataMismatch(
                field: "biometricPolicy",
                expected: BiometricPolicy.userPresence.rawValue,
                actual: recordPolicy.rawValue
            )
        }

        try validateAuthenticatedRecord(record, against: key, context: authContext)
        return try body(authContext, record)
    }

    private func encodeP256SSHSignature(_ rawSignature: Data) throws -> Data {
        try Self.encodeP256SSHSignature(rawSignature)
    }

    private static func encodeP256SSHSignature(_ rawSignature: Data) throws -> Data {
        try ECDSAP256KeySigner.shared.formatSSHSignatureBlob(rawSignature: rawSignature)
    }

    // Sign challenge data for SSH Agent returning wire format signature blob
    public func signSSH(
        key: SSHKeyInfo,
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
        key: SSHKeyInfo,
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
        let operation: KeyOperation = data.starts(with: SSHSIGPayload.magic) ? .signature : .ssh
        if key.purpose == .gitSigningOnly && !isGitSigningRequest {
            throw PrivateKeyRecordError.purposeNotAllowed(
                purpose: key.purpose.rawValue,
                operation: "non-Git SSH signing"
            )
        }

        try key.effectiveAccessProfile.require(operation)
        if existingContext == nil {
            ClavisLogger.promptDebug("clavis-code", "KeychainManager: prompting for SSH signature '\(key.label)' (storage: \(key.storageType.rawValue), policy: \(key.biometricPolicy?.rawValue ?? "default")): \"\(prompt)\"")
        }

        return try withVerifiedPrivateKeyRecord(
            for: key,
            prompt: prompt,
            existingContext: existingContext,
            invalidateContextOnMismatch: false,
            auditOnAuthFailure: false
        ) { context, record in
            try record.accessProfile.require(operation)
            guard allowedPurposes.contains(record.purpose) else {
                throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
            }
            if record.purpose == .gitSigningOnly && !isGitSigningRequest {
                throw PrivateKeyRecordError.purposeNotAllowed(
                    purpose: record.purpose.rawValue,
                    operation: "non-Git SSH signing"
                )
            }
            guard record.storageType == .secureEnclave else {
                throw PrivateKeyRecordError.storageMismatch(expected: KeyStorageType.secureEnclave.rawValue, actual: record.storageType.rawValue)
            }
            let signer = try self.signerRegistry.signer(for: record.algorithm)
            return try signer.signSSH(data: data, keyData: record.keyData, context: context, provider: self.activeSigningProvider)
        }
    }

    /// Authorizes a 5-minute Git signing grant via Touch ID, returning an active grant.
    @discardableResult
    internal func authorizeGitSigningGrant(
        key: SSHKeyInfo,
        prompt: String,
        clientIdentity: String,
        duration: TimeInterval = 300.0,
        maxOperations: Int = 200,
        approvedProcess: GitApprovedProcess? = nil
    ) throws -> GitSigningGrant {
        guard key.purpose != .agent else {
            throw KeyPurposeError.notAllowedOnThisPath(.agent)
        }

        return try withVerifiedPrivateKeyRecord(
            for: key,
            prompt: prompt,
            auditOnAuthFailure: false
        ) { context, record in
            guard record.purpose != .agent else {
                context.invalidate()
                throw KeyPurposeError.notAllowedOnThisPath(.agent)
            }

            context.interactionNotAllowed = true

            guard record.storageType == .secureEnclave else {
                context.invalidate()
                throw PrivateKeyRecordError.storageMismatch(expected: KeyStorageType.secureEnclave.rawValue, actual: record.storageType.rawValue)
            }

            let provider = self.activeSigningProvider
            let keyData = record.keyData
            let signer = try self.signerRegistry.signer(for: record.algorithm)
            let hardwareSigner: @Sendable (Data) throws -> Data = { dataToSign in
                try signer.signSSH(data: dataToSign, keyData: keyData, context: context, provider: provider)
            }
            return self.gitSigningGraceManager.recordGrant(
                keyLabel: key.label,
                clientIdentity: clientIdentity,
                duration: duration,
                maxOperations: maxOperations,
                context: context,
                approvedProcess: approvedProcess,
                hardwareSigner: hardwareSigner
            )
        }
    }

    /// Authorizes an agent session via Touch ID, returning an active grant.
    internal func authorizeAgentSession(
        key: SSHKeyInfo,
        prompt: String
    ) throws -> AgentSessionGrant {
        guard key.purpose == .agent else {
            throw KeyPurposeError.notAllowedOnThisPath(key.purpose)
        }

        ClavisLogger.promptDebug("clavis-code", "KeychainManager: prompting for agent session authorization '\(key.label)': \"\(prompt)\"")
        return try withVerifiedPrivateKeyRecord(
            for: key,
            prompt: prompt,
            auditOnAuthFailure: false
        ) { context, record in
            guard record.purpose == .agent else {
                context.invalidate()
                throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
            }

            context.interactionNotAllowed = true

            guard record.storageType == .secureEnclave else {
                context.invalidate()
                throw KeyPurposeError.notAllowedOnThisPath(record.purpose)
            }

            let provider = self.activeSigningProvider
            let keyData = record.keyData
            let signer = try self.signerRegistry.signer(for: record.algorithm)
            let hardwareSigner: @Sendable (Data) throws -> Data = { dataToSign in
                try signer.signSSH(data: dataToSign, keyData: keyData, context: context, provider: provider)
            }
            return AgentSessionGrant(
                key: key,
                context: context,
                hardwareSigner: hardwareSigner
            )
        }
    }

    public static func encodeSSHMPint(_ bytes: Data) -> Data {
        Data.encodeSSHMPint(bytes)
    }

    public static func formatECDSASignatureBlob(_ ecdsaSig: P256.Signing.ECDSASignature) -> Data {
        (try? ECDSAP256KeySigner.shared.formatSSHSignatureBlob(rawSignature: ecdsaSig.rawRepresentation)) ?? Data()
    }

    // Lock a key immediately
    public func lockKey(label: String) throws {
        try revokeKeyCapabilities(label: label)
        ClavisLogger.log("KEY_LOCK", "Key '\(label)' locked.")
    }

    private func revokeKeyCapabilities(label: String) throws {
        gitSigningGraceManager.invalidate(keyLabel: label)
        try agentGrantRevoker(label)
    }

    /// Change key purpose between general and agent. Requires user presence authentication.
    public func changeKind(label: String, to newPurpose: KeyPurpose, prompt: String? = nil) throws {
        guard let key = try fetchKeyInfo(label: label) else {
            throw KeychainManagerError.keyNotFound(label: label)
        }

        let currentPurpose = key.purpose
        guard (currentPurpose == .general && newPurpose == .agent) || (currentPurpose == .agent && newPurpose == .general) else {
            throw KeyPurposeError.kindChangeNotAllowed
        }

        let reason = prompt ?? "Touch ID to change key kind for '\(label)'"
        try withVerifiedPrivateKeyRecord(
            for: key,
            prompt: reason,
            auditOnAuthFailure: true,
            auditKeyKind: newPurpose.auditKind
        ) { _, record in
            guard (record.purpose == .general && newPurpose == .agent) || (record.purpose == .agent && newPurpose == .general) else {
                throw KeyPurposeError.kindChangeNotAllowed
            }

            try persistAccessProfile(record.accessProfile.changingType(to: newPurpose == .agent ? .bot : .personal),
                                     purpose: newPurpose, key: key, record: record)

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
    }

    private func persistAccessProfile(_ profile: KeyAccessProfile, purpose newPurpose: KeyPurpose,
                                      key: SSHKeyInfo, record: StoredPrivateKeyRecord) throws {
        let label = key.label
        try revokeKeyCapabilities(label: label)
        var updatedRecord = StoredPrivateKeyRecord(
            label: record.label,
            algorithm: record.algorithm,
            storageType: record.storageType,
            biometricPolicy: record.biometricPolicy,
            keyPurpose: newPurpose,
            accessProfile: profile,
            keyData: record.keyData,
            createdAt: record.createdAt
        )
        defer { updatedRecord.wipe() }

        let hasVaultRecord = vaultStore.hasRecord(label: label)
        if hasVaultRecord {
            try vaultStore.saveRecord(updatedRecord)
        }

        var recordData = try updatedRecord.encode()
        defer { Self.wipeData(&recordData) }

        do {
            try privateKeyStore.save(label: label, data: recordData, accessControlFlags: [])
        } catch {
            if hasVaultRecord {
                try? vaultStore.saveRecord(record)
            }
            throw error
        }

        let updatedKeyInfo = SSHKeyInfo(
            label: key.label,
            publicKeyOpenSSH: key.publicKeyOpenSSH,
            publicKeyBlob: key.publicKeyBlob,
            fingerprint: key.fingerprint,
            createdAt: key.createdAt,
            algorithmName: key.algorithmName,
            storage: key.storageType,
            biometricPolicy: key.biometricPolicy,
            keyPurpose: newPurpose,
            accessProfile: updatedRecord.accessProfile
        )

        do {
            try PublicKeyStore.saveChecked(updatedKeyInfo)
        } catch {
            if var originalRecordData = try? record.encode() {
                defer { Self.wipeData(&originalRecordData) }
                try? privateKeyStore.save(label: label, data: originalRecordData, accessControlFlags: [])
            }
            if hasVaultRecord {
                try? vaultStore.saveRecord(record)
            }
            throw error
        }

    }

    /// A type-only change never changes operation capabilities or legacy Git restrictions.
    /// Authentication cannot be supplied by the caller or reused from a previous unlock.
    public func changeAccessProfile(label: String, type: KeyType? = nil,
                                    capabilities: KeyCapabilities? = nil) throws {
        guard let key = try fetchKeyInfo(label: label) else {
            throw KeychainManagerError.keyNotFound(label: label)
        }
        let profile = KeyAccessProfile(type: type ?? key.effectiveAccessProfile.type,
            capabilities: capabilities ?? key.effectiveAccessProfile.capabilities)
        guard profile != key.effectiveAccessProfile else { return }
        try withVerifiedPrivateKeyRecord(for: key,
            prompt: "Change access policy for '\(label)'",
            auditOnAuthFailure: true, auditKeyKind: profile.type == .bot ? .agent : .personal
        ) { context, record in
            defer { context.invalidate() }
            // Retain Git-only restrictions unless the user explicitly enables SSH.
            let purpose: KeyPurpose = record.purpose == .gitSigningOnly && !profile.capabilities.ssh
                ? .gitSigningOnly : .general
            try persistAccessProfile(profile, purpose: purpose, key: key, record: record)
            auditRecorder.record(AuditEvent(type: .keyKindChange, result: .allowed,
                keyFingerprint: key.fingerprint, keyKind: profile.type == .bot ? .agent : .personal,
                sensitive: .init(keyLabel: label, processChain: [], host: nil)))
        }
    }

    /// Rename an existing key label across the private key store, shadow vault, and public key store.
    @discardableResult
    public func renameKey(from oldLabel: String, to newLabel: String) throws -> SSHKeyInfo {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.renameKey(from: oldLabel, to: newLabel)
            }
        }
        #endif

        let trimmedNew = newLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        try validateLabel(trimmedNew)

        guard let key = try fetchKeyInfo(label: oldLabel) else {
            throw KeychainManagerError.keyNotFound(label: oldLabel)
        }

        if trimmedNew == oldLabel {
            return key
        }

        if try fetchKeyInfo(label: trimmedNew) != nil
            || privateKeyStore.contains(label: trimmedNew)
            || vaultStore.hasRecord(label: trimmedNew) {
            throw KeychainManagerError.keyAlreadyExists(label: trimmedNew)
        }

        let nonInteractiveContext = LAContext()
        nonInteractiveContext.interactionNotAllowed = true
        var rawRecordData: Data? = try? privateKeyStore.load(label: oldLabel, context: nonInteractiveContext, prompt: "")
        if rawRecordData == nil {
            rawRecordData = try? privateKeyStore.load(label: oldLabel, context: LAContext(), prompt: "")
        }

        var loadedRecord: StoredPrivateKeyRecord? = nil
        if let rawRecordData {
            loadedRecord = try? StoredPrivateKeyRecord.decode(from: rawRecordData)
        }
        if loadedRecord == nil, vaultStore.hasRecord(label: oldLabel) {
            loadedRecord = try? vaultStore.loadRecord(label: oldLabel, context: nil)
        }

        guard var record = loadedRecord else {
            throw KeychainManagerError.privateKeyNotFound(label: oldLabel)
        }
        defer { record.wipe() }

        var updatedRecord = StoredPrivateKeyRecord(
            version: record.version,
            label: trimmedNew,
            algorithm: record.algorithm,
            storageType: record.storageType,
            biometricPolicy: record.biometricPolicy,
            keyPurpose: record.keyPurpose,
            accessProfile: record.accessProfile,
            keyData: record.keyData,
            createdAt: record.createdAt
        )
        defer { updatedRecord.wipe() }

        var recordData = try updatedRecord.encode()
        defer { Self.wipeData(&recordData) }

        let hadVaultRecord = vaultStore.hasRecord(label: oldLabel)
        try privateKeyStore.save(label: trimmedNew, data: recordData, accessControlFlags: [])
        do {
            if hadVaultRecord {
                try vaultStore.saveRecord(updatedRecord)
            }
        } catch {
            try? privateKeyStore.remove(label: trimmedNew, context: nonInteractiveContext, prompt: "")
            throw error
        }

        let openSSH: String
        if let signer = try? signerRegistry.signer(forAlgorithmName: key.algorithm) {
            openSSH = signer.formatOpenSSHPublicKey(publicKeyBlob: key.publicKeyBlob, label: trimmedNew)
        } else {
            let parts = key.publicKeyOpenSSH.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            if parts.count >= 2 {
                openSSH = "\(parts[0]) \(parts[1]) \(trimmedNew)"
            } else {
                openSSH = key.publicKeyOpenSSH
            }
        }

        let updatedKeyInfo = SSHKeyInfo(
            label: trimmedNew,
            publicKeyOpenSSH: openSSH,
            publicKeyBlob: key.publicKeyBlob,
            fingerprint: key.fingerprint,
            createdAt: key.createdAt,
            algorithmName: key.algorithmName,
            storage: key.storage,
            biometricPolicy: key.biometricPolicy,
            keyPurpose: key.keyPurpose,
            accessProfile: key.accessProfile
        )

        do {
            try PublicKeyStore.saveChecked(updatedKeyInfo)
            try PublicKeyStore.removeChecked(label: oldLabel)
        } catch {
            try? privateKeyStore.remove(label: trimmedNew, context: nonInteractiveContext, prompt: "")
            if hadVaultRecord {
                vaultStore.removeRecord(label: trimmedNew)
            }
            throw error
        }

        try? privateKeyStore.remove(label: oldLabel, context: nonInteractiveContext, prompt: "")
        if hadVaultRecord {
            vaultStore.removeRecord(label: oldLabel)
        }
        try? revokeKeyCapabilities(label: oldLabel)
        ClavisLogger.log("KEY_RENAME", "Renamed key '\(oldLabel)' to '\(trimmedNew)'.")
        return updatedKeyInfo
    }

    public func syncVault(repair: Bool = false) throws -> VaultSyncReport {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return try TestContextScope.$current.withValue(context) {
                try self.syncVault(repair: repair)
            }
        }
        #endif

        let publicKeys = try listKeys()
        let publicLabels = Set(publicKeys.map { $0.label })
        let privateLabels = Set(try privateKeyStore.allLabels())

        var detected: [VaultAnomaly] = []
        var repaired: [VaultAnomaly] = []

        // 1. Detect orphaned public cache items (public key exists, but no private key in privateKeyStore or vaultStore)
        for pubKey in publicKeys {
            let label = pubKey.label
            let hasPrivate = privateKeyStore.contains(label: label) || vaultStore.hasRecord(label: label)
            if !hasPrivate {
                detected.append(.orphanedPublicCache(label: label))
                if repair {
                    do {
                        try PublicKeyStore.removeChecked(label: label)
                        repaired.append(.orphanedPublicCache(label: label))
                    } catch {
                        ClavisLogger.log("VAULT_SYNC", "Failed to remove orphaned public key '\(label)': \(error.localizedDescription)")
                    }
                }
            }
        }

        // 2. Detect missing public cache items (private key exists, but no public key in cache)
        for privLabel in privateLabels.sorted() {
            if !publicLabels.contains(privLabel) {
                detected.append(.missingPublicCache(label: privLabel))
                if repair {
                    do {
                        var rawRecordData: Data? = nil
                        let emptyContext = LAContext()
                        emptyContext.interactionNotAllowed = true
                        do {
                            rawRecordData = try privateKeyStore.load(label: privLabel, context: emptyContext, prompt: "")
                        } catch {
                            rawRecordData = try? privateKeyStore.load(label: privLabel, context: LAContext(), prompt: "")
                        }

                        var record: StoredPrivateKeyRecord? = nil
                        if let rawRecordData {
                            record = try? StoredPrivateKeyRecord.decode(from: rawRecordData)
                        }
                        if record == nil, vaultStore.hasRecord(label: privLabel) {
                            record = try? vaultStore.loadRecord(label: privLabel, context: nil)
                        }

                        if var rec = record {
                            defer { rec.wipe() }
                            let signer = try signerRegistry.signer(for: rec.algorithm)
                            let pubBlob = try signer.derivePublicKeyBlob(record: rec, context: nil, provider: activeSigningProvider)
                            let openSSH = signer.formatOpenSSHPublicKey(publicKeyBlob: pubBlob, label: privLabel)
                            let fingerprint = "SHA256:" + Data(SHA256.hash(data: pubBlob)).base64EncodedString().replacingOccurrences(of: "=", with: "")

                            let restoredInfo = SSHKeyInfo(
                                label: privLabel,
                                publicKeyOpenSSH: openSSH,
                                publicKeyBlob: pubBlob,
                                fingerprint: fingerprint,
                                createdAt: rec.createdAt,
                                algorithmName: rec.algorithm.rawValue,
                                storage: rec.storageType,
                                biometricPolicy: rec.biometricPolicy ?? .userPresence,
                                keyPurpose: rec.keyPurpose,
                                accessProfile: rec.accessProfile
                            )
                            try PublicKeyStore.saveChecked(restoredInfo)
                            repaired.append(.missingPublicCache(label: privLabel))
                        }
                    } catch {
                        ClavisLogger.log("VAULT_SYNC", "Failed to repair missing public key for '\(privLabel)': \(error.localizedDescription)")
                    }
                }
            }
        }

        if repair {
            PublicKeyStore.invalidateCache()
        }

        return VaultSyncReport(detectedAnomalies: detected, repairedAnomalies: repaired)
    }

    private func validateLabel(_ label: String) throws {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasControlCharacters = label.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        guard !label.isEmpty,
              label == trimmed,
              label.utf8.count <= 128,
              !hasControlCharacters else {
            throw KeychainManagerError.invalidLabel
        }
    }
}

public enum KeychainManagerError: LocalizedError, Equatable {
    case keyAlreadyExists(label: String)
    case secureEnclaveUnavailable
    case unsupportedConfiguration(algorithm: String, storageType: String)
    case privateKeyNotFound(label: String)
    case keyNotFound(label: String)
    case invalidLabel
    case invalidSignatureLength(Int)

    public var errorDescription: String? {
        switch self {
        case .keyAlreadyExists(let label):
            return "Key with label '\(label)' already exists. Delete it first before generating a new key with this label."
        case .secureEnclaveUnavailable:
            return "Apple Secure Enclave is not available on this device."
        case .unsupportedConfiguration(let algorithm, let storageType):
            return "Unsupported key algorithm or storage combination: \(algorithm) / \(storageType)."
        case .privateKeyNotFound(let label):
            return "Private key not found for '\(label)'"
        case .keyNotFound(let label):
            return "Key with label '\(label)' not found."
        case .invalidLabel:
            return "Key label must be 1-128 bytes and contain no leading, trailing, or control characters."
        case .invalidSignatureLength(let count):
            return "Invalid P-256 signature length: expected 64 bytes, got \(count)."
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

public enum VaultAnomaly: Equatable, Hashable, Sendable {
    case missingPublicCache(label: String)
    case orphanedPublicCache(label: String)

    public var label: String {
        switch self {
        case .missingPublicCache(let label): return label
        case .orphanedPublicCache(let label): return label
        }
    }
}

public struct VaultSyncReport: Equatable, Sendable {
    public let missingPublicCache: [String]
    public let orphanedPublicCache: [String]
    public let repairedCount: Int
    public let detectedAnomalies: [VaultAnomaly]
    public let repairedAnomalies: [VaultAnomaly]

    public var isDesynchronized: Bool {
        !missingPublicCache.isEmpty || !orphanedPublicCache.isEmpty
    }

    public init(
        missingPublicCache: [String] = [],
        orphanedPublicCache: [String] = [],
        repairedCount: Int = 0,
        detectedAnomalies: [VaultAnomaly]? = nil,
        repairedAnomalies: [VaultAnomaly] = []
    ) {
        self.missingPublicCache = missingPublicCache
        self.orphanedPublicCache = orphanedPublicCache
        self.repairedCount = repairedCount
        if let detectedAnomalies {
            self.detectedAnomalies = detectedAnomalies
        } else {
            self.detectedAnomalies = missingPublicCache.map { .missingPublicCache(label: $0) }
                + orphanedPublicCache.map { .orphanedPublicCache(label: $0) }
        }
        self.repairedAnomalies = repairedAnomalies
    }

    public init(detectedAnomalies: [VaultAnomaly], repairedAnomalies: [VaultAnomaly] = []) {
        var missing: [String] = []
        var orphaned: [String] = []
        for anomaly in detectedAnomalies {
            switch anomaly {
            case .missingPublicCache(let label):
                missing.append(label)
            case .orphanedPublicCache(let label):
                orphaned.append(label)
            }
        }
        self.missingPublicCache = missing
        self.orphanedPublicCache = orphaned
        self.repairedCount = repairedAnomalies.count
        self.detectedAnomalies = detectedAnomalies
        self.repairedAnomalies = repairedAnomalies
    }
}
