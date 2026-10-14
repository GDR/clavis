import Foundation
import Security
import LocalAuthentication

/// Encapsulates the output of algorithm-specific key generation.
public struct GeneratedKeyPair: Sendable {
    public let keyData: Data
    public let publicKeyBlob: Data

    public init(keyData: Data, publicKeyBlob: Data) {
        self.keyData = keyData
        self.publicKeyBlob = publicKeyBlob
    }
}

/// Strategy protocol abstracting algorithm-specific cryptographic operations,
/// key generation, OpenSSH wire serialization, and verification for KeychainManager.
public protocol KeySigner: Sendable {
    /// The algorithm represented by this signer.
    var algorithm: KeyAlgorithm { get }

    /// The OpenSSH wire key type identifier (e.g. "ecdsa-sha2-nistp256").
    var sshKeyType: String { get }

    /// Generates a hardware-backed key pair, returning the raw/opaque key data to store in Keychain/Vault
    /// and the OpenSSH wire format public key blob.
    func generateKeyPair(
        label: String,
        accessControl: SecAccessControl,
        provider: SecureEnclaveSigningProviding
    ) throws -> GeneratedKeyPair

    /// Derives the OpenSSH wire format public key blob from a stored private key record.
    func derivePublicKeyBlob(
        record: StoredPrivateKeyRecord,
        context: LAContext?,
        provider: SecureEnclaveSigningProviding
    ) throws -> Data

    /// Verifies that the stored private key record matches the public key in SSHKeyInfo.
    /// Throws `PrivateKeyRecordError.publicKeyMismatch` if the derived public key does not match.
    func verifyPublicKey(
        record: StoredPrivateKeyRecord,
        against key: SSHKeyInfo,
        context: LAContext,
        provider: SecureEnclaveSigningProviding
    ) throws

    /// Formats the complete OpenSSH public key line (e.g. "ecdsa-sha2-nistp256 <base64> <label>").
    func formatOpenSSHPublicKey(publicKeyBlob: Data, label: String) -> String

    /// Formats a raw signature into the OpenSSH wire format signature blob.
    func formatSSHSignatureBlob(rawSignature: Data) throws -> Data

    /// Signs challenge data and returns the complete OpenSSH wire format signature blob.
    func signSSH(
        data: Data,
        keyData: Data,
        context: LAContext?,
        provider: SecureEnclaveSigningProviding
    ) throws -> Data
}

public extension KeySigner {
    func formatOpenSSHPublicKey(publicKeyBlob: Data, label: String) -> String {
        let b64 = publicKeyBlob.base64EncodedString()
        return "\(sshKeyType) \(b64) \(label)"
    }

    func verifyPublicKey(
        record: StoredPrivateKeyRecord,
        against key: SSHKeyInfo,
        context: LAContext,
        provider: SecureEnclaveSigningProviding
    ) throws {
        let derivedBlob = try derivePublicKeyBlob(record: record, context: context, provider: provider)
        guard derivedBlob == key.publicKeyBlob else {
            ClavisLogger.log("SECURITY_ALERT", "Public key mismatch for '\(key.label)'! Possible metadata tampering.")
            throw PrivateKeyRecordError.publicKeyMismatch
        }
    }
}
