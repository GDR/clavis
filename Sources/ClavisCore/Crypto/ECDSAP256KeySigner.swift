import Foundation
import Security
import LocalAuthentication
import CryptoKit

/// ECDSA NIST P-256 implementation of KeySigner.
public final class ECDSAP256KeySigner: KeySigner, @unchecked Sendable {
    public static let shared = ECDSAP256KeySigner()

    public var algorithm: KeyAlgorithm { .ecdsaP256 }
    public let sshKeyType: String = "ecdsa-sha2-nistp256"
    public let curveIdentifier: String = "nistp256"

    public init() {}

    public func generateKeyPair(
        label: String,
        accessControl: SecAccessControl,
        provider: SecureEnclaveSigningProviding
    ) throws -> GeneratedKeyPair {
        let (dataRepresentation, pubKeyData) = try provider.generateKey(accessControl: accessControl)
        let blob = formatPublicKeyBlob(rawPublicKeyData: pubKeyData)
        return GeneratedKeyPair(keyData: dataRepresentation, publicKeyBlob: blob)
    }

    public func formatPublicKeyBlob(rawPublicKeyData: Data) -> Data {
        var blob = Data()
        blob.appendWireString(sshKeyType)
        blob.appendWireString(curveIdentifier)
        blob.appendWireData(rawPublicKeyData)
        return blob
    }

    public func derivePublicKeyBlob(
        record: StoredPrivateKeyRecord,
        context: LAContext?,
        provider: SecureEnclaveSigningProviding
    ) throws -> Data {
        guard record.algorithm == .ecdsaP256 && record.storageType == .secureEnclave else {
            throw PrivateKeyRecordError.corruptedRecord("Unsupported key algorithm or storage type")
        }
        let pubKeyData = try provider.derivePublicKey(dataRepresentation: record.keyData, context: context)
        return formatPublicKeyBlob(rawPublicKeyData: pubKeyData)
    }

    public func formatSSHSignatureBlob(rawSignature: Data) throws -> Data {
        guard rawSignature.count == 64 else {
            throw KeychainManagerError.invalidSignatureLength(rawSignature.count)
        }
        let r = Data(rawSignature.prefix(32))
        let s = Data(rawSignature.suffix(32))

        var innerBlob = Data()
        innerBlob.append(Data.encodeSSHMPint(r))
        innerBlob.append(Data.encodeSSHMPint(s))

        var sigBlob = Data()
        sigBlob.appendWireString(sshKeyType)
        sigBlob.appendWireData(innerBlob)
        return sigBlob
    }

    public func signSSH(
        data: Data,
        keyData: Data,
        context: LAContext?,
        provider: SecureEnclaveSigningProviding
    ) throws -> Data {
        let ecdsaSig = try provider.signature(for: data, dataRepresentation: keyData, context: context)
        return try formatSSHSignatureBlob(rawSignature: ecdsaSig.rawRepresentation)
    }
}
