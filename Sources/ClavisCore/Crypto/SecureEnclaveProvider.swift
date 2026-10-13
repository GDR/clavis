import Foundation
import CryptoKit
import Security
import LocalAuthentication

// MARK: - Secure Enclave Signing Seam

public protocol SecureEnclaveSigningProviding: Sendable {
    var isAvailable: Bool { get }

    /// Generates a new hardware-bound P-256 signing key.
    /// Returns the opaque hardware dataRepresentation and uncompressed ANSI X9.63 public key bytes.
    func generateKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKeyData: Data)

    /// Derives the uncompressed ANSI X9.63 public key bytes from stored dataRepresentation without authentication prompts.
    func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> Data

    /// Signs payload data using the key identified by dataRepresentation under the provided LAContext.
    func signature(for data: Data, dataRepresentation: Data, context: LAContext?) throws -> P256.Signing.ECDSASignature
}

// MARK: - Secure Enclave Key Agreement Seam (Vault)

public protocol SecureEnclaveKeyAgreementProviding: Sendable {
    var isAvailable: Bool { get }

    /// Generates a new hardware-bound P-256 master key for vault envelope encryption.
    /// Returns the opaque hardware dataRepresentation and the public key.
    func generateMasterKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKey: P256.KeyAgreement.PublicKey)

    /// Reconstitutes public key from stored dataRepresentation.
    func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> P256.KeyAgreement.PublicKey

    /// Performs ECDH key agreement with peer ephemeral public key under optional context.
    func sharedSecret(
        dataRepresentation: Data,
        with peerPublicKey: P256.KeyAgreement.PublicKey,
        context: LAContext?
    ) throws -> SharedSecret
}

// MARK: - Production Implementations

public final class ProductionSecureEnclaveSigningProvider: SecureEnclaveSigningProviding, @unchecked Sendable {
    public init() {}
    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func generateKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKeyData: Data) {
        let seKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        return (seKey.dataRepresentation, seKey.publicKey.x963Representation)
    }

    public func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> Data {
        let authContext = context ?? LAContext()
        let seKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation,
            authenticationContext: authContext
        )
        return seKey.publicKey.x963Representation
    }

    public func signature(for data: Data, dataRepresentation: Data, context: LAContext?) throws -> P256.Signing.ECDSASignature {
        let authContext = context ?? LAContext()
        let seKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation,
            authenticationContext: authContext
        )
        return try seKey.signature(for: data)
    }
}

public final class ProductionSecureEnclaveKeyAgreementProvider: SecureEnclaveKeyAgreementProviding, @unchecked Sendable {
    public init() {}
    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func generateMasterKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKey: P256.KeyAgreement.PublicKey) {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        return (seKey.dataRepresentation, seKey.publicKey)
    }

    public func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> P256.KeyAgreement.PublicKey {
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let context {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
        } else {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
        }
        return seKey.publicKey
    }

    public func sharedSecret(
        dataRepresentation: Data,
        with peerPublicKey: P256.KeyAgreement.PublicKey,
        context: LAContext?
    ) throws -> SharedSecret {
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let context {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
        } else {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
        }
        return try seKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }
}

// MARK: - In-Memory Test Implementations

public final class InMemorySecureEnclaveSigningProvider: SecureEnclaveSigningProviding, @unchecked Sendable {
    public var isAvailable: Bool = true
    private let lock = NSLock()
    private var keysByData: [Data: P256.Signing.PrivateKey] = [:]

    public init() {}

    public func generateKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKeyData: Data) {
        lock.lock()
        defer { lock.unlock() }
        let key = P256.Signing.PrivateKey()
        let dataRep = key.rawRepresentation // 32-byte scalar as simulated hardware handle
        keysByData[dataRep] = key
        return (dataRep, key.publicKey.x963Representation)
    }

    public func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        let key: P256.Signing.PrivateKey
        if let cached = keysByData[dataRepresentation] {
            key = cached
        } else {
            key = try P256.Signing.PrivateKey(rawRepresentation: dataRepresentation)
            keysByData[dataRepresentation] = key
        }
        return key.publicKey.x963Representation
    }

    public func signature(for data: Data, dataRepresentation: Data, context: LAContext?) throws -> P256.Signing.ECDSASignature {
        lock.lock()
        defer { lock.unlock() }
        let key: P256.Signing.PrivateKey
        if let cached = keysByData[dataRepresentation] {
            key = cached
        } else {
            key = try P256.Signing.PrivateKey(rawRepresentation: dataRepresentation)
            keysByData[dataRepresentation] = key
        }
        return try key.signature(for: data)
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        keysByData.removeAll()
    }
}

public final class InMemorySecureEnclaveKeyAgreementProvider: SecureEnclaveKeyAgreementProviding, @unchecked Sendable {
    public var isAvailable: Bool = true
    private let lock = NSLock()
    private var keysByData: [Data: P256.KeyAgreement.PrivateKey] = [:]

    public init() {}

    public func generateMasterKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKey: P256.KeyAgreement.PublicKey) {
        lock.lock()
        defer { lock.unlock() }
        let key = P256.KeyAgreement.PrivateKey()
        let dataRep = key.rawRepresentation // 32-byte scalar as simulated hardware handle
        keysByData[dataRep] = key
        return (dataRep, key.publicKey)
    }

    public func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> P256.KeyAgreement.PublicKey {
        lock.lock()
        defer { lock.unlock() }
        let key: P256.KeyAgreement.PrivateKey
        if let cached = keysByData[dataRepresentation] {
            key = cached
        } else {
            key = try P256.KeyAgreement.PrivateKey(rawRepresentation: dataRepresentation)
            keysByData[dataRepresentation] = key
        }
        return key.publicKey
    }

    public func sharedSecret(
        dataRepresentation: Data,
        with peerPublicKey: P256.KeyAgreement.PublicKey,
        context: LAContext?
    ) throws -> SharedSecret {
        lock.lock()
        defer { lock.unlock() }
        let key: P256.KeyAgreement.PrivateKey
        if let cached = keysByData[dataRepresentation] {
            key = cached
        } else {
            key = try P256.KeyAgreement.PrivateKey(rawRepresentation: dataRepresentation)
            keysByData[dataRepresentation] = key
        }
        return try key.sharedSecretFromKeyAgreement(with: peerPublicKey)
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        keysByData.removeAll()
    }
}
