import Foundation

/// Thread-safe registry maintaining KeySigner strategies indexed by KeyAlgorithm.
public final class KeySignerRegistry: @unchecked Sendable {
    public static let shared = KeySignerRegistry()

    private let lock = NSLock()
    private var signers: [KeyAlgorithm: KeySigner]

    public init(signers: [KeyAlgorithm: KeySigner] = [.ecdsaP256: ECDSAP256KeySigner.shared]) {
        self.signers = signers
    }

    /// Resolves the KeySigner strategy for a given KeyAlgorithm enum case.
    public func signer(for algorithm: KeyAlgorithm) throws -> KeySigner {
        lock.lock()
        defer { lock.unlock() }
        guard let signer = signers[algorithm] else {
            throw KeychainManagerError.unsupportedConfiguration(
                algorithm: algorithm.rawValue,
                storageType: KeyStorageType.secureEnclave.rawValue
            )
        }
        return signer
    }

    /// Resolves the KeySigner strategy by algorithm name string (e.g. "ECDSA P-256").
    public func signer(forAlgorithmName name: String) throws -> KeySigner {
        guard let algo = KeyAlgorithm(rawValue: name) ?? (name == "ECDSA P-256" ? .ecdsaP256 : nil) else {
            throw KeychainManagerError.unsupportedConfiguration(
                algorithm: name,
                storageType: KeyStorageType.secureEnclave.rawValue
            )
        }
        return try signer(for: algo)
    }

    /// Registers a custom or mock KeySigner strategy.
    public func register(_ signer: KeySigner) {
        lock.lock()
        defer { lock.unlock() }
        signers[signer.algorithm] = signer
    }

    /// Resets the registered signers back to default configuration.
    public func resetToDefaults() {
        lock.lock()
        defer { lock.unlock() }
        signers = [.ecdsaP256: ECDSAP256KeySigner.shared]
    }

    /// Returns the list of currently registered algorithms.
    public var registeredAlgorithms: [KeyAlgorithm] {
        lock.lock()
        defer { lock.unlock() }
        return Array(signers.keys)
    }
}
