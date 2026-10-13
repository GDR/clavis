import Foundation
import LocalAuthentication
import CryptoKit
import Security

public enum AgentSessionGrantError: Error, Equatable {
    case grantInvalidated
}

public final class AgentSessionGrant: @unchecked Sendable {
    private let lock = NSLock()
    private let key: Ed25519KeyInfo?
    private let context: LAContext?
    private var isInvalidated = false
    internal private(set) var secureBuffer: SecureBuffer?
    private var hardwareSigner: (@Sendable (Data) throws -> Data)?
    private let algorithm: KeyAlgorithm?

    public var isBufferWiped: Bool {
        lock.lock()
        defer { lock.unlock() }
        if let secureBuffer {
            return secureBuffer.isWiped
        }
        return true
    }

    public convenience init(key: Ed25519KeyInfo, context: LAContext) {
        self.init(key: key, context: context, secureBuffer: nil, hardwareSigner: nil)
    }

    internal init(
        key: Ed25519KeyInfo,
        context: LAContext,
        secureBuffer: SecureBuffer? = nil,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil
    ) {
        self.key = key
        self.context = context
        self.secureBuffer = secureBuffer
        self.hardwareSigner = hardwareSigner
        self.algorithm = KeyAlgorithm(rawValue: key.algorithm) ?? (key.algorithm.contains("P-256") ? .ecdsaP256 : .ed25519)
    }

    internal init() {
        self.key = nil
        self.context = nil
        self.secureBuffer = nil
        self.hardwareSigner = nil
        self.algorithm = nil
    }

    public func sign(_ data: Data, using keyManager: KeychainManager? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard !isInvalidated, let key = key else {
            throw AgentSessionGrantError.grantInvalidated
        }

        if let hardwareSigner {
            return try hardwareSigner(data)
        }

        if let buffer = secureBuffer {
            guard !buffer.isWiped else {
                throw AgentSessionGrantError.grantInvalidated
            }
            switch algorithm ?? .ed25519 {
            case .ed25519:
                guard let sig = try buffer.withUnsafeBytes({ raw -> Data in
                    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
                    return try privateKey.signature(for: data)
                }) else {
                    throw AgentSessionGrantError.grantInvalidated
                }
                var sigBlob = Data()
                sigBlob.appendWireString("ssh-ed25519")
                sigBlob.appendWireData(sig)
                return sigBlob

            case .ecdsaP256:
                guard let ecdsaSig = try buffer.withUnsafeBytes({ raw -> P256.Signing.ECDSASignature in
                    let privateKey = try P256.Signing.PrivateKey(rawRepresentation: raw)
                    return try privateKey.signature(for: data)
                }) else {
                    throw AgentSessionGrantError.grantInvalidated
                }
                return KeychainManager.formatECDSASignatureBlob(ecdsaSig)
            }
        }

        guard let context = context, let keyManager = keyManager else {
            throw AgentSessionGrantError.grantInvalidated
        }

        return try keyManager.signSSH(
            key: key,
            data: data,
            prompt: "",
            useCache: false,
            existingContext: context,
            allowedPurposes: [.agent]
        )
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        guard !isInvalidated else { return }
        isInvalidated = true
        secureBuffer?.wipe()
        secureBuffer = nil
        hardwareSigner = nil
        context?.invalidate()
    }

    deinit {
        invalidate()
    }
}
