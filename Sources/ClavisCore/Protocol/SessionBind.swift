import Foundation
import CryptoKit

public struct SessionBinding: Equatable, Sendable {
    public let hostKeyBlob: Data
    public let sessionID: Data
    public let isForwarding: Bool

    public init(hostKeyBlob: Data, sessionID: Data, isForwarding: Bool) {
        self.hostKeyBlob = hostKeyBlob
        self.sessionID = sessionID
        self.isForwarding = isForwarding
    }
}

public final class AgentConnectionState: @unchecked Sendable {
    private let lock = NSLock()
    private var _bindings: [SessionBinding] = []

    public init() {}

    public var bindings: [SessionBinding] {
        lock.lock()
        defer { lock.unlock() }
        return _bindings
    }

    /// Verifies and appends. Returns false (caller replies [5]) on bad signature,
    /// unsupported key type, duplicate session id, or a non-forwarding bind after
    /// one already exists (OpenSSH refuses rebinding an auth connection).
    public func bind(_ b: SessionBinding, signature: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if _bindings.contains(where: { $0.sessionID == b.sessionID }) {
            return false
        }

        if !b.isForwarding && _bindings.contains(where: { !$0.isForwarding }) {
            return false
        }

        guard SSHHostKeyVerifier.verify(hostKeyBlob: b.hostKeyBlob, signatureBlob: signature, message: b.sessionID) else {
            return false
        }

        _bindings.append(b)
        return true
    }

    public var hasForwarding: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _bindings.contains(where: { $0.isForwarding })
    }

    public var authBinding: SessionBinding? {
        lock.lock()
        defer { lock.unlock() }
        return _bindings.last(where: { !$0.isForwarding })
    }
}

public enum SSHHostKeyVerifier {
    public static func verify(hostKeyBlob: Data, signatureBlob: Data, message: Data) -> Bool {
        var keyReader = DataReader(data: hostKeyBlob)
        guard let keyType = keyReader.readWireString() else { return false }

        var sigReader = DataReader(data: signatureBlob)
        guard let sigType = sigReader.readWireString() else { return false }

        guard keyType == sigType else { return false }

        switch keyType {
        case "ssh-ed25519":
            guard let rawKey = keyReader.readWireData(), keyReader.isEOF, rawKey.count == 32 else {
                return false
            }
            guard let rawSig = sigReader.readWireData(), sigReader.isEOF, rawSig.count == 64 else {
                return false
            }
            guard let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey) else {
                return false
            }
            return pubKey.isValidSignature(rawSig, for: message)

        case "ecdsa-sha2-nistp256":
            guard let curveId = keyReader.readWireString(), curveId == "nistp256",
                  let qBytes = keyReader.readWireData(), keyReader.isEOF else {
                return false
            }
            guard let sigData = sigReader.readWireData(), sigReader.isEOF else { return false }
            var ecdsaReader = DataReader(data: sigData)
            guard let rBytes = ecdsaReader.readWireData(),
                  let sBytes = ecdsaReader.readWireData(),
                  ecdsaReader.isEOF else {
                return false
            }
            guard let r = normalizeMPInt(rBytes, byteCount: 32),
                  let s = normalizeMPInt(sBytes, byteCount: 32) else {
                return false
            }
            guard let ecdsaSig = try? P256.Signing.ECDSASignature(rawRepresentation: r + s),
                  let pubKey = try? P256.Signing.PublicKey(x963Representation: qBytes) else {
                return false
            }
            return pubKey.isValidSignature(ecdsaSig, for: message)

        case "ecdsa-sha2-nistp384":
            guard let curveId = keyReader.readWireString(), curveId == "nistp384",
                  let qBytes = keyReader.readWireData(), keyReader.isEOF else {
                return false
            }
            guard let sigData = sigReader.readWireData(), sigReader.isEOF else { return false }
            var ecdsaReader = DataReader(data: sigData)
            guard let rBytes = ecdsaReader.readWireData(),
                  let sBytes = ecdsaReader.readWireData(),
                  ecdsaReader.isEOF else {
                return false
            }
            guard let r = normalizeMPInt(rBytes, byteCount: 48),
                  let s = normalizeMPInt(sBytes, byteCount: 48) else {
                return false
            }
            guard let ecdsaSig = try? P384.Signing.ECDSASignature(rawRepresentation: r + s),
                  let pubKey = try? P384.Signing.PublicKey(x963Representation: qBytes) else {
                return false
            }
            return pubKey.isValidSignature(ecdsaSig, for: message)

        case "ecdsa-sha2-nistp521":
            guard let curveId = keyReader.readWireString(), curveId == "nistp521",
                  let qBytes = keyReader.readWireData(), keyReader.isEOF else {
                return false
            }
            guard let sigData = sigReader.readWireData(), sigReader.isEOF else { return false }
            var ecdsaReader = DataReader(data: sigData)
            guard let rBytes = ecdsaReader.readWireData(),
                  let sBytes = ecdsaReader.readWireData(),
                  ecdsaReader.isEOF else {
                return false
            }
            guard let r = normalizeMPInt(rBytes, byteCount: 66),
                  let s = normalizeMPInt(sBytes, byteCount: 66) else {
                return false
            }
            guard let ecdsaSig = try? P521.Signing.ECDSASignature(rawRepresentation: r + s),
                  let pubKey = try? P521.Signing.PublicKey(x963Representation: qBytes) else {
                return false
            }
            return pubKey.isValidSignature(ecdsaSig, for: message)

        default:
            return false
        }
    }

    private static func normalizeMPInt(_ data: Data, byteCount: Int) -> Data? {
        var d = data
        while d.count > byteCount && d.first == 0 {
            d.removeFirst()
        }
        guard d.count <= byteCount else { return nil }
        if d.count < byteCount {
            let padding = Data(repeating: 0, count: byteCount - d.count)
            return padding + d
        }
        return d
    }
}
