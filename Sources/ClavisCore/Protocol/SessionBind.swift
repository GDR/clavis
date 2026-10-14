import Foundation
import CryptoKit
import Security

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
    private var _hasFailedBind: Bool = false

    public init() {}

    public var bindings: [SessionBinding] {
        lock.lock()
        defer { lock.unlock() }
        return _bindings
    }

    public var hasFailedBind: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _hasFailedBind
    }

    /// Verifies and appends. Returns false (caller replies [5]) on bad signature,
    /// unsupported key type, duplicate session id, or a non-forwarding bind after
    /// one already exists (OpenSSH refuses rebinding an auth connection).
    /// Any failed bind marks the connection with `hasFailedBind = true` so policy
    /// evaluation fails closed.
    public func bind(_ b: SessionBinding, signature: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if _bindings.contains(where: { $0.sessionID == b.sessionID }) {
            _hasFailedBind = true
            return false
        }

        if !b.isForwarding && _bindings.contains(where: { !$0.isForwarding }) {
            _hasFailedBind = true
            return false
        }

        guard SSHHostKeyVerifier.verify(hostKeyBlob: b.hostKeyBlob, signatureBlob: signature, message: b.sessionID) else {
            _hasFailedBind = true
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

        switch keyType {
        case "ssh-ed25519":
            guard keyType == sigType else { return false }
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
            guard keyType == sigType else { return false }
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
            guard keyType == sigType else { return false }
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
            guard keyType == sigType else { return false }
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

        case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
            // OpenSSH servers advertise an "ssh-rsa" host key blob even when signing with rsa-sha2-256/512 (RFC 8332).
            let algorithm: SecKeyAlgorithm
            switch sigType {
            case "rsa-sha2-256":
                algorithm = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512":
                algorithm = .rsaSignatureMessagePKCS1v15SHA512
            case "ssh-rsa":
                algorithm = .rsaSignatureMessagePKCS1v15SHA1
            default:
                return false
            }
            guard let eBytes = keyReader.readWireData(),
                  let nBytes = keyReader.readWireData(),
                  keyReader.isEOF,
                  let rawSig = sigReader.readWireData(),
                  sigReader.isEOF,
                  !rawSig.isEmpty,
                  let derKey = makeRSAPublicKeyDER(modulus: nBytes, exponent: eBytes) else {
                return false
            }
            let attributes: [CFString: Any] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPublic
            ]
            guard let secKey = SecKeyCreateWithData(derKey as CFData, attributes as CFDictionary, nil) else {
                return false
            }
            return SecKeyVerifySignature(secKey, algorithm, message as CFData, rawSig as CFData, nil)

        default:
            return false
        }
    }

    private static func makeRSAPublicKeyDER(modulus nBytes: Data, exponent eBytes: Data) -> Data? {
        guard let nDER = derInteger(nBytes),
              let eDER = derInteger(eBytes) else {
            return nil
        }
        return derEncode(tag: 0x30, content: nDER + eDER)
    }

    private static func derInteger(_ mpint: Data) -> Data? {
        let stripped = Data(mpint.drop(while: { $0 == 0 }))
        guard let first = stripped.first else { return nil }
        var body = Data()
        if (first & 0x80) != 0 {
            body.append(0x00)
        }
        body.append(stripped)
        return derEncode(tag: 0x02, content: body)
    }

    private static func derEncode(tag: UInt8, content: Data) -> Data? {
        let len = content.count
        var out = Data([tag])
        if len < 128 {
            out.append(UInt8(len))
        } else if len < 256 {
            out.append(contentsOf: [0x81, UInt8(len)])
        } else if len < 65536 {
            out.append(contentsOf: [0x82, UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)])
        } else {
            return nil
        }
        out.append(content)
        return out
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

public enum SessionBind {
    public static func isValidSSH2UserAuthRequest(
        _ data: Data,
        expectedSessionID: Data? = nil,
        expectedKeyBlob: Data? = nil,
        expectedHostKeyBlob: Data? = nil
    ) -> Bool {
        var reader = DataReader(data: data)
        guard let sessionID = reader.readWireData() else { return false }
        if let expectedSessionID, sessionID != expectedSessionID { return false }
        guard let msgType = reader.readUInt8(), msgType == 50 else { return false }
        guard let _ = reader.readWireString() else { return false }
        guard let service = reader.readWireString(), service == "ssh-connection" else { return false }
        guard let method = reader.readWireString() else { return false }
        guard let hasSig = reader.readBool(), hasSig == true else { return false }
        guard let _ = reader.readWireString() else { return false }
        guard let keyBlob = reader.readWireData() else { return false }
        if let expectedKeyBlob, keyBlob != expectedKeyBlob { return false }
        switch method {
        case "publickey":
            return reader.isEOF
        case "publickey-hostbound-v00@openssh.com":
            guard let hostKeyBlob = reader.readWireData(), !hostKeyBlob.isEmpty else { return false }
            if let expectedHostKeyBlob, hostKeyBlob != expectedHostKeyBlob { return false }
            return reader.isEOF
        default:
            return false
        }
    }

    public static func extractHostKeyFromUserAuthRequest(_ data: Data) -> Data? {
        var reader = DataReader(data: data)
        guard let _ = reader.readWireData(),
              let msgType = reader.readUInt8(), msgType == 50,
              let _ = reader.readWireString(),
              let service = reader.readWireString(), service == "ssh-connection",
              let method = reader.readWireString(), method == "publickey-hostbound-v00@openssh.com",
              let hasSig = reader.readBool(), hasSig == true,
              let _ = reader.readWireString(),
              let _ = reader.readWireData(),
              let hostKeyBlob = reader.readWireData(),
              reader.isEOF else {
            return nil
        }
        return hostKeyBlob
    }
}
