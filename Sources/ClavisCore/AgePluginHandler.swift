import Foundation
import CryptoKit

public extension Data {
    init?(base64Lenient string: String) {
        let clean = string.trimmingCharacters(in: .whitespacesAndNewlines)
        var b64 = clean.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 {
            b64.append("=")
        }
        self.init(base64Encoded: b64)
    }
}

public struct AgeStanza: Equatable {
    public let fileIndex: Int
    public let tag: String
    public let epk: String
    public let wrappedKey: Data

    public init(fileIndex: Int, tag: String, epk: String, wrappedKey: Data) {
        self.fileIndex = fileIndex
        self.tag = tag
        self.epk = epk
        self.wrappedKey = wrappedKey
    }

    public func encodeIPC() -> String {
        let wrappedB64 = wrappedKey.base64EncodedString()
        return "-> recipient-stanza \(fileIndex) \(tag) \(epk)\n\(wrappedB64)"
    }

    public static func parseIPC(header: String, body: String) -> AgeStanza? {
        let parts = header.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ").map(String.init)
        guard parts.count >= 4, parts[0] == "->", parts[1] == "recipient-stanza" else { return nil }
        guard let fileIndex = Int(parts[2]) else { return nil }
        let tag = parts[3]
        let epk = parts.count >= 5 ? parts[4] : ""
        guard let wrappedData = Data(base64Lenient: body) else { return nil }
        return AgeStanza(fileIndex: fileIndex, tag: tag, epk: epk, wrappedKey: wrappedData)
    }
}

public enum AgePluginError: Error, Equatable {
    case invalidRecipient
    case invalidEphemeralKey
    case invalidWrappedKey
    case decryptionFailed
    case keychainError(String)
}

public struct AgePluginCrypto {
    public static func wrapFileKey(fileKey: Data, recipientString: String) throws -> (epkB64: String, wrappedKey: Data) {
        let recipientData: Data
        if recipientString.hasPrefix("age1") {
            let decoded = try Bech32.decode(bech32String: recipientString)
            if let converted = Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: decoded.data) {
                recipientData = converted
            } else if decoded.data.count == 32 {
                recipientData = decoded.data
            } else {
                throw AgePluginError.invalidRecipient
            }
        } else if let raw = Data(base64Lenient: recipientString), raw.count == 32 {
            recipientData = raw
        } else {
            throw AgePluginError.invalidRecipient
        }

        let ephemeralPrivKey = Curve25519.KeyAgreement.PrivateKey()
        let epkData = ephemeralPrivKey.publicKey.rawRepresentation

        let recipientPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientData)
        let sharedSecret = try ephemeralPrivKey.sharedSecretFromKeyAgreement(with: recipientPubKey)

        var salt = Data()
        salt.append(epkData)
        salt.append(recipientData)

        let info = Data("age-encryption.org/v1/X25519".utf8)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)

        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let sealedBox = try ChaChaPoly.seal(fileKey, using: symmetricKey, nonce: zeroNonce)
        let wrappedKey = sealedBox.ciphertext + sealedBox.tag

        return (epkB64: epkData.base64EncodedString(), wrappedKey: wrappedKey)
    }

    public static func unwrapFileKey(wrappedKey: Data, epkB64: String, ed25519Seed: Data) throws -> Data {
        guard let epkData = Data(base64Lenient: epkB64), epkData.count == 32 else {
            throw AgePluginError.invalidEphemeralKey
        }
        guard wrappedKey.count > 16 else {
            throw AgePluginError.invalidWrappedKey
        }

        let x25519PrivKey = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: ed25519Seed)
        let recPubKeyData = x25519PrivKey.publicKey.rawRepresentation

        let epkPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: epkData)
        let sharedSecret = try x25519PrivKey.sharedSecretFromKeyAgreement(with: epkPubKey)

        var salt = Data()
        salt.append(epkData)
        salt.append(recPubKeyData)

        let info = Data("age-encryption.org/v1/X25519".utf8)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)

        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let ciphertext = wrappedKey.prefix(wrappedKey.count - 16)
        let tag = wrappedKey.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: zeroNonce, ciphertext: ciphertext, tag: tag)

        do {
            let fileKey = try ChaChaPoly.open(sealedBox, using: symmetricKey)
            return fileKey
        } catch {
            throw AgePluginError.decryptionFailed
        }
    }
}
