import Foundation
import CryptoKit
import Security

public enum AuditCryptoError: Error, Equatable {
    case invalidEpochID
    case invalidSealedBlob
    case sealFailed
    case unwrapFailed
    case openFailed
}

public enum AuditCrypto {
    /// Generates 16 cryptographically secure random bytes for an epoch ID.
    public static func newEpochID() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            fatalError("SecRandomCopyBytes failed with status \(status)")
        }
        return Data(bytes)
    }

    /// Generates a new random 256-bit symmetric key for row encryption.
    public static func newDEK() -> SymmetricKey {
        SymmetricKey(size: .bits256)
    }

    /// Wraps an epoch DEK using ephemeral ECDH + HKDF + AES-GCM.
    public static func wrapDEK(
        _ dek: SymmetricKey,
        epochID: Data,
        keyID: String,
        to pub: P256.KeyAgreement.PublicKey
    ) throws -> (epk: Data, wrapped: Data) {
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: pub)
        var sharedInfo = Data("clavis-audit-epoch-v1".utf8)
        sharedInfo.append(contentsOf: keyID.utf8)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: eph.publicKey.x963Representation,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        let dekData = dek.withUnsafeBytes { Data($0) }
        let sealedBox = try AES.GCM.seal(dekData, using: kek, authenticating: epochID)
        guard let wrapped = sealedBox.combined else {
            throw AuditCryptoError.sealFailed
        }
        return (epk: eph.publicKey.x963Representation, wrapped: wrapped)
    }

    /// Unwraps an epoch DEK using ECDH via `agree` callback + HKDF + AES-GCM.
    public static func unwrapDEK(
        epk: Data,
        wrapped: Data,
        epochID: Data,
        keyID: String,
        agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret
    ) throws -> SymmetricKey {
        let peerPub = try P256.KeyAgreement.PublicKey(x963Representation: epk)
        let shared = try agree(peerPub)
        var sharedInfo = Data("clavis-audit-epoch-v1".utf8)
        sharedInfo.append(contentsOf: keyID.utf8)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: epk,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        let sealedBox = try AES.GCM.SealedBox(combined: wrapped)
        let dekData = try AES.GCM.open(sealedBox, using: kek, authenticating: epochID)
        return SymmetricKey(data: dekData)
    }

    /// Re-wraps an epoch DEK from an old key to a new public key using ECDH agreement.
    public static func rewrapDEK(
        epk: Data,
        wrapped: Data,
        epochID: Data,
        keyID: String,
        agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret,
        to newKey: AuditReadPublicKey
    ) throws -> (epk: Data, wrapped: Data) {
        let dek = try unwrapDEK(epk: epk, wrapped: wrapped, epochID: epochID, keyID: keyID, agree: agree)
        return try wrapDEK(dek, epochID: epochID, keyID: newKey.keyID, to: newKey.publicKey)
    }

    /// Computes the authenticated associated data for an audit row.
    /// aad = "clavis-audit-row-v1" | event_id | time.bitPattern (UInt64 big-endian, 8 bytes) | type | fingerprint ?? ""
    /// where `|` is a single 0x00 byte separator.
    public static func rowAAD(eventID: UUID, time: Date, type: AuditEventType, fingerprint: String?) -> Data {
        var aad = Data("clavis-audit-row-v1".utf8)
        aad.append(0x00)
        aad.append(contentsOf: eventID.uuidString.utf8)
        aad.append(0x00)
        var timeBits = time.timeIntervalSince1970.bitPattern.bigEndian
        withUnsafeBytes(of: &timeBits) { aad.append(contentsOf: $0) }
        aad.append(0x00)
        aad.append(contentsOf: type.rawValue.utf8)
        aad.append(0x00)
        if let fp = fingerprint {
            aad.append(contentsOf: fp.utf8)
        }
        return aad
    }

    /// Seals an AuditSensitive object with an epoch DEK using AES-GCM.
    /// Returns 16 bytes epochID + AES.GCM combined box.
    public static func sealRow(
        _ s: AuditSensitive,
        dek: SymmetricKey,
        epochID: Data,
        aad: Data
    ) throws -> Data {
        guard epochID.count == 16 else {
            throw AuditCryptoError.invalidEpochID
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext = try encoder.encode(s)
        let sealedBox = try AES.GCM.seal(plaintext, using: dek, authenticating: aad)
        guard let combined = sealedBox.combined else {
            throw AuditCryptoError.sealFailed
        }
        var blob = Data()
        blob.reserveCapacity(epochID.count + combined.count)
        blob.append(epochID)
        blob.append(combined)
        return blob
    }

    /// Extracts the epochID (first 16 bytes) from a sealed row blob, if present and valid length.
    public static func epochID(ofSealedRow blob: Data) -> Data? {
        // 16 bytes epochID + at least 12 bytes nonce + 16 bytes tag = 44 bytes
        guard blob.count >= 44 else { return nil }
        return blob.prefix(16)
    }

    /// Opens a sealed row blob with a DEK resolution callback.
    public static func openRow(
        _ blob: Data,
        dek: (Data) throws -> SymmetricKey,
        aad: Data
    ) throws -> AuditSensitive {
        guard let epochID = epochID(ofSealedRow: blob) else {
            throw AuditCryptoError.invalidSealedBlob
        }
        let key = try dek(epochID)
        let combined = blob.dropFirst(16)
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        return try JSONDecoder().decode(AuditSensitive.self, from: plaintext)
    }

    /// Convenience overload for openRow with a direct SymmetricKey.
    public static func openRow(
        _ blob: Data,
        dek: SymmetricKey,
        aad: Data
    ) throws -> AuditSensitive {
        try openRow(blob, dek: { _ in dek }, aad: aad)
    }
}
