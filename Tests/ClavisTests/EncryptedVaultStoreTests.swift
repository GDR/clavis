import XCTest
import CryptoKit
@testable import ClavisCore

final class EncryptedVaultStoreTests: ClavisBaseTestCase {

    private func makeRecord(label: String) -> StoredPrivateKeyRecord {
        StoredPrivateKeyRecord(
            version: 1,
            label: label,
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: Data(repeating: 0x42, count: 32)
        )
    }

    private func vaultFileURL(for label: String) -> URL {
        let hash = SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
        return EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("\(hash).enc")
    }

    /// Reproduces the pre-AAD `CLVENV01` writer so the legacy read path stays covered.
    private func writeLegacyEnvelope(_ record: StoredPrivateKeyRecord) throws {
        let masterPublicKey = try EncryptedVaultStore.shared.ensureMasterKey()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: masterPublicKey)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.publicKey.rawRepresentation,
            sharedInfo: Data("clavis-vault-envelope-v1".utf8),
            outputByteCount: 32
        )
        let sealed = try ChaChaPoly.seal(try record.encode(), using: key)
        let epk = ephemeral.publicKey.rawRepresentation
        var envelope = Data("CLVENV01".utf8)
        envelope.append(UInt8(epk.count))
        envelope.append(epk)
        envelope.append(sealed.combined)
        try envelope.write(to: vaultFileURL(for: record.label), options: .atomic)
    }

    func testNewEnvelopesUseAuthenticatedFormatAndRoundTrip() throws {
        let label = "vault-roundtrip"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

        let raw = try Data(contentsOf: vaultFileURL(for: label))
        XCTAssertTrue(raw.starts(with: Data("CLVENV02".utf8)))

        let loaded = try XCTUnwrap(EncryptedVaultStore.shared.loadRecord(label: label))
        XCTAssertEqual(loaded.label, label)
        XCTAssertEqual(loaded.keyData, Data(repeating: 0x42, count: 32))
    }

    func testEnvelopeMovedToAnotherLabelSlotIsRejected() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "victim"))
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "decoy"))

        // Attacker with write access to the vault directory swaps one label's ciphertext in
        // place of another's. Without AAD this decrypts fine and relies on later label checks.
        let source = vaultFileURL(for: "decoy")
        let target = vaultFileURL(for: "victim")
        try FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(at: source, to: target)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: "victim"))
        XCTAssertNoThrow(try EncryptedVaultStore.shared.loadRecord(label: "decoy"))
    }

    func testTamperedCiphertextIsRejected() throws {
        let label = "vault-tamper"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))
        let url = vaultFileURL(for: label)
        var raw = try Data(contentsOf: url)
        raw[raw.count - 1] ^= 0x01
        try raw.write(to: url)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: label))
    }

    func testLegacyEnvelopeStillLoadsAndIsUpgraded() throws {
        let label = "vault-legacy"
        try writeLegacyEnvelope(makeRecord(label: label))
        XCTAssertTrue(try Data(contentsOf: vaultFileURL(for: label)).starts(with: Data("CLVENV01".utf8)))

        let loaded = try XCTUnwrap(EncryptedVaultStore.shared.loadRecord(label: label))
        XCTAssertEqual(loaded.keyData, Data(repeating: 0x42, count: 32))

        XCTAssertTrue(try Data(contentsOf: vaultFileURL(for: label)).starts(with: Data("CLVENV02".utf8)),
                      "A successfully authenticated legacy record is rewritten in the new format")
        XCTAssertEqual(try EncryptedVaultStore.shared.loadRecord(label: label)?.label, label)
    }

    func testLegacyEnvelopeUnderWrongLabelIsNotUpgraded() throws {
        // A legacy file for "decoy" planted in "victim"'s slot still decrypts (no AAD), but must
        // never be re-sealed under the victim's label.
        try writeLegacyEnvelope(makeRecord(label: "decoy"))
        let planted = vaultFileURL(for: "victim")
        try FileManager.default.copyItem(at: vaultFileURL(for: "decoy"), to: planted)

        let loaded = try EncryptedVaultStore.shared.loadRecord(label: "victim")
        XCTAssertEqual(loaded?.label, "decoy", "Callers still detect this via the record label check")
        XCTAssertTrue(try Data(contentsOf: planted).starts(with: Data("CLVENV01".utf8)))
    }
}
