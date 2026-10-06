import XCTest
import CryptoKit
@testable import ClavisCore

final class AuditCryptoTests: ClavisBaseTestCase {
    func test_008_T1_wrapUnwrapRoundTrip() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let keyID = "testkeyid1234567"
        let epochID = AuditCrypto.newEpochID()
        XCTAssertEqual(epochID.count, 16)
        let dek = AuditCrypto.newDEK()

        let (epk, wrapped) = try AuditCrypto.wrapDEK(dek, epochID: epochID, keyID: keyID, to: publicKey)
        XCTAssertFalse(epk.isEmpty)
        XCTAssertFalse(wrapped.isEmpty)

        let unwrapped = try AuditCrypto.unwrapDEK(
            epk: epk,
            wrapped: wrapped,
            epochID: epochID,
            keyID: keyID,
            agree: { peerPub in
                try privateKey.sharedSecretFromKeyAgreement(with: peerPub)
            }
        )

        let dekData = dek.withUnsafeBytes { Data($0) }
        let unwrappedData = unwrapped.withUnsafeBytes { Data($0) }
        XCTAssertEqual(dekData, unwrappedData)
    }

    func test_008_T1_unwrapWithWrongKeyFails() throws {
        let keyA = P256.KeyAgreement.PrivateKey()
        let keyB = P256.KeyAgreement.PrivateKey()
        let keyID = "testkeyid1234567"
        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()

        let (epk, wrapped) = try AuditCrypto.wrapDEK(dek, epochID: epochID, keyID: keyID, to: keyA.publicKey)

        // Wrong private key
        XCTAssertThrowsError(
            try AuditCrypto.unwrapDEK(
                epk: epk,
                wrapped: wrapped,
                epochID: epochID,
                keyID: keyID,
                agree: { peerPub in
                    try keyB.sharedSecretFromKeyAgreement(with: peerPub)
                }
            )
        )

        // Wrong epochID (AAD mismatch)
        let wrongEpochID = AuditCrypto.newEpochID()
        XCTAssertThrowsError(
            try AuditCrypto.unwrapDEK(
                epk: epk,
                wrapped: wrapped,
                epochID: wrongEpochID,
                keyID: keyID,
                agree: { peerPub in
                    try keyA.sharedSecretFromKeyAgreement(with: peerPub)
                }
            )
        )

        // Wrong keyID (sharedInfo mismatch)
        XCTAssertThrowsError(
            try AuditCrypto.unwrapDEK(
                epk: epk,
                wrapped: wrapped,
                epochID: epochID,
                keyID: "differentkeyid",
                agree: { peerPub in
                    try keyA.sharedSecretFromKeyAgreement(with: peerPub)
                }
            )
        )

        // Tampered wrapped data
        var tamperedWrapped = wrapped
        tamperedWrapped[tamperedWrapped.count - 1] ^= 0x55
        XCTAssertThrowsError(
            try AuditCrypto.unwrapDEK(
                epk: epk,
                wrapped: tamperedWrapped,
                epochID: epochID,
                keyID: keyID,
                agree: { peerPub in
                    try keyA.sharedSecretFromKeyAgreement(with: peerPub)
                }
            )
        )
    }

    func test_008_T1_sealOpenRoundTrip() throws {
        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()
        let eventID = UUID()
        let time = Date()
        let type: AuditEventType = .signature
        let fingerprint = "SHA256:abc123def456"
        let aad = AuditCrypto.rowAAD(eventID: eventID, time: time, type: type, fingerprint: fingerprint)

        let sensitive = AuditSensitive(
            keyLabel: "id_ed25519_personal",
            processChain: [
                AuditProcess(executablePath: "/usr/bin/ssh", pid: 1234),
                AuditProcess(executablePath: "/bin/bash", pid: 1000)
            ],
            host: "git.example.com"
        )

        let blob = try AuditCrypto.sealRow(sensitive, dek: dek, epochID: epochID, aad: aad)
        XCTAssertEqual(AuditCrypto.epochID(ofSealedRow: blob), epochID)

        let opened = try AuditCrypto.openRow(blob, dek: dek, aad: aad)
        XCTAssertEqual(opened, sensitive)

        // Test with closure resolution
        let openedViaClosure = try AuditCrypto.openRow(blob, dek: { id in
            XCTAssertEqual(id, epochID)
            return dek
        }, aad: aad)
        XCTAssertEqual(openedViaClosure, sensitive)
    }

    func test_008_T1_aadBindsRowFields() throws {
        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()
        let eventID = UUID()
        let time = Date()
        let type: AuditEventType = .signature
        let fingerprint = "SHA256:abc123def456"
        let aad = AuditCrypto.rowAAD(eventID: eventID, time: time, type: type, fingerprint: fingerprint)

        let sensitive = AuditSensitive(
            keyLabel: "id_ed25519_personal",
            processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 1234)],
            host: "git.example.com"
        )

        let blob = try AuditCrypto.sealRow(sensitive, dek: dek, epochID: epochID, aad: aad)

        // Modified eventID
        let modifiedEventID = UUID()
        let aadModifiedID = AuditCrypto.rowAAD(eventID: modifiedEventID, time: time, type: type, fingerprint: fingerprint)
        XCTAssertThrowsError(try AuditCrypto.openRow(blob, dek: dek, aad: aadModifiedID))

        // Modified time
        let modifiedTime = time.addingTimeInterval(1.0)
        let aadModifiedTime = AuditCrypto.rowAAD(eventID: eventID, time: modifiedTime, type: type, fingerprint: fingerprint)
        XCTAssertThrowsError(try AuditCrypto.openRow(blob, dek: dek, aad: aadModifiedTime))

        // Modified type
        let modifiedType: AuditEventType = .lock
        let aadModifiedType = AuditCrypto.rowAAD(eventID: eventID, time: time, type: modifiedType, fingerprint: fingerprint)
        XCTAssertThrowsError(try AuditCrypto.openRow(blob, dek: dek, aad: aadModifiedType))

        // Modified fingerprint
        let modifiedFingerprint = "SHA256:different"
        let aadModifiedFP = AuditCrypto.rowAAD(eventID: eventID, time: time, type: type, fingerprint: modifiedFingerprint)
        XCTAssertThrowsError(try AuditCrypto.openRow(blob, dek: dek, aad: aadModifiedFP))

        // Nil vs non-nil fingerprint
        let aadNilFP = AuditCrypto.rowAAD(eventID: eventID, time: time, type: type, fingerprint: nil)
        XCTAssertThrowsError(try AuditCrypto.openRow(blob, dek: dek, aad: aadNilFP))
    }

    func test_008_AC1_sealedBlobContainsNoPlaintext() throws {
        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()
        let eventID = UUID()
        let time = Date()
        let type: AuditEventType = .signature
        let fingerprint = "SHA256:abc123def456"
        let aad = AuditCrypto.rowAAD(eventID: eventID, time: time, type: type, fingerprint: fingerprint)

        let secretLabel = "super_secret_ssh_key_label_xyz"
        let secretPath = "/very/secret/path/to/script.sh"
        let secretHost = "classified-vault.internal.corp"

        let sensitive = AuditSensitive(
            keyLabel: secretLabel,
            processChain: [AuditProcess(executablePath: secretPath, pid: 42)],
            host: secretHost
        )

        let blob = try AuditCrypto.sealRow(sensitive, dek: dek, epochID: epochID, aad: aad)

        func containsSubdata(_ data: Data, target: Data) -> Bool {
            guard !target.isEmpty, data.count >= target.count else { return false }
            return data.range(of: target) != nil
        }

        XCTAssertFalse(containsSubdata(blob, target: Data(secretLabel.utf8)))
        XCTAssertFalse(containsSubdata(blob, target: Data(secretPath.utf8)))
        XCTAssertFalse(containsSubdata(blob, target: Data(secretHost.utf8)))
    }
}
