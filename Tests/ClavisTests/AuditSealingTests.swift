import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

private final class FailingAuditKeyring: AuditKeyring, @unchecked Sendable {
    func currentPublicKey() throws -> AuditReadPublicKey {
        throw AuditKeyringError.secureEnclaveUnavailable
    }
    func agree(keyID: String, with peer: P256.KeyAgreement.PublicKey, context: LAContext?) throws -> SharedSecret {
        throw AuditKeyringError.secureEnclaveUnavailable
    }
    func validateCurrent(context: LAContext?) -> AuditKeyringValidation {
        .unusable
    }
    func rotate(mode: AuditReadMode) throws -> AuditReadPublicKey {
        throw AuditKeyringError.secureEnclaveUnavailable
    }
    func knownKeyIDs() throws -> [String] {
        []
    }
}

final class AuditSealingTests: ClavisBaseTestCase {
    private var dbURL: URL {
        testRootURL.appendingPathComponent("audit-sealing-test.db")
    }

    func test_008_AC4_recordingNeedsNoContextOrPrompt() throws {
        let keyring = SoftwareAuditKeyring(requireContext: true)
        let sealer = AuditSealer(keyring: keyring)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            sealer: sealer
        )

        for i in 0..<100 {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                sensitive: AuditSensitive(keyLabel: "key_\(i)", processChain: [], host: "host.example.com")
            )
            recorder.record(event)
        }
        recorder.flush()

        // Recording 100 events must require 0 agree calls (no context, no Touch ID)
        XCTAssertEqual(keyring.agreeCalls, 0)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let records = try store.query(AuditQuery(limit: 200))
        XCTAssertEqual(records.count, 100)
        XCTAssertTrue(records.allSatisfy { $0.sensitiveFormat == 1 && $0.sealedSensitive != nil })
    }

    func test_008_T4_rotatesEpochByRowsAndAge() throws {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let keyring = SoftwareAuditKeyring(requireContext: true)
        let sealer = AuditSealer(
            keyring: keyring,
            now: { currentTime },
            maxEpochAge: 10,
            maxEpochRows: 3
        )
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        // Seal row 1, 2, 3 -> should use epoch 1
        for _ in 0..<3 {
            let event = AuditEvent(type: .signature, result: .allowed)
            let (fmt, blob) = sealer.seal(event, store: store)
            XCTAssertEqual(fmt, 1)
            XCTAssertFalse(blob.isEmpty)
        }
        var epochs = try store.epochs()
        XCTAssertEqual(epochs.count, 1)

        // Seal row 4 -> maxEpochRows is 3, so must rotate to epoch 2
        let (fmt4, blob4) = sealer.seal(AuditEvent(type: .signature, result: .allowed), store: store)
        XCTAssertEqual(fmt4, 1)
        XCTAssertFalse(blob4.isEmpty)
        epochs = try store.epochs()
        XCTAssertEqual(epochs.count, 2)

        // Advance time by 11s -> exceeds maxEpochAge (10s), so must rotate to epoch 3
        currentTime = currentTime.addingTimeInterval(11.0)
        let (fmt5, blob5) = sealer.seal(AuditEvent(type: .signature, result: .allowed), store: store)
        XCTAssertEqual(fmt5, 1)
        XCTAssertFalse(blob5.isEmpty)
        epochs = try store.epochs()
        XCTAssertEqual(epochs.count, 3)
    }

    func test_008_T4_keyringErrorWritesFormat2() throws {
        let failingKeyring = FailingAuditKeyring()
        let sealer = AuditSealer(keyring: failingKeyring)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            sealer: sealer
        )

        let event = AuditEvent(
            type: .signature,
            result: .denied,
            reason: .unknownKey,
            keyFingerprint: "SHA256:victimKey",
            sensitive: AuditSensitive(keyLabel: "super_secret_label")
        )
        recorder.record(event)
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let records = try store.query(AuditQuery())
        XCTAssertEqual(records.count, 1)
        let record = records[0]
        XCTAssertEqual(record.sensitiveFormat, 2)
        XCTAssertNil(record.sealedSensitive)
        // Filter columns are still recorded intact
        XCTAssertEqual(record.event.type, .signature)
        XCTAssertEqual(record.event.result, .denied)
        XCTAssertEqual(record.event.reason, .unknownKey)
        XCTAssertEqual(record.event.keyFingerprint, "SHA256:victimKey")
        XCTAssertEqual(record.event.sensitive, AuditSensitive())
    }

    func test_008_T4_resealerConvertsLegacyRows() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        // Insert legacy format-0 plaintext rows
        for i in 0..<5 {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                sensitive: AuditSensitive(keyLabel: "legacy_key_\(i)")
            )
            try store.insert(event)
        }

        let legacyRowsBefore = try store.legacyPlaintextRows(limit: 10)
        XCTAssertEqual(legacyRowsBefore.count, 5)

        let keyring = SoftwareAuditKeyring(requireContext: true)
        let sealer = AuditSealer(keyring: keyring)
        let resealer = AuditResealer(
            storeFactory: { try AuditStore(url: self.dbURL) },
            sealer: sealer,
            batchSize: 10
        )

        let converted = resealer.runBatch()
        XCTAssertEqual(converted, 5)

        let legacyRowsAfter = try store.legacyPlaintextRows(limit: 10)
        XCTAssertEqual(legacyRowsAfter.count, 0)

        let allRecords = try store.query(AuditQuery(limit: 10))
        XCTAssertEqual(allRecords.count, 5)
        XCTAssertTrue(allRecords.allSatisfy { $0.sensitiveFormat == 1 && $0.sealedSensitive != nil })
    }
}
