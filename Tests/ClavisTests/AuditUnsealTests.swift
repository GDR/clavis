import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

final class AuditUnsealTests: ClavisBaseTestCase {
    private var dbURL: URL {
        testRootURL.appendingPathComponent("audit-unseal-test.db")
    }

    func test_008_AC3_unlockedReaderOpensAllRowsWithOneAgreePerEpoch() throws {
        let keyring = SoftwareAuditKeyring(requireContext: true)
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        // Create 3 epochs, 50 rows each
        for epochIdx in 0..<3 {
            let sealer = AuditSealer(
                keyring: keyring,
                maxEpochAge: 3600,
                maxEpochRows: 50
            )
            for rowIdx in 0..<50 {
                let event = AuditEvent(
                    type: .signature,
                    result: .allowed,
                    sensitive: AuditSensitive(
                        keyLabel: "key_\(epochIdx)_\(rowIdx)",
                        processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 100 + Int32(rowIdx))],
                        host: "host\(epochIdx).example.com"
                    )
                )
                let (fmt, blob) = sealer.seal(event, store: store)
                try store.insert(event, sensitiveFormat: fmt, sensitiveBlob: blob)
            }
        }

        let epochs = try store.epochs()
        XCTAssertEqual(epochs.count, 3)

        let records = try store.query(AuditQuery(limit: 200))
        XCTAssertEqual(records.count, 150)

        // Read all rows with unlock context
        let dummyContext = LAContext()
        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: dummyContext)

        for record in records {
            let result = unsealer.open(record)
            guard case .plaintext(let sensitive) = result else {
                XCTFail("Expected plaintext for record \(record.seq), got \(result)")
                return
            }
            XCTAssertNotNil(sensitive.keyLabel)
            XCTAssertEqual(sensitive.processChain.count, 1)
            XCTAssertNotNil(sensitive.host)
        }

        // AC3: 3 epochs * 50 rows -> agreeCalls == 3
        XCTAssertEqual(keyring.agreeCalls, 3)
    }

    func test_008_AC5_lostKeyShowsOldRowsUnreadableNewRowsReadable() throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        // Write row under old key
        let oldPubKey = try keyring.currentPublicKey()
        let sealer1 = AuditSealer(keyring: keyring)
        let event1 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "old_key", processChain: [], host: "old.host")
        )
        let (fmt1, blob1) = sealer1.seal(event1, store: store)
        let seq1 = try store.insert(event1, sensitiveFormat: fmt1, sensitiveBlob: blob1)

        // Rotate to new key and drop old key (simulating lost key)
        let newPubKey = try keyring.rotate(mode: .passwordOrBiometry)
        XCTAssertNotEqual(oldPubKey.keyID, newPubKey.keyID)
        keyring.dropKey(keyID: oldPubKey.keyID)

        // Write row under new key
        let sealer2 = AuditSealer(keyring: keyring)
        let event2 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "new_key", processChain: [], host: "new.host")
        )
        let (fmt2, blob2) = sealer2.seal(event2, store: store)
        let seq2 = try store.insert(event2, sensitiveFormat: fmt2, sensitiveBlob: blob2)

        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: nil)
        let records = try store.query(AuditQuery(limit: 10))
        let rec1 = records.first(where: { $0.seq == seq1 })!
        let rec2 = records.first(where: { $0.seq == seq2 })!

        // AC5: old entry is unreadable, new entry is readable
        XCTAssertEqual(unsealer.open(rec1), .unreadable)
        if case .plaintext(let s2) = unsealer.open(rec2) {
            XCTAssertEqual(s2.keyLabel, "new_key")
        } else {
            XCTFail("Expected rec2 to be readable plaintext")
        }
    }

    func test_008_T5_tamperedBlobIsUnreadable() throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let sealer = AuditSealer(keyring: keyring)
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "secret", processChain: [], host: "tamper.test")
        )
        let (fmt, mutBlob) = sealer.seal(event, store: store)
        var tamperedBlob = mutBlob
        // Tamper with ciphertext bytes (after 16-byte epoch ID)
        tamperedBlob[20] ^= 0xff

        let seq = try store.insert(event, sensitiveFormat: fmt, sensitiveBlob: tamperedBlob)
        let records = try store.query(AuditQuery(limit: 1))
        let record = records.first(where: { $0.seq == seq })!

        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: nil)
        XCTAssertEqual(unsealer.open(record), .unreadable)
    }

    func test_008_T5_legacyAndOmittedFormats() throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        // Format 0 (legacy plaintext JSON)
        let event0 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "legacy_key", processChain: [], host: "legacy.host")
        )
        let seq0 = try store.insert(event0) // writes format 0

        // Format 2 (omitted)
        let event2 = AuditEvent(type: .signature, result: .allowed)
        let seq2 = try store.insert(event2, sensitiveFormat: 2, sensitiveBlob: Data())

        // Format 99 (unknown format)
        let event99 = AuditEvent(type: .signature, result: .allowed)
        let seq99 = try store.insert(event99, sensitiveFormat: 99, sensitiveBlob: Data([1, 2, 3]))

        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: nil)
        let records = try store.query(AuditQuery(limit: 10))
        let rec0 = records.first(where: { $0.seq == seq0 })!
        let rec2 = records.first(where: { $0.seq == seq2 })!
        let rec99 = records.first(where: { $0.seq == seq99 })!

        XCTAssertEqual(unsealer.open(rec0), .plaintext(event0.sensitive))
        XCTAssertEqual(unsealer.open(rec2), .omitted)
        XCTAssertEqual(unsealer.open(rec99), .unreadable)
    }

    func test_008_AC2_otherKeyringCannotRead() throws {
        let keyring1 = SoftwareAuditKeyring(requireContext: false)
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let sealer = AuditSealer(keyring: keyring1)
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "secret_backup", processChain: [], host: "remote.host")
        )
        let (fmt, blob) = sealer.seal(event, store: store)
        let seq = try store.insert(event, sensitiveFormat: fmt, sensitiveBlob: blob)

        // AC2: simulated restore on another Mac with a different keyring
        let keyring2 = SoftwareAuditKeyring(requireContext: false)
        let unsealer = AuditUnsealer(keyring: keyring2, store: store, context: nil)

        let records = try store.query(AuditQuery(limit: 1))
        let record = records.first(where: { $0.seq == seq })!

        XCTAssertEqual(unsealer.open(record), .unreadable)
    }
}
