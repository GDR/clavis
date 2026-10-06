import XCTest
import SQLite3
@testable import ClavisCore

final class AuditStoreV2Tests: ClavisBaseTestCase {
    private var dbURL: URL {
        testRootURL.appendingPathComponent("audit-v2-test.db")
    }

    func test_008_T3_migratesV1DatabaseKeepingRows() throws {
        // Manually create a v1 database with user_version = 1 and 1 event
        var rawDb: OpaquePointer?
        XCTAssertEqual(sqlite3_open(dbURL.path, &rawDb), SQLITE_OK)
        guard let db = rawDb else {
            XCTFail("Failed to open raw sqlite db")
            return
        }

        let v1Schema = """
        BEGIN IMMEDIATE;
        CREATE TABLE events (
          seq              INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id         TEXT    NOT NULL UNIQUE,
          time             REAL    NOT NULL,
          type             TEXT    NOT NULL,
          result           TEXT    NOT NULL,
          reason           TEXT,
          key_fingerprint  TEXT,
          key_kind         TEXT,
          session_id       TEXT,
          count            INTEGER NOT NULL DEFAULT 1,
          sensitive_format INTEGER NOT NULL,
          sensitive        BLOB    NOT NULL
        ) STRICT;
        CREATE INDEX idx_events_time    ON events(time);
        CREATE INDEX idx_events_key     ON events(key_fingerprint, time);
        CREATE INDEX idx_events_session ON events(session_id, time);
        CREATE INDEX idx_events_result  ON events(result, time);
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        PRAGMA user_version = 1;
        COMMIT;
        """
        XCTAssertEqual(sqlite3_exec(db, v1Schema, nil, nil, nil), SQLITE_OK)

        // Insert a v1 row
        let insertSQL = """
        INSERT INTO events (
          event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
        ) VALUES ('11111111-1111-1111-1111-111111111111', 1700000000.0, 'signature', 'allowed', NULL, 'SHA256:test', 'personal', NULL, 1, 0, X'7B7D');
        """
        XCTAssertEqual(sqlite3_exec(db, insertSQL, nil, nil, nil), SQLITE_OK)
        sqlite3_close(db)

        // Open with AuditStore — should migrate to v2
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let records = try store.query(AuditQuery())
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].seq, 1)
        XCTAssertEqual(records[0].event.keyFingerprint, "SHA256:test")

        // Verify epochs table exists and user_version is 2
        let epoch = AuditEpoch(
            epochID: Data(repeating: 0x01, count: 16),
            keyID: "testkeyid",
            epk: Data(repeating: 0x02, count: 65),
            wrappedDEK: Data(repeating: 0x03, count: 48)
        )
        XCTAssertNoThrow(try store.insertEpoch(epoch))
        let retrieved = try store.epoch(id: epoch.epochID)
        XCTAssertEqual(retrieved, epoch)
    }

    func test_008_T3_epochRoundTrip() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let epochID = AuditCrypto.newEpochID()
        let epoch = AuditEpoch(
            epochID: epochID,
            keyID: "key1234567890123",
            epk: Data(repeating: 0xAA, count: 65),
            wrappedDEK: Data(repeating: 0xBB, count: 60),
            created: Date(timeIntervalSince1970: 1_700_000_100)
        )

        try store.insertEpoch(epoch)

        let fetched = try store.epoch(id: epochID)
        XCTAssertEqual(fetched, epoch)

        let allEpochs = try store.epochs()
        XCTAssertEqual(allEpochs.count, 1)
        XCTAssertEqual(allEpochs.first, epoch)

        // Update wrap
        let newEpk = Data(repeating: 0xCC, count: 65)
        let newWrapped = Data(repeating: 0xDD, count: 60)
        let newKeyID = "newkeyid98765432"
        try store.updateEpochWrap(id: epochID, keyID: newKeyID, epk: newEpk, wrappedDEK: newWrapped)

        let updated = try store.epoch(id: epochID)
        XCTAssertEqual(updated?.keyID, newKeyID)
        XCTAssertEqual(updated?.epk, newEpk)
        XCTAssertEqual(updated?.wrappedDEK, newWrapped)
    }

    func test_008_T3_replaceSensitiveIsConditional() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "legacy_label", host: "legacy_host")
        )
        let seq = try store.insert(event)

        let legacyRows = try store.legacyPlaintextRows(limit: 10)
        XCTAssertEqual(legacyRows.count, 1)
        XCTAssertEqual(legacyRows[0].seq, seq)
        XCTAssertEqual(legacyRows[0].event.sensitive.keyLabel, "legacy_label")

        let sealedBlob = Data([0x01, 0x02, 0x03, 0x04])
        // First replace: expectedFormat = 0, newFormat = 1 -> true
        let replacedFirst = try store.replaceSensitive(seq: seq, expectedFormat: 0, newFormat: 1, blob: sealedBlob)
        XCTAssertTrue(replacedFirst)

        // Second replace with expectedFormat = 0 -> false (already format 1)
        let replacedSecond = try store.replaceSensitive(seq: seq, expectedFormat: 0, newFormat: 1, blob: sealedBlob)
        XCTAssertFalse(replacedSecond)

        // Legacy rows should now be empty
        let remainingLegacy = try store.legacyPlaintextRows(limit: 10)
        XCTAssertTrue(remainingLegacy.isEmpty)

        // Query row directly
        let records = try store.query(AuditQuery())
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].sensitiveFormat, 1)
        XCTAssertEqual(records[0].sealedSensitive, sealedBlob)
    }

    func test_008_AC1_rawFileHasNoPlaintext() throws {
        let store = try AuditStore(url: dbURL)

        let secretLabel = "super_classified_key_label_v2"
        let secretPath = "/very/private/daemon/path"
        let secretHost = "super-secret.enterprise.internal"

        let sensitive = AuditSensitive(
            keyLabel: secretLabel,
            processChain: [AuditProcess(executablePath: secretPath, pid: 100)],
            host: secretHost
        )

        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: sensitive
        )
        let aad = AuditCrypto.rowAAD(eventID: event.id, time: event.time, type: event.type, fingerprint: event.keyFingerprint)
        let blob = try AuditCrypto.sealRow(sensitive, dek: dek, epochID: epochID, aad: aad)

        _ = try store.insert(event, sensitiveFormat: 1, sensitiveBlob: blob)
        try store.checkpoint()
        store.close()

        let fileData = try Data(contentsOf: dbURL)
        func containsSubdata(_ data: Data, target: Data) -> Bool {
            data.range(of: target) != nil
        }

        XCTAssertFalse(containsSubdata(fileData, target: Data(secretLabel.utf8)))
        XCTAssertFalse(containsSubdata(fileData, target: Data(secretPath.utf8)))
        XCTAssertFalse(containsSubdata(fileData, target: Data(secretHost.utf8)))
    }
}
