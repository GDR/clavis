import XCTest
import SQLite3
@testable import ClavisCore

final class AuditStoreTests: ClavisBaseTestCase {
    private var testDirURL: URL!
    private var dbURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testDirURL = testRootURL.appendingPathComponent("audit-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        dbURL = testDirURL.appendingPathComponent("audit.db")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: testDirURL)
        try super.tearDownWithError()
    }

    func test_002_AC6_eventsPersistAcrossReopen() throws {
        let store1 = try AuditStore(url: dbURL)
        let event1 = AuditEvent(type: .signature, result: .allowed, reason: .viaPrompt, keyFingerprint: "SHA256:key1")
        let event2 = AuditEvent(type: .signature, result: .denied, reason: .unknownKey, keyFingerprint: "SHA256:key2")
        let event3 = AuditEvent(type: .lock, result: .info, reason: .lockNow)

        let seq1 = try store1.insert(event1)
        let seq2 = try store1.insert(event2)
        let seq3 = try store1.insert(event3)
        store1.close()

        let store2 = try AuditStore(url: dbURL)
        defer { store2.close() }

        let records = try store2.query(AuditQuery(limit: 10))
        XCTAssertEqual(records.count, 3)
        // Newest first
        XCTAssertEqual(records[0].seq, seq3)
        XCTAssertEqual(records[0].event.type, .lock)
        XCTAssertEqual(records[1].seq, seq2)
        XCTAssertEqual(records[1].event.type, .signature)
        XCTAssertEqual(records[1].event.result, .denied)
        XCTAssertEqual(records[2].seq, seq1)
        XCTAssertEqual(records[2].event.seqOrFingerprintMatch("SHA256:key1"), true)
    }

    func test_002_T2_seqIsMonotonicAcrossTwoStores() throws {
        let store1 = try AuditStore(url: dbURL)
        defer { store1.close() }
        let store2 = try AuditStore(url: dbURL)
        defer { store2.close() }

        var seqs: [Int64] = []
        for i in 0..<10 {
            let s1 = try store1.insert(AuditEvent(type: .signature, result: .allowed, sessionID: "s1-\(i)"))
            seqs.append(s1)
            let s2 = try store2.insert(AuditEvent(type: .signature, result: .allowed, sessionID: "s2-\(i)"))
            seqs.append(s2)
        }

        XCTAssertEqual(seqs.count, 20)
        for i in 1..<seqs.count {
            XCTAssertGreaterThan(seqs[i], seqs[i - 1])
        }
        XCTAssertEqual(Set(seqs).count, 20)
    }

    func test_002_T2_fileIsOwnerOnly() throws {
        let store = try AuditStore(url: dbURL)
        try store.insert(AuditEvent(type: .signature, result: .allowed))
        store.close()

        var info = stat()
        XCTAssertEqual(lstat(dbURL.path, &info), 0)
        let mode = info.st_mode & 0o777
        XCTAssertEqual(mode, 0o600)
    }

    func test_002_T2_refusesSymlink() throws {
        let realFile = testDirURL.appendingPathComponent("real.db")
        try Data().write(to: realFile)
        let symlinkURL = testDirURL.appendingPathComponent("symlink.db")
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: realFile)

        XCTAssertThrowsError(try AuditStore(url: symlinkURL)) { error in
            XCTAssertEqual(error as? AuditStoreError, AuditStoreError.insecureLocation)
        }
    }

    func test_002_T2_refusesSchemaFromFuture() throws {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(dbURL.path, &db), SQLITE_OK)
        XCTAssertEqual(sqlite3_exec(db, "PRAGMA user_version = 99;", nil, nil, nil), SQLITE_OK)
        sqlite3_close(db)

        XCTAssertThrowsError(try AuditStore(url: dbURL)) { error in
            XCTAssertEqual(error as? AuditStoreError, AuditStoreError.schemaTooNew(99))
        }
    }

    func test_002_AC3_filtersByResultTypeAndTime() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let baseDate = Date(timeIntervalSince1970: 1_700_000_000)
        let event1 = AuditEvent(time: baseDate, type: .signature, result: .allowed)
        let event2 = AuditEvent(time: baseDate.addingTimeInterval(10), type: .signature, result: .denied)
        let event3 = AuditEvent(time: baseDate.addingTimeInterval(20), type: .lock, result: .info)
        let event4 = AuditEvent(time: baseDate.addingTimeInterval(30), type: .keyCreate, result: .allowed)

        let seq1 = try store.insert(event1)
        let seq2 = try store.insert(event2)
        let seq3 = try store.insert(event3)
        let seq4 = try store.insert(event4)

        // Filter by result: .allowed
        let allowedRecords = try store.query(AuditQuery(results: [.allowed]))
        XCTAssertEqual(allowedRecords.map(\.seq), [seq4, seq1])

        // Filter by type: .signature
        let signatureRecords = try store.query(AuditQuery(types: [.signature]))
        XCTAssertEqual(signatureRecords.map(\.seq), [seq2, seq1])

        // Filter by time range
        let timeRecords = try store.query(AuditQuery(
            from: baseDate.addingTimeInterval(5),
            to: baseDate.addingTimeInterval(25)
        ))
        XCTAssertEqual(timeRecords.map(\.seq), [seq3, seq2])

        // Combined filter
        let combinedRecords = try store.query(AuditQuery(
            from: baseDate.addingTimeInterval(5),
            types: [.signature],
            results: [.denied]
        ))
        XCTAssertEqual(combinedRecords.map(\.seq), [seq2])
    }

    func test_002_AC4_filtersByKeyFingerprint() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let fpA = "SHA256:fingerprintA"
        let fpB = "SHA256:fingerprintB"

        let seqA1 = try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: fpA))
        _ = try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: fpB))
        let seqA2 = try store.insert(AuditEvent(type: .signature, result: .denied, keyFingerprint: fpA))

        let resultsA = try store.query(AuditQuery(keyFingerprint: fpA))
        XCTAssertEqual(resultsA.map(\.seq), [seqA2, seqA1])
    }

    func test_002_T2_sqlInjectionInFingerprintIsInert() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: "valid"))

        let malicious = "x' OR '1'='1"
        let results = try store.query(AuditQuery(keyFingerprint: malicious))
        XCTAssertTrue(results.isEmpty)
        XCTAssertEqual(try store.count(), 1)
    }

    func test_002_T2_pruneRecordsPrunedThroughSeq() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let baseDate = Date(timeIntervalSince1970: 1_700_000_000)
        var seqs: [Int64] = []
        for i in 0..<10 {
            let s = try store.insert(AuditEvent(time: baseDate.addingTimeInterval(Double(i * 10)), type: .signature, result: .allowed))
            seqs.append(s)
        }

        XCTAssertEqual(try store.count(), 10)

        // Prune older than baseDate + 45s (should delete items with time <= baseDate + 40, i.e. 5 rows: seqs[0]..seqs[4])
        let deleted = try store.prune(olderThan: baseDate.addingTimeInterval(45), maxRows: 100)
        XCTAssertEqual(deleted, 5)
        XCTAssertEqual(try store.count(), 5)

        let metaPruned = try store.meta("pruned_through_seq")
        XCTAssertEqual(metaPruned, String(seqs[4]))
    }

    func test_002_T2_unknownSensitiveFormatDecodesEmpty() throws {
        let store = try AuditStore(url: dbURL)

        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(dbURL.path, &db), SQLITE_OK)
        let insertSQL = """
        INSERT INTO events (
            event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
        ) VALUES ('\(UUID().uuidString)', 1700000000.0, 'signature', 'allowed', NULL, NULL, NULL, NULL, 1, 7, X'deadbeef');
        """
        XCTAssertEqual(sqlite3_exec(db, insertSQL, nil, nil, nil), SQLITE_OK)
        sqlite3_close(db)

        let records = try store.query(AuditQuery(limit: 1))
        store.close()

        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].event.sensitive, AuditSensitive(keyLabel: nil, processChain: [], host: nil))
    }
}

private extension AuditEvent {
    func seqOrFingerprintMatch(_ fp: String) -> Bool {
        keyFingerprint == fp
    }
}
