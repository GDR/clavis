import Testing
import Foundation
import SQLite3
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct AuditStoreTests {

    private func makeTestDB(fixture: ClavisTestFixture) throws -> URL {
        let testDirURL = fixture.testRootURL.appendingPathComponent("audit-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        return testDirURL.appendingPathComponent("audit.db")
    }

    @Test func test_002_AC6_eventsPersistAcrossReopen() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        #expect(records.count == 3)
        // Newest first
        #expect(records[0].seq == seq3)
        #expect(records[0].event.type == .lock)
        #expect(records[1].seq == seq2)
        #expect(records[1].event.type == .signature)
        #expect(records[1].event.result == .denied)
        #expect(records[2].seq == seq1)
        #expect(records[2].event.seqOrFingerprintMatch("SHA256:key1") == true)
    }

    @Test func test_002_T2_seqIsMonotonicAcrossTwoStores() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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

        #expect(seqs.count == 20)
        for i in 1..<seqs.count {
            #expect(seqs[i] > seqs[i - 1])
        }
        #expect(Set(seqs).count == 20)
    }

    @Test func test_002_T2_fileIsOwnerOnly() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        _ = try store.insert(AuditEvent(type: .signature, result: .allowed))
        store.close()

        var info = stat()
        #expect(lstat(dbURL.path, &info) == 0)
        let mode = info.st_mode & 0o777
        #expect(mode == 0o600)
    }

    @Test func test_002_T2_refusesSymlink() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testDirURL = fixture.testRootURL.appendingPathComponent("audit-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)

        let realFile = testDirURL.appendingPathComponent("real.db")
        try Data().write(to: realFile)
        let symlinkURL = testDirURL.appendingPathComponent("symlink.db")
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: realFile)

        #expect {
            try AuditStore(url: symlinkURL)
        } throws: { error in
            error as? AuditStoreError == AuditStoreError.insecureLocation
        }
    }

    @Test func test_002_T2_refusesSchemaFromFuture() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        var db: OpaquePointer?
        #expect(sqlite3_open(dbURL.path, &db) == SQLITE_OK)
        #expect(sqlite3_exec(db, "PRAGMA user_version = 99;", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        #expect {
            try AuditStore(url: dbURL)
        } throws: { error in
            error as? AuditStoreError == AuditStoreError.schemaTooNew(99)
        }
    }

    @Test func test_002_AC3_filtersByResultTypeAndTime() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        #expect(allowedRecords.map(\.seq) == [seq4, seq1])

        // Filter by type: .signature
        let signatureRecords = try store.query(AuditQuery(types: [.signature]))
        #expect(signatureRecords.map(\.seq) == [seq2, seq1])

        // Filter by time range
        let timeRecords = try store.query(AuditQuery(
            from: baseDate.addingTimeInterval(5),
            to: baseDate.addingTimeInterval(25)
        ))
        #expect(timeRecords.map(\.seq) == [seq3, seq2])

        // Combined filter
        let combinedRecords = try store.query(AuditQuery(
            from: baseDate.addingTimeInterval(5),
            types: [.signature],
            results: [.denied]
        ))
        #expect(combinedRecords.map(\.seq) == [seq2])
    }

    @Test func test_002_AC4_filtersByKeyFingerprint() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let fpA = "SHA256:fingerprintA"
        let fpB = "SHA256:fingerprintB"

        let seqA1 = try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: fpA))
        _ = try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: fpB))
        let seqA2 = try store.insert(AuditEvent(type: .signature, result: .denied, keyFingerprint: fpA))

        let resultsA = try store.query(AuditQuery(keyFingerprint: fpA))
        #expect(resultsA.map(\.seq) == [seqA2, seqA1])
    }

    @Test func test_002_T2_sqlInjectionInFingerprintIsInert() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        _ = try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: "valid"))

        let malicious = "x' OR '1'='1"
        let results = try store.query(AuditQuery(keyFingerprint: malicious))
        #expect(results.isEmpty)
        #expect(try store.count() == 1)
    }

    @Test func test_002_T2_pruneRecordsPrunedThroughSeq() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let baseDate = Date(timeIntervalSince1970: 1_700_000_000)
        var seqs: [Int64] = []
        for i in 0..<10 {
            let s = try store.insert(AuditEvent(time: baseDate.addingTimeInterval(Double(i * 10)), type: .signature, result: .allowed))
            seqs.append(s)
        }

        #expect(try store.count() == 10)

        // Prune older than baseDate + 45s (should delete items with time <= baseDate + 40, i.e. 5 rows: seqs[0]..seqs[4])
        let deleted = try store.prune(olderThan: baseDate.addingTimeInterval(45), maxRows: 100)
        #expect(deleted == 5)
        #expect(try store.count() == 5)

        let metaPruned = try store.meta("pruned_through_seq")
        #expect(metaPruned == String(seqs[4]))
    }

    @Test func test_002_T2_unknownSensitiveFormatDecodesEmpty() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)

        var db: OpaquePointer?
        #expect(sqlite3_open(dbURL.path, &db) == SQLITE_OK)
        let insertSQL = """
        INSERT INTO events (
            event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
        ) VALUES ('\(UUID().uuidString)', 1700000000.0, 'signature', 'allowed', NULL, NULL, NULL, NULL, 1, 7, X'deadbeef');
        """
        #expect(sqlite3_exec(db, insertSQL, nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let records = try store.query(AuditQuery(limit: 1))
        store.close()

        #expect(records.count == 1)
        #expect(records[0].event.sensitive == AuditSensitive(keyLabel: nil, processChain: [], host: nil))
    }
}

private extension AuditEvent {
    func seqOrFingerprintMatch(_ fp: String) -> Bool {
        keyFingerprint == fp
    }
}
