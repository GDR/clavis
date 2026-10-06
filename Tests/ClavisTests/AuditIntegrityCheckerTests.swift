import SQLite3
import XCTest
@testable import ClavisCore

final class AuditIntegrityCheckerTests: ClavisBaseTestCase {
    private var testDirURL: URL!
    private var dbURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testDirURL = testRootURL.appendingPathComponent("checker-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        dbURL = testDirURL.appendingPathComponent("audit.db")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: testDirURL)
        try super.tearDownWithError()
    }

    private func executeSQL(_ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(dbURL.path, &db) == SQLITE_OK else {
            throw AuditStoreError.openFailed(sqlite3_errcode(db))
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw AuditStoreError.stepFailed(sqlite3_errcode(db))
        }
    }

    func test_007_AC1_intactHistoryIsOK() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        for i in 1...5 {
            let event = AuditEvent(
                time: now.addingTimeInterval(Double(i) * 10),
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            let digest = AuditWitness.digest(
                seq: seq,
                eventID: event.id,
                time: event.time,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                fingerprint: event.keyFingerprint,
                kind: event.keyKind?.rawValue,
                session: event.sessionID,
                count: event.count,
                sensitiveFormat: 2,
                sensitiveBlob: Data()
            )
            witnessList.append(AuditWitnessEntry(
                seq: seq,
                eventID: event.id,
                type: event.type.rawValue,
                result: event.result.rawValue,
                fingerprint: event.keyFingerprint,
                digest: digest,
                loggedAt: event.time
            ))
        }

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        XCTAssertEqual(report.status, .ok)
        XCTAssertTrue(report.missingRows.isEmpty)
        XCTAssertTrue(report.inconsistentRows.isEmpty)
        XCTAssertTrue(report.unwitnessedRows.isEmpty)
        XCTAssertFalse(report.truncatedTail)
        XCTAssertTrue(report.gapsOutsideWindow.isEmpty)
        XCTAssertEqual(report.checkedRows, 5)
    }

    func test_007_AC2_deletedRowIsReportedWithTime() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()
        let loggedTime = now.addingTimeInterval(30)

        for i in 1...5 {
            let event = AuditEvent(
                time: now.addingTimeInterval(Double(i) * 10),
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            let digest = AuditWitness.digest(
                seq: seq,
                eventID: event.id,
                time: event.time,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                fingerprint: event.keyFingerprint,
                kind: event.keyKind?.rawValue,
                session: event.sessionID,
                count: event.count,
                sensitiveFormat: 2,
                sensitiveBlob: Data()
            )
            witnessList.append(AuditWitnessEntry(
                seq: seq,
                eventID: event.id,
                type: event.type.rawValue,
                result: event.result.rawValue,
                fingerprint: event.keyFingerprint,
                digest: digest,
                loggedAt: (seq == 3) ? loggedTime : event.time
            ))
        }

        // Delete row 3 via C API
        try executeSQL("DELETE FROM events WHERE seq = 3;")

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        XCTAssertEqual(report.status, .problems)
        XCTAssertEqual(report.missingRows.count, 1)
        XCTAssertEqual(report.missingRows[0].seq, 3)
        XCTAssertEqual(report.missingRows[0].loggedAt, loggedTime)
        XCTAssertTrue(report.inconsistentRows.isEmpty)
    }

    func test_007_AC3_alteredRowIsInconsistent() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        for i in 1...4 {
            let event = AuditEvent(
                time: now.addingTimeInterval(Double(i) * 10),
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            let digest = AuditWitness.digest(
                seq: seq,
                eventID: event.id,
                time: event.time,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                fingerprint: event.keyFingerprint,
                kind: event.keyKind?.rawValue,
                session: event.sessionID,
                count: event.count,
                sensitiveFormat: 2,
                sensitiveBlob: Data()
            )
            witnessList.append(AuditWitnessEntry(
                seq: seq,
                eventID: event.id,
                type: event.type.rawValue,
                result: event.result.rawValue,
                fingerprint: event.keyFingerprint,
                digest: digest,
                loggedAt: event.time
            ))
        }

        // Alter row 2 result to denied
        try executeSQL("UPDATE events SET result = 'denied' WHERE seq = 2;")

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        XCTAssertEqual(report.status, .problems)
        XCTAssertEqual(report.inconsistentRows, [2])
        XCTAssertTrue(report.missingRows.isEmpty)
    }

    func test_007_AC3_alteredSealedBlobIsInconsistent() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let now = Date()
        let blob = Data([0xaa, 0xbb, 0xcc, 0xdd])
        let event = AuditEvent(
            time: now,
            type: .signature,
            result: .allowed,
            keyFingerprint: "SHA256:key1"
        )
        let seq = try store.insert(event, sensitiveFormat: 1, sensitiveBlob: blob)
        let digest = AuditWitness.digest(
            seq: seq,
            eventID: event.id,
            time: event.time,
            type: event.type.rawValue,
            result: event.result.rawValue,
            reason: event.reason?.rawValue,
            fingerprint: event.keyFingerprint,
            kind: event.keyKind?.rawValue,
            session: event.sessionID,
            count: event.count,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        )
        let witness = AuditWitnessEntry(
            seq: seq,
            eventID: event.id,
            type: event.type.rawValue,
            result: event.result.rawValue,
            fingerprint: event.keyFingerprint,
            digest: digest,
            loggedAt: event.time
        )

        // Alter the sealed sensitive blob in the database
        try executeSQL("UPDATE events SET sensitive = X'ffee1122' WHERE seq = \(seq);")

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now.addingTimeInterval(100),
            days: 7
        )

        XCTAssertEqual(report.status, .problems)
        XCTAssertEqual(report.inconsistentRows, [seq])
        XCTAssertTrue(report.missingRows.isEmpty)
    }

    func test_007_T3_tailTruncationDetected() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        for i in 1...5 {
            let event = AuditEvent(
                time: now.addingTimeInterval(Double(i) * 10),
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq: Int64 = Int64(i)
            if i <= 3 {
                _ = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            }
            let digest = AuditWitness.digest(
                seq: seq,
                eventID: event.id,
                time: event.time,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                fingerprint: event.keyFingerprint,
                kind: event.keyKind?.rawValue,
                session: event.sessionID,
                count: event.count,
                sensitiveFormat: 2,
                sensitiveBlob: Data()
            )
            witnessList.append(AuditWitnessEntry(
                seq: seq,
                eventID: event.id,
                type: event.type.rawValue,
                result: event.result.rawValue,
                fingerprint: event.keyFingerprint,
                digest: digest,
                loggedAt: event.time
            ))
        }

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        XCTAssertEqual(report.status, .problems)
        XCTAssertTrue(report.truncatedTail)
        XCTAssertEqual(report.missingRows.map(\.seq), [4, 5])
    }

    func test_007_T3_prunedRowsAreIgnored() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        // Insert 15 rows: 1..10 in the past, 11..15 recent
        for i in 1...15 {
            let eventTime = (i <= 10) ? now.addingTimeInterval(-100_000 + Double(i)) : now.addingTimeInterval(Double(i))
            let event = AuditEvent(
                time: eventTime,
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            let digest = AuditWitness.digest(
                seq: seq,
                eventID: event.id,
                time: event.time,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                fingerprint: event.keyFingerprint,
                kind: event.keyKind?.rawValue,
                session: event.sessionID,
                count: event.count,
                sensitiveFormat: 2,
                sensitiveBlob: Data()
            )
            witnessList.append(AuditWitnessEntry(
                seq: seq,
                eventID: event.id,
                type: event.type.rawValue,
                result: event.result.rawValue,
                fingerprint: event.keyFingerprint,
                digest: digest,
                loggedAt: event.time
            ))
        }

        // Prune rows older than cutoff (deletes rows 1..10, sets pruned_through_seq to 10)
        let prunedCount = try store.prune(olderThan: now.addingTimeInterval(-50_000), maxRows: 100)
        XCTAssertEqual(prunedCount, 10)
        XCTAssertEqual(try store.meta("pruned_through_seq"), "10")

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(500),
            days: 7
        )

        XCTAssertEqual(report.status, .ok)
        XCTAssertTrue(report.missingRows.isEmpty)
        XCTAssertTrue(report.inconsistentRows.isEmpty)
        XCTAssertFalse(report.truncatedTail)
    }

    func test_007_T3_unwitnessedIsWarningOnly() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        for i in 1...5 {
            let event = AuditEvent(
                time: now.addingTimeInterval(Double(i) * 10),
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            let seq = try store.insert(event, sensitiveFormat: 2, sensitiveBlob: Data())
            if i < 5 {
                let digest = AuditWitness.digest(
                    seq: seq,
                    eventID: event.id,
                    time: event.time,
                    type: event.type.rawValue,
                    result: event.result.rawValue,
                    reason: event.reason?.rawValue,
                    fingerprint: event.keyFingerprint,
                    kind: event.keyKind?.rawValue,
                    session: event.sessionID,
                    count: event.count,
                    sensitiveFormat: 2,
                    sensitiveBlob: Data()
                )
                witnessList.append(AuditWitnessEntry(
                    seq: seq,
                    eventID: event.id,
                    type: event.type.rawValue,
                    result: event.result.rawValue,
                    fingerprint: event.keyFingerprint,
                    digest: digest,
                    loggedAt: event.time
                ))
            }
        }

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        // Status is still .ok because unwitnessed is warning-only
        XCTAssertEqual(report.status, .ok)
        XCTAssertEqual(report.unwitnessedRows, [5])
        XCTAssertTrue(report.missingRows.isEmpty)
        XCTAssertTrue(report.inconsistentRows.isEmpty)
    }

    func test_007_T3_unavailableWitnessIsNotOK() throws {
        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .unavailable("log show failed"),
            now: Date(),
            days: 7
        )

        XCTAssertEqual(report.status, .unavailable("log show failed"))
    }

    func test_007_T4_parseHistoryCheckArgs() throws {
        // Defaults
        let defaultArgs = try CLIService.parseHistoryCheckArgs(["history", "check"])
        XCTAssertEqual(defaultArgs, HistoryCheckArgs(days: 7, dbPath: nil))

        let fullArgv = try CLIService.parseHistoryCheckArgs(["clavis", "history", "check"])
        XCTAssertEqual(fullArgv, HistoryCheckArgs(days: 7, dbPath: nil))

        // Custom days
        let customDays = try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "14"])
        XCTAssertEqual(customDays, HistoryCheckArgs(days: 14, dbPath: nil))

        // Custom db
        let customDb = try CLIService.parseHistoryCheckArgs(["history", "check", "--db", "/tmp/copy.db"])
        XCTAssertEqual(customDb, HistoryCheckArgs(days: 7, dbPath: "/tmp/copy.db"))

        // Both in either order
        let both1 = try CLIService.parseHistoryCheckArgs(["clavis", "history", "check", "--days", "30", "--db", "/tmp/audit.db"])
        XCTAssertEqual(both1, HistoryCheckArgs(days: 30, dbPath: "/tmp/audit.db"))

        let both2 = try CLIService.parseHistoryCheckArgs(["history", "check", "--db", "/tmp/audit.db", "--days", "1"])
        XCTAssertEqual(both2, HistoryCheckArgs(days: 1, dbPath: "/tmp/audit.db"))

        // Errors: invalid days (> 30, <= 0, non-int)
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "31"]))
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "0"]))
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "-5"]))
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "seven"]))

        // Errors: missing argument values
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--days"]))
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--db"]))

        // Errors: unknown argument
        XCTAssertThrowsError(try CLIService.parseHistoryCheckArgs(["history", "check", "--unknown"]))

        // Test format report exit codes
        let okReport = AuditIntegrityReport(status: .ok, checkedFrom: Date(), checkedRows: 10)
        let (okOut, okCode) = CLIService.formatHistoryCheckReport(okReport)
        XCTAssertEqual(okCode, 0)
        XCTAssertTrue(okOut.contains("History integrity check: OK"))

        let probReport = AuditIntegrityReport(
            status: .problems,
            missingRows: [(seq: 3, loggedAt: Date())],
            inconsistentRows: [4],
            truncatedTail: true,
            checkedFrom: Date(),
            checkedRows: 10
        )
        let (probOut, probCode) = CLIService.formatHistoryCheckReport(probReport)
        XCTAssertEqual(probCode, 2)
        XCTAssertTrue(probOut.contains("PROBLEMS DETECTED"))
        XCTAssertTrue(probOut.contains("Missing: seq 3"))
        XCTAssertTrue(probOut.contains("Inconsistent: seq 4"))
        XCTAssertTrue(probOut.contains("Truncated tail"))

        let unavailReport = AuditIntegrityReport(status: .unavailable("log show failed"), checkedFrom: Date())
        let (unavailOut, unavailCode) = CLIService.formatHistoryCheckReport(unavailReport)
        XCTAssertEqual(unavailCode, 1)
        XCTAssertTrue(unavailOut.contains("UNAVAILABLE"))
    }

    func test_007_T4_readOnlyAuditStore() throws {
        // Create store normally
        let store = try AuditStore(url: dbURL)
        let event = AuditEvent(type: .signature, result: .allowed)
        try store.insert(event)
        store.close()

        // Open read-only
        let roStore = try AuditStore(url: dbURL, readOnly: true)
        defer { roStore.close() }

        let records = try roStore.records(fromSeq: 1)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].seq, 1)
    }
}
