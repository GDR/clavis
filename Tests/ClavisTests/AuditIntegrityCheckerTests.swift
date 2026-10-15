import Testing
import Foundation
import SQLite3
@testable import ClavisCore

@Suite struct AuditIntegrityCheckerTests {

    private func makeTestDB(fixture: ClavisTestFixture) throws -> URL {
        let testDirURL = fixture.testRootURL.appendingPathComponent("checker-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        return testDirURL.appendingPathComponent("audit.db")
    }

    private func executeSQL(_ sql: String, dbURL: URL) throws {
        var db: OpaquePointer?
        guard sqlite3_open(dbURL.path, &db) == SQLITE_OK else {
            throw AuditStoreError.openFailed(sqlite3_errcode(db))
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw AuditStoreError.stepFailed(sqlite3_errcode(db))
        }
    }

    @Test func test_007_AC1_intactHistoryIsOK() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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

        #expect(report.status == .ok)
        #expect(report.missingRows.isEmpty)
        #expect(report.inconsistentRows.isEmpty)
        #expect(report.unwitnessedRows.isEmpty)
        #expect(!report.truncatedTail)
        #expect(report.gapsOutsideWindow.isEmpty)
        #expect(report.checkedRows == 5)
    }

    @Test func test_007_AC2_deletedRowIsReportedWithTime() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        try executeSQL("DELETE FROM events WHERE seq = 3;", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(report.status == .problems)
        #expect(report.missingRows.count == 1)
        #expect(report.missingRows[0].seq == 3)
        #expect(report.missingRows[0].loggedAt == loggedTime)
        #expect(report.inconsistentRows.isEmpty)
    }

    @Test func test_007_AC3_alteredRowIsInconsistent() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        try executeSQL("UPDATE events SET result = 'denied' WHERE seq = 2;", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(report.status == .problems)
        #expect(report.inconsistentRows == [2])
        #expect(report.missingRows.isEmpty)
    }

    @Test func test_007_AC3_alteredSealedBlobIsInconsistent() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        try executeSQL("UPDATE events SET sensitive = X'ffee1122' WHERE seq = \(seq);", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(report.status == .problems)
        #expect(report.inconsistentRows == [seq])
        #expect(report.missingRows.isEmpty)
    }

    @Test func test_007_T3_tailTruncationDetected() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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

        #expect(report.status == .problems)
        #expect(report.truncatedTail)
        #expect(report.missingRows.map(\.seq) == [4, 5])
    }

    @Test func test_007_T3_prunedRowsAreIgnored() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        var witnessList: [AuditWitnessEntry] = []
        let now = Date()

        // Insert 15 rows: 1..10 in the past (older than 7-day check window), 11..15 recent
        for i in 1...15 {
            let eventTime = (i <= 10) ? now.addingTimeInterval(-800_000 + Double(i)) : now.addingTimeInterval(Double(i))
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
        let prunedCount = try store.prune(olderThan: now.addingTimeInterval(-700_000), maxRows: 100)
        #expect(prunedCount == 10)
        #expect(try store.meta("pruned_through_seq") == "10")

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(500),
            days: 7
        )

        #expect(report.status == .ok)
        #expect(report.missingRows.isEmpty)
        #expect(report.inconsistentRows.isEmpty)
        #expect(!report.truncatedTail)
    }

    @Test func test_007_T3_unwitnessedIsWarningOnly() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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
        #expect(report.status == .ok)
        #expect(report.unwitnessedRows == [5])
        #expect(report.missingRows.isEmpty)
        #expect(report.inconsistentRows.isEmpty)
    }

    @Test func test_007_T3_unavailableWitnessIsNotOK() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .unavailable("log show failed"),
            now: Date(),
            days: 7
        )

        #expect(report.status == .unavailable("log show failed"))
    }

    @Test func test_007_T4_parseHistoryCheckArgs() throws {
        // Defaults
        let defaultArgs = try CLIService.parseHistoryCheckArgs(["history", "check"])
        #expect(defaultArgs == HistoryCheckArgs(days: 7, dbPath: nil))

        let fullArgv = try CLIService.parseHistoryCheckArgs(["clavis", "history", "check"])
        #expect(fullArgv == HistoryCheckArgs(days: 7, dbPath: nil))

        // Custom days
        let customDays = try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "14"])
        #expect(customDays == HistoryCheckArgs(days: 14, dbPath: nil))

        // Custom db
        let customDb = try CLIService.parseHistoryCheckArgs(["history", "check", "--db", "/tmp/copy.db"])
        #expect(customDb == HistoryCheckArgs(days: 7, dbPath: "/tmp/copy.db"))

        // Both in either order
        let both1 = try CLIService.parseHistoryCheckArgs(["clavis", "history", "check", "--days", "30", "--db", "/tmp/audit.db"])
        #expect(both1 == HistoryCheckArgs(days: 30, dbPath: "/tmp/audit.db"))

        let both2 = try CLIService.parseHistoryCheckArgs(["history", "check", "--db", "/tmp/audit.db", "--days", "1"])
        #expect(both2 == HistoryCheckArgs(days: 1, dbPath: "/tmp/audit.db"))

        // Errors: invalid days (> 30, <= 0, non-int)
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "31"])
        }
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "0"])
        }
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "-5"])
        }
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--days", "seven"])
        }

        // Errors: missing argument values
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--days"])
        }
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--db"])
        }

        // Errors: unknown argument
        #expect(throws: (any Error).self) {
            try CLIService.parseHistoryCheckArgs(["history", "check", "--unknown"])
        }

        // Test format report exit codes
        let okReport = AuditIntegrityReport(status: .ok, checkedFrom: Date(), checkedRows: 10)
        let (okOut, okCode) = CLIService.formatHistoryCheckReport(okReport)
        #expect(okCode == 0)
        #expect(okOut.contains("History integrity check: OK"))

        let probReport = AuditIntegrityReport(
            status: .problems,
            missingRows: [(seq: 3, loggedAt: Date())],
            inconsistentRows: [4],
            truncatedTail: true,
            checkedFrom: Date(),
            checkedRows: 10
        )
        let (probOut, probCode) = CLIService.formatHistoryCheckReport(probReport)
        #expect(probCode == 2)
        #expect(probOut.contains("PROBLEMS DETECTED"))
        #expect(probOut.contains("Missing: seq 3"))
        #expect(probOut.contains("Inconsistent: seq 4"))
        #expect(probOut.contains("Truncated tail"))

        let unavailReport = AuditIntegrityReport(status: .unavailable("log show failed"), checkedFrom: Date())
        let (unavailOut, unavailCode) = CLIService.formatHistoryCheckReport(unavailReport)
        #expect(unavailCode == 1)
        #expect(unavailOut.contains("UNAVAILABLE"))
    }

    @Test func test_007_T4_readOnlyAuditStore() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        // Create store normally
        let store = try AuditStore(url: dbURL)
        let event = AuditEvent(type: .signature, result: .allowed)
        _ = try store.insert(event)
        store.close()

        // Open read-only
        let roStore = try AuditStore(url: dbURL, readOnly: true)
        defer { roStore.close() }

        let records = try roStore.records(fromSeq: 1)
        #expect(records.count == 1)
        #expect(records[0].seq == 1)
    }

    @Test func test_F08_prunedThroughSeqCannotHideMissingRowsWithinCheckWindow() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

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

        // Delete row 3 from the database (simulating tampering)
        try executeSQL("DELETE FROM events WHERE seq = 3;", dbURL: dbURL)

        // Artificially update meta.pruned_through_seq to 3 to conceal the deletion
        try executeSQL("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '3');", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries(witnessList),
            now: now.addingTimeInterval(100),
            days: 7
        )

        // The check must detect row 3 as missing because its witness timestamp falls within the 7-day check window
        #expect(report.status == .problems)
        #expect(report.missingRows.count == 1)
        #expect(report.missingRows.first?.seq == 3)
    }

    @Test func test_F08_prunedThroughSeqInt64MaxDoesNotCrash() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let now = Date()
        let event = AuditEvent(time: now, type: .signature, result: .allowed, keyFingerprint: "SHA256:key1")
        let seq = try store.insert(event)
        let record = try #require((try store.records(fromSeq: seq)).first)
        let digest = AuditWitness.digest(for: record)
        let witness = AuditWitnessEntry(
            seq: seq,
            eventID: event.id,
            type: event.type.rawValue,
            result: event.result.rawValue,
            fingerprint: event.keyFingerprint,
            digest: digest,
            loggedAt: event.time
        )

        // Set pruned_through_seq to Int64.max to test integer overflow boundary condition
        try executeSQL("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '\(Int64.max)');", dbURL: dbURL)

        // Must not trap / crash with SIGTRAP on integer overflow
        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(report.status == AuditIntegrityReport.Status.ok)
        #expect(!report.truncatedTail)
        #expect(report.missingRows.isEmpty)
    }

    @Test func test_F08_negativePrunedThroughSeqDoesNotGenerateSpuriousGaps() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let now = Date()
        let event = AuditEvent(time: now, type: .signature, result: .allowed, keyFingerprint: "SHA256:key1")
        let seq = try store.insert(event)
        let record = try #require((try store.records(fromSeq: seq)).first)
        let digest = AuditWitness.digest(for: record)
        let witness = AuditWitnessEntry(
            seq: seq,
            eventID: event.id,
            type: event.type.rawValue,
            result: event.result.rawValue,
            fingerprint: event.keyFingerprint,
            digest: digest,
            loggedAt: event.time
        )

        // Set negative pruned_through_seq
        try executeSQL("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '-1');", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(report.status == AuditIntegrityReport.Status.ok)
        #expect(report.gapsOutsideWindow.isEmpty, "Spurious gaps generated: \(report.gapsOutsideWindow)")
    }

    @Test func test_F08_legitimatePruningDoesNotTriggerTruncatedTail() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let now = Date()
        let pastTime = now.addingTimeInterval(-800_000)
        let event = AuditEvent(time: pastTime, type: .signature, result: .allowed, keyFingerprint: "SHA256:key1")
        let seq = try store.insert(event)
        let record = try #require((try store.records(fromSeq: seq)).first)
        let digest = AuditWitness.digest(for: record)
        let witness = AuditWitnessEntry(
            seq: seq,
            eventID: event.id,
            type: event.type.rawValue,
            result: event.result.rawValue,
            fingerprint: event.keyFingerprint,
            digest: digest,
            loggedAt: pastTime
        )

        // Legitimate pruning deletes row 1 and advances pruned_through_seq
        try executeSQL("DELETE FROM events WHERE seq = 1;", dbURL: dbURL)
        try executeSQL("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '1');", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now,
            days: 7
        )

        // Should be .ok, truncatedTail should be false because seq 1 <= pruned
        #expect(report.status == AuditIntegrityReport.Status.ok)
        #expect(!report.truncatedTail)
        #expect(report.missingRows.isEmpty)
    }

    @Test func test_F08_gapsOutsideWindowExpectedSeqDoesNotStartBelowOne() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        let store = try AuditStore(url: dbURL)
        defer { store.close() }

        let now = Date()
        for i in 1...5 {
            let event = AuditEvent(time: now.addingTimeInterval(Double(i) * 10), type: .signature, result: .allowed, keyFingerprint: "SHA256:key\(i)")
            _ = try store.insert(event)
        }
        try executeSQL("DELETE FROM events WHERE seq < 5;", dbURL: dbURL)

        let record = try #require((try store.records(fromSeq: 5)).first)
        let digest = AuditWitness.digest(for: record)
        let witness = AuditWitnessEntry(
            seq: 5,
            eventID: record.event.id,
            type: record.event.type.rawValue,
            result: record.event.result.rawValue,
            fingerprint: record.event.keyFingerprint,
            digest: digest,
            loggedAt: record.event.time
        )

        // Set negative pruned_through_seq
        try executeSQL("INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '-5');", dbURL: dbURL)

        let report = try AuditIntegrityChecker.check(
            store: store,
            witness: .entries([witness]),
            now: now.addingTimeInterval(100),
            days: 7
        )

        #expect(!report.gapsOutsideWindow.isEmpty)
        for gap in report.gapsOutsideWindow {
            #expect(gap.lowerBound >= 1, "Gap lower bound cannot start below 1: \(gap)")
        }
    }
}
