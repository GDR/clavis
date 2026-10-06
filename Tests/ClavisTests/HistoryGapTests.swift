import SQLite3
import XCTest
@testable import ClavisCore
@testable import Clavis

@MainActor
final class HistoryGapTests: ClavisBaseTestCase {

    private func createTestStore() throws -> (store: AuditStore, dbURL: URL) {
        let dbURL = testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db")
        let store = try AuditStore(url: dbURL)
        return (store, dbURL)
    }

    private func executeSQL(on dbURL: URL, _ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(dbURL.path, &db) == SQLITE_OK else {
            throw AuditStoreError.openFailed(sqlite3_errcode(db))
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw AuditStoreError.stepFailed(sqlite3_errcode(db))
        }
    }

    func test_007_AC4_gapIsFlagged() async throws {
        let (store, dbURL) = try createTestStore()
        defer { store.close() }

        // Insert 5 events (seq 1..5)
        for i in 1...5 {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            _ = try store.insert(event)
        }

        // Delete row 3 to create a gap between 4 and 2
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq = 3;")

        let viewModel = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil })
        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 4)
        XCTAssertEqual(viewModel.items.count, 5)

        guard case .record(let r5) = viewModel.items[0],
              case .record(let r4) = viewModel.items[1],
              case .gap(let fromSeq, let toSeq, let count) = viewModel.items[2],
              case .record(let r2) = viewModel.items[3],
              case .record(let r1) = viewModel.items[4] else {
            XCTFail("Unexpected items layout: \(viewModel.items)")
            return
        }

        XCTAssertEqual(r5.seq, 5)
        XCTAssertEqual(r4.seq, 4)
        XCTAssertEqual(fromSeq, 3)
        XCTAssertEqual(toSeq, 3)
        XCTAssertEqual(count, 1)
        XCTAssertEqual(r2.seq, 2)
        XCTAssertEqual(r1.seq, 1)
        XCTAssertEqual(viewModel.items[2].id, "gap-3-3")

        // Also test multi-entry gap: delete seq 2 as well
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq = 2;")
        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 3)
        XCTAssertEqual(viewModel.items.count, 4)
        if case .gap(let from, let to, let cnt) = viewModel.items[2] {
            XCTAssertEqual(from, 2)
            XCTAssertEqual(to, 3)
            XCTAssertEqual(cnt, 2)
        } else {
            XCTFail("Expected gap at index 2")
        }
    }

    func test_007_AC4_prunedRangeNotFlagged() async throws {
        let (store, dbURL) = try createTestStore()
        defer { store.close() }

        // Insert 6 events (seq 1..6)
        for i in 1...6 {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            _ = try store.insert(event)
        }

        // Simulate retention pruning: delete rows 1..3 and set pruned_through_seq = 3
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq <= 3;")
        try executeSQL(on: dbURL, "INSERT OR REPLACE INTO meta (key, value) VALUES ('pruned_through_seq', '3');")

        let viewModel = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil })
        await viewModel.reload().value

        // Remaining records in DB: 6, 5, 4. Since none are missing between 6, 5, 4,
        // and 1..3 are pruned (seq <= 3), no gap is flagged.
        XCTAssertEqual(viewModel.records.count, 3)
        XCTAssertEqual(viewModel.items.count, 3)
        for item in viewModel.items {
            if case .gap = item {
                XCTFail("Pruned range must not produce a gap item")
            }
        }

        // Now delete seq 5 (so rows 6 and 4 remain).
        // seq 4 > pruned_through_seq (4 > 3), so gap 5..5 MUST be flagged!
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq = 5;")
        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 2)
        XCTAssertEqual(viewModel.items.count, 3)
        if case .gap(let from, let to, let cnt) = viewModel.items[1] {
            XCTAssertEqual(from, 5)
            XCTAssertEqual(to, 5)
            XCTAssertEqual(cnt, 1)
        } else {
            XCTFail("Expected gap at index 1")
        }

        // Unit test computeItems with adjacent pair touching pruned boundary:
        // If records are [10, 3] and prunedThroughSeq is 3:
        // next.seq is 3, 3 > 3 is false, so no gap flagged.
        let records = [
            AuditRecord(seq: 10, event: AuditEvent(type: .signature, result: .allowed)),
            AuditRecord(seq: 3, event: AuditEvent(type: .signature, result: .allowed))
        ]
        let items = HistoryViewModel.computeItems(from: records, prunedThroughSeq: 3, hasFilters: false)
        XCTAssertEqual(items.count, 2)
        XCTAssertFalse(items.contains { $0.isGap })
    }

    func test_007_AC4_filteredViewShowsNoGaps() async throws {
        let (store, dbURL) = try createTestStore()
        defer { store.close() }

        for i in 1...5 {
            let event = AuditEvent(
                type: .signature,
                result: i % 2 == 0 ? .denied : .allowed,
                keyFingerprint: "SHA256:key\(i)"
            )
            _ = try store.insert(event)
        }

        // Delete row 3
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq = 3;")

        let viewModel = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil })

        // 1. Without filters: gap is flagged
        await viewModel.reload().value
        XCTAssertTrue(viewModel.items.contains { $0.isGap })

        // 2. Filter by keyFingerprint
        viewModel.query.keyFingerprint = "SHA256:key1"
        await viewModel.reload().value
        XCTAssertFalse(viewModel.items.contains { $0.isGap })
        viewModel.query.keyFingerprint = nil

        // 3. Filter by result
        viewModel.query.results = [.allowed]
        await viewModel.reload().value
        XCTAssertFalse(viewModel.items.contains { $0.isGap })
        viewModel.query.results = []

        // 4. Filter by type
        viewModel.query.types = [.signature]
        await viewModel.reload().value
        XCTAssertFalse(viewModel.items.contains { $0.isGap })
        viewModel.query.types = []

        // 5. Filter by keyKind
        viewModel.query.keyKind = .personal
        await viewModel.reload().value
        XCTAssertFalse(viewModel.items.contains { $0.isGap })
        viewModel.query.keyKind = nil

        // 6. Filter by sessionID
        viewModel.query.sessionID = "test-session"
        await viewModel.reload().value
        XCTAssertFalse(viewModel.items.contains { $0.isGap })
        viewModel.query.sessionID = nil

        // 7. Time range filter (only from / to): gap SHOULD still be flagged!
        viewModel.query.from = Date().addingTimeInterval(-3600)
        await viewModel.reload().value
        XCTAssertTrue(viewModel.items.contains { $0.isGap })
    }
}
