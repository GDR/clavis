import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct AuditStoreSortCursorTests {

    private func makeStore(_ fixture: ClavisTestFixture) throws -> AuditStore {
        let dir = fixture.testRootURL.appendingPathComponent("audit-sort-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: dir)
        return try AuditStore(url: dir.appendingPathComponent("audit.db"))
    }

    private let base = Date(timeIntervalSince1970: 1_800_000_000)

    @discardableResult
    private func add(_ store: AuditStore, at offset: TimeInterval, key: String = "k1",
                     result: AuditResult = .allowed) throws -> Int64 {
        try store.insert(AuditEvent(
            time: base.addingTimeInterval(offset), type: .signature, result: result,
            reason: .viaPrompt, keyFingerprint: key))
    }

    private func drain(_ store: AuditStore, order: AuditSortOrder, pageSize: Int,
                       base q: AuditQuery = AuditQuery()) throws -> [Int64] {
        var query = q
        query.sortOrder = order
        query.limit = pageSize
        var all: [Int64] = []
        while true {
            let page = try store.query(query)
            all += page.map(\.seq)
            guard let last = page.last, page.count == pageSize else { break }
            query.cursor = AuditCursor(record: last)
        }
        return all
    }

    @Test func test_009_sortOrdersByTimeThenSeq() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let store = try makeStore(fixture)
        defer { store.close() }

        // Inserted out of time order; two rows share a timestamp.
        let s1 = try add(store, at: 30)
        let s2 = try add(store, at: 10)
        let s3 = try add(store, at: 10)
        let s4 = try add(store, at: 20)

        var q = AuditQuery(limit: 10)
        q.orderByTime = true
        q.sortOrder = .newestFirst
        #expect(try store.query(q).map(\.seq) == [s1, s4, s3, s2])
        q.sortOrder = .oldestFirst
        #expect(try store.query(q).map(\.seq) == [s2, s3, s4, s1])
    }

    @Test func test_009_cursorPagingIsContinuousInBothDirections() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let store = try makeStore(fixture)
        defer { store.close() }

        // 25 rows, many equal timestamps to stress the tie-breaker.
        for i in 0..<25 { try add(store, at: TimeInterval(i / 4)) }

        for order in [AuditSortOrder.newestFirst, .oldestFirst] {
            let paged = try drain(store, order: order, pageSize: 4)
            var full = AuditQuery(limit: 100)
            full.sortOrder = order
            #expect(paged == (try store.query(full)).map(\.seq))
            #expect(Set(paged).count == 25)
        }
    }

    @Test func test_009_keyFingerprintsAreOrCombinedAndExclusiveEndIsStrict() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let store = try makeStore(fixture)
        defer { store.close() }

        try add(store, at: 0, key: "A")
        try add(store, at: 1, key: "B")
        try add(store, at: 2, key: "C")
        try add(store, at: 3, key: "A")

        var q = AuditQuery(limit: 10)
        q.keyFingerprints = ["A", "B"]
        #expect(try store.query(q).count == 3)
        #expect(try store.count(q) == 3)

        q.keyFingerprints = []
        q.toExclusive = base.addingTimeInterval(3)
        #expect(try store.count(q) == 3)   // row at +3 excluded
    }

    @Test func test_009_countIgnoresPagingAndLimit() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let store = try makeStore(fixture)
        defer { store.close() }

        for i in 0..<12 { try add(store, at: TimeInterval(i), result: i % 2 == 0 ? .allowed : .denied) }

        var q = AuditQuery(limit: 3)
        q.results = [.denied]
        let firstPage = try store.query(q)
        q.cursor = AuditCursor(record: firstPage.last!)
        #expect(try store.count(q) == 6)
    }
}
