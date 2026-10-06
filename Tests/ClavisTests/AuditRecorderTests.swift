import XCTest
@testable import ClavisCore

final class AuditRecorderTests: ClavisBaseTestCase {
    private var testDirURL: URL!
    private var dbURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testDirURL = testRootURL.appendingPathComponent("audit-rec-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        dbURL = testDirURL.appendingPathComponent("audit.db")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: testDirURL)
        try super.tearDownWithError()
    }

    func test_002_C2_floodBecomesAggregateRow() throws {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            now: { currentTime },
            floodThreshold: 30,
            floodWindow: 60
        )

        // 100 denied events in 10s
        for _ in 0..<100 {
            currentTime = currentTime.addingTimeInterval(0.1)
            recorder.record(AuditEvent(
                time: currentTime,
                type: .signature,
                result: .denied,
                reason: .unknownKey,
                keyFingerprint: "SHA256:victimKey"
            ))
        }

        // Advance clock by 61s and flush
        currentTime = currentTime.addingTimeInterval(61.0)
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let records = try store.query(AuditQuery(limit: 200))
        XCTAssertEqual(records.count, 31)

        // Check suppressed row
        let suppressedRecords = records.filter { $0.event.type == .suppressed }
        XCTAssertEqual(suppressedRecords.count, 1)
        XCTAssertEqual(suppressedRecords[0].event.count, 70)
        XCTAssertEqual(suppressedRecords[0].event.result, .denied)
        XCTAssertEqual(suppressedRecords[0].event.reason, .unknownKey)
        XCTAssertEqual(suppressedRecords[0].event.keyFingerprint, "SHA256:victimKey")
        XCTAssertEqual(suppressedRecords[0].event.sensitive, AuditSensitive())

        // Check normal rows
        let normalRecords = records.filter { $0.event.type == .signature }
        XCTAssertEqual(normalRecords.count, 30)
    }

    func test_002_C2_floodDoesNotEvictOlderEvents() throws {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            now: { currentTime },
            floodThreshold: 30,
            floodWindow: 60,
            retentionMaxRows: 100_000
        )

        let allowedEvent = AuditEvent(
            time: currentTime,
            type: .signature,
            result: .allowed,
            keyFingerprint: "SHA256:preciousKey"
        )
        recorder.record(allowedEvent)

        for _ in 0..<10_000 {
            currentTime = currentTime.addingTimeInterval(0.001)
            recorder.record(AuditEvent(
                time: currentTime,
                type: .signature,
                result: .denied,
                reason: .authenticationFailed,
                keyFingerprint: "SHA256:floodingKey"
            ))
        }

        currentTime = currentTime.addingTimeInterval(61.0)
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let allowedQuery = try store.query(AuditQuery(results: [.allowed]))
        XCTAssertEqual(allowedQuery.count, 1)
        XCTAssertEqual(allowedQuery[0].event.keyFingerprint, "SHA256:preciousKey")
    }

    func test_002_C2_allowedSignaturesAreNeverSuppressed() throws {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            now: { currentTime },
            floodThreshold: 30,
            floodWindow: 60
        )

        for _ in 0..<100 {
            currentTime = currentTime.addingTimeInterval(0.1)
            recorder.record(AuditEvent(
                time: currentTime,
                type: .signature,
                result: .allowed,
                reason: .viaPrompt,
                keyFingerprint: "SHA256:busyKey"
            ))
        }
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let records = try store.query(AuditQuery(limit: 200))
        XCTAssertEqual(records.count, 100)
        XCTAssertTrue(records.allSatisfy { $0.event.type == .signature && $0.event.result == .allowed })
    }

    func test_002_T3_retentionPrunesByAgeAndCap() throws {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            now: { currentTime },
            floodThreshold: 1000,
            floodWindow: 60,
            retentionAge: 3600, // 1 hour
            retentionMaxRows: 10,
            pruneEvery: 5
        )

        // Record 20 events spaced out in time
        for _ in 0..<20 {
            currentTime = currentTime.addingTimeInterval(10)
            recorder.record(AuditEvent(type: .lock, result: .info))
        }

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let count = try store.count()
        // Should have been pruned because pruneEvery is 5 and maxRows is 10
        XCTAssertLessThanOrEqual(count, 10)
    }

    func test_002_T3_storeOpenFailureDoesNotThrow() {
        struct MockError: Error {}
        let recorder = AuditRecorder(
            storeFactory: { throw MockError() }
        )

        // Must not throw or crash
        recorder.record(AuditEvent(type: .signature, result: .allowed))
        recorder.flush()
    }
}
