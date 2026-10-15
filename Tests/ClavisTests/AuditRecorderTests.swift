import Testing
import Foundation
@testable import ClavisCore

@Suite struct AuditRecorderTests {

    private func makeTestDB(fixture: ClavisTestFixture) throws -> URL {
        let testDirURL = fixture.testRootURL.appendingPathComponent("audit-rec-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        return testDirURL.appendingPathComponent("audit.db")
    }

    @Test func test_002_C2_floodBecomesAggregateRow() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: dbURL) },
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
        #expect(records.count == 31)

        // Check suppressed row
        let suppressedRecords = records.filter { $0.event.type == .suppressed }
        #expect(suppressedRecords.count == 1)
        #expect(suppressedRecords[0].event.count == 70)
        #expect(suppressedRecords[0].event.result == .denied)
        #expect(suppressedRecords[0].event.reason == .unknownKey)
        #expect(suppressedRecords[0].event.keyFingerprint == "SHA256:victimKey")
        #expect(suppressedRecords[0].event.sensitive == AuditSensitive())

        // Check normal rows
        let normalRecords = records.filter { $0.event.type == .signature }
        #expect(normalRecords.count == 30)
    }

    @Test func test_002_C2_floodDoesNotEvictOlderEvents() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: dbURL) },
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
        #expect(allowedQuery.count == 1)
        #expect(allowedQuery[0].event.keyFingerprint == "SHA256:preciousKey")
    }

    @Test func test_002_C2_allowedSignaturesAreNeverSuppressed() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: dbURL) },
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
        #expect(records.count == 100)
        #expect(records.allSatisfy { $0.event.type == .signature && $0.event.result == .allowed })
    }

    @Test func test_002_T3_retentionPrunesByAgeAndCap() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let dbURL = try makeTestDB(fixture: fixture)

        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: dbURL) },
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
        #expect(count <= 10)
    }

    @Test func test_002_T3_storeOpenFailureDoesNotThrow() {
        struct MockError: Error {}
        let recorder = AuditRecorder(
            storeFactory: { throw MockError() }
        )

        // Must not throw or crash
        recorder.record(AuditEvent(type: .signature, result: .allowed))
        recorder.flush()
    }
}
