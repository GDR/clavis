import XCTest
@testable import ClavisCore
@testable import Clavis

@MainActor
final class HistoryViewModelTests: ClavisBaseTestCase {

    private func createTestStore() throws -> AuditStore {
        let storeURL = testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db")
        return try AuditStore(url: storeURL)
    }

    func test_002_AC3_viewModelAppliesFilters() async throws {
        let store = try createTestStore()
        let eventAllowed = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k1"))
        let eventDenied = AuditEvent(type: .signature, result: .denied, reason: .unknownKey)
        try store.insert(eventAllowed)
        try store.insert(eventDenied)

        let viewModel = HistoryViewModel(store: { store })
        viewModel.query.results = [.allowed]

        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 1)
        XCTAssertEqual(viewModel.records[0].event.result, .allowed)
    }

    func test_002_AC4_openingForKeyPresetsFingerprintFilter() async throws {
        let store = try createTestStore()
        let eventA = AuditEvent(type: .signature, result: .allowed, keyFingerprint: "fp-A")
        let eventB = AuditEvent(type: .signature, result: .allowed, keyFingerprint: "fp-B")
        try store.insert(eventA)
        try store.insert(eventB)

        let viewModel = HistoryViewModel(initialKeyFingerprint: "fp-A", store: { store })
        XCTAssertEqual(viewModel.query.keyFingerprint, "fp-A")

        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 1)
        XCTAssertEqual(viewModel.records[0].event.keyFingerprint, "fp-A")
    }

    func test_002_T7_loadMorePagesBySeq() async throws {
        let store = try createTestStore()
        for i in 1...5 {
            let event = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-\(i)"))
            try store.insert(event)
        }

        let viewModel = HistoryViewModel(store: { store })
        viewModel.query.limit = 2

        await viewModel.reload().value

        XCTAssertEqual(viewModel.records.count, 2)
        let firstSeq = viewModel.records.first?.seq
        let secondSeq = viewModel.records.last?.seq
        XCTAssertEqual(firstSeq, 5)
        XCTAssertEqual(secondSeq, 4)

        await viewModel.loadMore().value

        XCTAssertEqual(viewModel.records.count, 4)
        XCTAssertEqual(viewModel.records[2].seq, 3)
        XCTAssertEqual(viewModel.records[3].seq, 2)
    }
}
