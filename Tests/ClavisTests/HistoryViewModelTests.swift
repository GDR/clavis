import Foundation
import Testing
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

private final class CleanupHook: @unchecked Sendable {
    private let action: () -> Void
    init(action: @escaping () -> Void) {
        self.action = action
    }
    deinit {
        action()
    }
}

@MainActor
struct HistoryViewModelTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }
    private let _cleanup: CleanupHook
    private let notificationCenter = NotificationCenter()

    init() throws {
        let fixture = try ClavisTestFixture()
        self.fixture = fixture
        self._cleanup = CleanupHook {
            fixture.cleanup()
        }
    }

    private func createTestStore() throws -> AuditStore {
        let storeURL = testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db")
        return try AuditStore(url: storeURL)
    }

    @Test func test_002_AC3_viewModelAppliesFilters() async throws {
        let store = try createTestStore()
        let eventAllowed = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k1"))
        let eventDenied = AuditEvent(type: .signature, result: .denied, reason: .unknownKey)
        try store.insert(eventAllowed)
        try store.insert(eventDenied)

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        viewModel.query.results = [.allowed]

        await viewModel.reload().value

        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.result == .allowed)
    }

    @Test func test_002_AC4_openingForKeyPresetsFingerprintFilter() async throws {
        let store = try createTestStore()
        let eventA = AuditEvent(type: .signature, result: .allowed, keyFingerprint: "fp-A")
        let eventB = AuditEvent(type: .signature, result: .allowed, keyFingerprint: "fp-B")
        try store.insert(eventA)
        try store.insert(eventB)

        let viewModel = HistoryViewModel(initialKeyFingerprint: "fp-A", store: { store }, notificationCenter: notificationCenter)
        #expect(viewModel.query.keyFingerprint == "fp-A")

        await viewModel.reload().value

        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.keyFingerprint == "fp-A")
    }

    @Test func test_002_T7_loadMorePagesBySeq() async throws {
        let store = try createTestStore()
        for i in 1...5 {
            let event = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-\(i)"))
            try store.insert(event)
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        viewModel.query.limit = 2

        await viewModel.reload().value

        #expect(viewModel.records.count == 2)
        let firstSeq = viewModel.records.first?.seq
        let secondSeq = viewModel.records.last?.seq
        #expect(firstSeq == 5)
        #expect(secondSeq == 4)

        await viewModel.loadMore().value

        #expect(viewModel.records.count == 4)
        #expect(viewModel.records[2].seq == 3)
        #expect(viewModel.records[3].seq == 2)
    }

    @Test func test_008_T5_viewModelUnsealsAndClearsOnLock() async throws {
        let store = try createTestStore()
        let keyring = SoftwareAuditKeyring(requireContext: true)
        let sealer = AuditSealer(keyring: keyring)

        // Row 1: format 1 sealed
        let event1 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "secret-key", processChain: [], host: "test.host")
        )
        let (fmt1, blob1) = sealer.seal(event1, store: store)
        let seq1 = try store.insert(event1, sensitiveFormat: fmt1, sensitiveBlob: blob1)

        // Row 2: format 0 legacy
        let event2 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "legacy-key", processChain: [], host: "legacy.host")
        )
        let seq2 = try store.insert(event2)

        // Row 3: format 2 omitted
        let event3 = AuditEvent(type: .signature, result: .allowed)
        let seq3 = try store.insert(event3, sensitiveFormat: 2, sensitiveBlob: Data())

        let dummyContext = LAContext()
        let viewModel = HistoryViewModel(
            store: { store },
            keyring: keyring,
            contextProvider: { dummyContext },
            notificationCenter: notificationCenter
        )

        await viewModel.reload().value

        #expect(viewModel.records.count == 3)
        #expect(viewModel.sensitive.count == 3)

        if case .plaintext(let s1) = viewModel.sensitive[seq1] {
            #expect(s1.keyLabel == "secret-key")
        } else {
            Issue.record("Expected plaintext for seq1")
        }

        if case .plaintext(let s2) = viewModel.sensitive[seq2] {
            #expect(s2.keyLabel == "legacy-key")
        } else {
            Issue.record("Expected plaintext for seq2")
        }

        #expect(viewModel.sensitive[seq3] == AuditUnsealResult.omitted)

        // Lock notification must clear sensitive dictionary
        notificationCenter.post(name: PanelLockController.didLockNotification, object: nil)
        for _ in 0..<100 {
            if viewModel.sensitive.isEmpty { break }
            await Task.yield()
        }

        #expect(viewModel.sensitive.isEmpty)
    }

    @Test func test_008_T5_viewModelExportWithUnsealed() async throws {
        let store = try createTestStore()
        let keyring = SoftwareAuditKeyring(requireContext: true)
        let sealer = AuditSealer(keyring: keyring)

        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(keyLabel: "export-key", processChain: [], host: "export.host")
        )
        let (fmt, blob) = sealer.seal(event, store: store)
        _ = try store.insert(event, sensitiveFormat: fmt, sensitiveBlob: blob)

        let dummyContext = LAContext()
        let viewModel = HistoryViewModel(
            store: { store },
            keyring: keyring,
            contextProvider: { dummyContext },
            notificationCenter: notificationCenter
        )

        await viewModel.reload().value
        #expect(viewModel.sensitive.count == 1)

        let exportURL = testRootURL.appendingPathComponent("export.jsonl")
        try viewModel.export(to: exportURL)

        let exportedData = try Data(contentsOf: exportURL)
        let jsonString = String(decoding: exportedData, as: UTF8.self)
        #expect(!jsonString.isEmpty)

        // Key label should be hashed, not plaintext
        #expect(!jsonString.contains("export-key"))
        // host is unredacted in export
        #expect(jsonString.contains("export.host"))
    }

    @Test func test_002_AC5_sessionFilterShowsOnlySessionRows() async throws {
        let store = try createTestStore()
        let eventSession = AuditEvent(type: .signature, result: .allowed, sessionID: "sess-123", sensitive: AuditSensitive(keyLabel: "k1"))
        let eventOther = AuditEvent(type: .signature, result: .allowed, sessionID: "sess-456", sensitive: AuditSensitive(keyLabel: "k2"))
        let eventNoSession = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k3"))
        try store.insert(eventSession)
        try store.insert(eventOther)
        try store.insert(eventNoSession)

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        viewModel.query.sessionID = "sess-123"

        await viewModel.reload().value

        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.sessionID == "sess-123")
    }

    @Test func test_004_T5a_historyNeedsKeyContextWhenPinRequired() async throws {
        let store = try createTestStore()
        let keyring = SoftwareAuditKeyring()
        let pinContext = LAContext()
        TestContextPinRegistry.shared.setPIN("654321", for: pinContext)
        let pub = try keyring.createKey(mode: .biometryOrPIN, context: pinContext)
        try keyring.setCurrent(keyID: pub.keyID)

        var currentContext: LAContext? = nil
        let viewModel = HistoryViewModel(
            store: { store },
            keyring: keyring,
            contextProvider: { currentContext },
            notificationCenter: notificationCenter
        )

        // Without PIN context: needsKeyContext is true
        await viewModel.reload().value
        #expect(viewModel.needsKeyContext)

        // With PIN context: needsKeyContext is false
        currentContext = pinContext
        await viewModel.reload().value
        #expect(!viewModel.needsKeyContext)

        // On lock: needsKeyContext becomes false
        viewModel.needsKeyContext = true
        notificationCenter.post(name: PanelLockController.didLockNotification, object: nil)
        for _ in 0..<100 {
            if !viewModel.needsKeyContext { break }
            await Task.yield()
        }
        #expect(!viewModel.needsKeyContext)
    }
}
