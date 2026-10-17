@testable import ClavisTestSupport
import Foundation
import Testing
import LocalAuthentication
import SQLite3
@testable import ClavisCore
@testable import Clavis

@MainActor
final class HistoryViewModelTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }
    private let notificationCenter = NotificationCenter()

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    private func createTestStore() throws -> AuditStore {
        let storeURL = testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db")
        return try AuditStore(url: storeURL)
    }

    private func createTestStoreWithURL() throws -> (store: AuditStore, dbURL: URL) {
        let storeURL = testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db")
        let store = try AuditStore(url: storeURL)
        return (store, storeURL)
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
        #expect(viewModel.selectedKeyFingerprint == "fp-A")

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

    @Test func test_121_autoReloadsOnAuditNotification() async throws {
        let store = try createTestStore()
        let event1 = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-1"))
        try store.insert(event1)

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value
        #expect(viewModel.records.count == 1)

        let event2 = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-2"))
        try store.insert(event2)

        notificationCenter.post(name: HistoryViewModel.didRecordAuditNotification, object: nil)

        for _ in 0..<100 {
            if viewModel.records.count == 2 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(viewModel.records.count == 2)
    }

    @Test func test_121_autoReloadsOnAgentSignedNotification() async throws {
        let store = try createTestStore()
        let event1 = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-1"))
        try store.insert(event1)

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value
        #expect(viewModel.records.count == 1)

        let event2 = AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "key-2"))
        try store.insert(event2)

        notificationCenter.post(name: NSNotification.Name("com.clavis.agentSigned"), object: nil)

        for _ in 0..<100 {
            if viewModel.records.count == 2 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(viewModel.records.count == 2)
    }

    /// Commits a free-text badge and waits for the resulting reload.
    private func commitText(_ vm: HistoryViewModel, _ text: String) async {
        vm.add(.text(text))
        await vm.waitForLoad()
    }

    @Test func test_122_searchFilteringByKeyLabel() async throws {
        let store = try createTestStore()
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "production-deploy-key")))
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "staging-test-key")))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value
        #expect(viewModel.records.count == 2)

        await commitText(viewModel, "production")
        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.sensitive.keyLabel == "production-deploy-key")

        viewModel.removeCriterion(id: HistoryCriterion.text("production").id)
        await viewModel.waitForLoad()
        await commitText(viewModel, "staging")
        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.sensitive.keyLabel == "staging-test-key")

        viewModel.clearFilters()
        await viewModel.waitForLoad()
        #expect(viewModel.records.count == 2)
    }

    @Test func test_122_searchFilteringByFingerprint() async throws {
        let store = try createTestStore()
        try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: "SHA256:alpha123", sensitive: AuditSensitive(keyLabel: "k1")))
        try store.insert(AuditEvent(type: .signature, result: .allowed, keyFingerprint: "SHA256:beta456", sensitive: AuditSensitive(keyLabel: "k2")))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value

        await commitText(viewModel, "alpha")
        #expect(viewModel.records.map(\.event.keyFingerprint) == ["SHA256:alpha123"])
    }

    @Test func test_122_hostBadgeMatchesExactHostOnly() async throws {
        let store = try createTestStore()
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k1", host: "github.com")))
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k2", host: "gitlab.com")))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value

        viewModel.add(.host("github.com"))
        await viewModel.waitForLoad()
        #expect(viewModel.records.map(\.event.sensitive.host) == ["github.com"])

        // A host is exact: a fragment is a different criterion and matches nothing.
        viewModel.removeCriterion(id: HistoryCriterion.host("github.com").id)
        viewModel.add(.host("github"))
        await viewModel.waitForLoad()
        #expect(viewModel.records.isEmpty)
    }

    @Test func test_122_searchFilteringByProcessAndPID() async throws {
        let store = try createTestStore()
        let proc1 = AuditProcess(executablePath: "/usr/bin/ssh", pid: 12345)
        let proc2 = AuditProcess(executablePath: "/opt/homebrew/bin/git", pid: 67890)
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(processChain: [proc1])))
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(processChain: [proc2])))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value

        await commitText(viewModel, "ssh")
        #expect(viewModel.records.count == 1)
        #expect(viewModel.records[0].event.sensitive.processChain.first?.executablePath == "/usr/bin/ssh")

        viewModel.clearFilters()
        await viewModel.waitForLoad()
        await commitText(viewModel, "67890")
        #expect(viewModel.records.first?.event.sensitive.processChain.first?.pid == 67890)

        viewModel.clearFilters()
        await viewModel.waitForLoad()
        viewModel.add(.process(.path("/usr/bin/ssh")))
        await viewModel.waitForLoad()
        #expect(viewModel.records.first?.event.sensitive.processChain.first?.pid == 12345)
    }

    @Test func test_123_paginationBeyond200Events() async throws {
        let store = try createTestStore()
        for i in 1...250 {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                sensitive: AuditSensitive(keyLabel: "key-\(i)")
            )
            try store.insert(event)
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        #expect(viewModel.query.limit == 200)

        await viewModel.reload().value
        #expect(viewModel.records.count == 200)
        #expect(viewModel.hasMore == true)
        let oldestSeqInFirstPage = viewModel.records.last?.seq
        #expect(oldestSeqInFirstPage == 51)

        await viewModel.loadMore().value
        #expect(viewModel.records.count == 250)
        #expect(viewModel.hasMore == false)
        let oldestSeqInSecondPage = viewModel.records.last?.seq
        #expect(oldestSeqInSecondPage == 1)
    }

    @Test func test_124_recordDigestAndDetailInspection() async throws {
        let store = try createTestStore()
        let proc = AuditProcess(executablePath: "/usr/bin/git", pid: 4242)
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            keyFingerprint: "SHA256:fingerprintExample",
            keyKind: .agent,
            sessionID: "sess-9999",
            sensitive: AuditSensitive(keyLabel: "agent-key", processChain: [proc], host: "git.internal")
        )
        try store.insert(event)

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value

        #expect(viewModel.records.count == 1)
        let record = viewModel.records[0]

        let digest = AuditWitness.digest(for: record)
        #expect(digest.count == 32)

        if case .plaintext(let sens) = viewModel.sensitive[record.seq] {
            #expect(sens.keyLabel == "agent-key")
            #expect(sens.host == "git.internal")
            #expect(sens.processChain.count == 1)
            #expect(sens.processChain[0].executablePath == "/usr/bin/git")
            #expect(sens.processChain[0].pid == 4242)
        } else {
            Issue.record("Expected unsealed plaintext sensitive fields")
        }
    }

    @Test func testAdversarialPaginationOver600EventsNoGaps() async throws {
        let store = try createTestStore()
        let count = 600
        for i in 1...count {
            let event = AuditEvent(
                type: .signature,
                result: .allowed,
                sensitive: AuditSensitive(
                    keyLabel: "key-\(i % 10)",
                    processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: pid_t(1000 + i))],
                    host: "host-\(i % 5).internal"
                )
            )
            try store.insert(event)
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        #expect(viewModel.query.limit == 200)

        // Page 1
        await viewModel.reload().value

        #expect(viewModel.records.count == 200)
        #expect(viewModel.hasMore == true)
        #expect(viewModel.records.first?.seq == 600)
        #expect(viewModel.records.last?.seq == 401)
        #expect(viewModel.items.count == 200)
        #expect(!viewModel.items.contains(where: { $0.isGap }))

        // Page 2
        await viewModel.loadMore().value

        #expect(viewModel.records.count == 400)
        #expect(viewModel.hasMore == true)
        #expect(viewModel.records[199].seq == 401)
        #expect(viewModel.records[200].seq == 400)
        #expect(viewModel.records.last?.seq == 201)
        #expect(viewModel.items.count == 400)
        #expect(!viewModel.items.contains(where: { $0.isGap }))

        // Page 3
        await viewModel.loadMore().value

        #expect(viewModel.records.count == 600)
        #expect(viewModel.hasMore == true) // Exact multiple of limit (200), so hasMore is true until next empty fetch
        #expect(viewModel.records[399].seq == 201)
        #expect(viewModel.records[400].seq == 200)
        #expect(viewModel.records.last?.seq == 1)
        #expect(viewModel.items.count == 600)
        #expect(!viewModel.items.contains(where: { $0.isGap }))

        // Page 4 (when reaching beyond the last record for exact multiples)
        await viewModel.loadMore().value

        #expect(viewModel.records.count == 600)
        #expect(viewModel.hasMore == false)
        #expect(!viewModel.items.contains(where: { $0.isGap }))
    }

    @Test func testAdversarialPaginationOver550EventsNonMultiple() async throws {
        let store = try createTestStore()
        for _ in 1...550 {
            try store.insert(AuditEvent(type: .signature, result: .allowed))
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        #expect(viewModel.query.limit == 200)

        // Page 1
        await viewModel.reload().value
        #expect(viewModel.records.count == 200)
        #expect(viewModel.hasMore == true)

        // Page 2
        await viewModel.loadMore().value
        #expect(viewModel.records.count == 400)
        #expect(viewModel.hasMore == true)

        // Page 3: 150 events remaining (< 200)
        await viewModel.loadMore().value
        #expect(viewModel.records.count == 550)
        #expect(viewModel.hasMore == false)
        #expect(viewModel.items.count == 550)
        #expect(!viewModel.items.contains(where: { $0.isGap }))
    }


    @Test func testAdversarialMultiFieldFilteringAndPerformanceOn600Events() async throws {
        let store = try createTestStore()
        for i in 1...600 {
            let label: String
            switch i % 4 {
            case 0: label = "prod-deploy-key"
            case 1: label = "staging-key"
            case 2: label = "backup-key"
            default: label = "alpha-test-key"
            }

            let host: String
            switch i % 3 {
            case 0: host = "github.com"
            case 1: host = "gitlab.internal"
            default: host = "bastion.prod.company.net"
            }

            let execPath = (i % 2 == 0) ? "/usr/bin/ssh" : "/opt/homebrew/bin/git"
            let pid = pid_t(10000 + (i % 50))

            let event = AuditEvent(
                type: .signature,
                result: (i % 5 == 0) ? .denied : .allowed,
                keyFingerprint: "SHA256:fingerprint-\(label)",
                sensitive: AuditSensitive(
                    keyLabel: label,
                    processChain: [AuditProcess(executablePath: execPath, pid: pid)],
                    host: host
                )
            )
            try store.insert(event)
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        viewModel.query.limit = 600
        await viewModel.reload().value
        #expect(viewModel.records.count == 600)

        // 1. Host badge (decrypt-time criterion, scanned until the page is full)
        viewModel.add(.host("bastion.prod.company.net"))
        await viewModel.waitForLoad()
        #expect(viewModel.records.count == 200)
        #expect(viewModel.records.allSatisfy { $0.event.sensitive.host == "bastion.prod.company.net" })
        #expect(!viewModel.items.contains(where: { $0.isGap }))

        // 2. Key badge (SQL criterion; stable fingerprint, not the label)
        viewModel.openForKey(nil)
        viewModel.add(.key("SHA256:fingerprint-prod-deploy-key"))
        await viewModel.waitForLoad()
        #expect(viewModel.records.count == 150)
        #expect(viewModel.records.allSatisfy { $0.event.sensitive.keyLabel == "prod-deploy-key" })
        #expect(viewModel.totalMatching == 150)

        // 3. Process badge by name
        viewModel.openForKey(nil)   // fresh filter: Clear Filters would keep the lone key badge
        viewModel.add(.process(.name("git")))
        await viewModel.waitForLoad()
        #expect(viewModel.records.count == 300)
        #expect(viewModel.records.allSatisfy { $0.event.sensitive.processChain.first?.executablePath.contains("homebrew") == true })

        // 4. Combined: AND across types
        viewModel.openForKey(nil)
        viewModel.add(.key("SHA256:fingerprint-staging-key"))
        viewModel.add(.host("gitlab.internal"))
        viewModel.add(.process(.name("git")))
        await viewModel.waitForLoad()
        #expect(viewModel.records.allSatisfy { rec in
            rec.event.sensitive.keyLabel == "staging-key" &&
            rec.event.sensitive.host == "gitlab.internal" &&
            rec.event.sensitive.processChain.first?.executablePath.contains("homebrew") == true
        })

        // 5. Removing every badge restores all 600
        viewModel.openForKey(nil)
        await viewModel.waitForLoad()
        #expect(viewModel.records.count == 600)
    }

    @Test func testAdversarialArtificialGapDetectionWithPagination() async throws {
        let (store, dbURL) = try createTestStoreWithURL()
        // Insert 350 events (seq 1..350)
        for _ in 1...350 {
            _ = try store.insert(AuditEvent(type: .signature, result: .allowed))
        }

        // Delete rows 101..200 (gap of 100 rows)
        try executeSQL(on: dbURL, "DELETE FROM events WHERE seq BETWEEN 101 AND 200;")

        let viewModel = HistoryViewModel(
            store: { store },
            keyring: nil,
            contextProvider: { nil },
            notificationCenter: notificationCenter
        )
        viewModel.query.limit = 150
        await viewModel.reload().value

        #expect(viewModel.records.count == 150) // seqs 350 down to 201
        #expect(!viewModel.items.contains(where: { $0.isGap })) // no gap in first page

        await viewModel.loadMore().value
        #expect(viewModel.records.count == 250) // all 250 remaining records

        // Gap should now be detected between seq 201 and 100
        let gaps = viewModel.items.compactMap { item -> (Int64, Int64, Int64)? in
            if case .gap(let fromSeq, let toSeq, let missing) = item {
                return (fromSeq, toSeq, missing)
            }
            return nil
        }
        #expect(gaps.count == 1)
        #expect(gaps.first?.0 == 101)
        #expect(gaps.first?.1 == 200)
        #expect(gaps.first?.2 == 100)
    }

    @Test func testPaginationIgnoresGlobalDistributedAndDefaultNotificationsWhenIsolated() async throws {
        let store = try createTestStore()
        for _ in 1...400 {
            try store.insert(AuditEvent(type: .signature, result: .allowed))
        }

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.reload().value
        #expect(viewModel.records.count == 200)
        #expect(viewModel.hasMore == true)

        await viewModel.loadMore().value
        #expect(viewModel.records.count == 400)

        // Broadcast notifications on global centers (simulating concurrent tests or background processes)
        let globalNames: [NSNotification.Name] = [
            HistoryViewModel.didRecordAuditNotification,
            NSNotification.Name("com.clavis.agentSigned"),
            NSNotification.Name("com.clavis.agentRateLimited"),
            NSNotification.Name("com.clavis.agentSessionsChanged")
        ]
        for name in globalNames {
            NotificationCenter.default.post(name: name, object: nil)
            DistributedNotificationCenter.default().postNotificationName(
                name,
                object: nil,
                userInfo: nil,
                deliverImmediately: true
            )
        }

        // Pump main actor tasks/runloop to ensure any stray observers would have fired
        for _ in 0..<10 {
            await Task.yield()
        }

        await viewModel.loadMore().value
        #expect(viewModel.records.count == 400)
        #expect(viewModel.hasMore == false)
    }

    @Test func testSuggestionIndexRanksHostsAndProcessesAndDropsOnLock() async throws {
        let store = try createTestStore()
        let ssh = AuditProcess(executablePath: "/usr/bin/ssh", pid: 1)
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k1", processChain: [ssh], host: "github.com")))
        try store.insert(AuditEvent(type: .signature, result: .allowed, sensitive: AuditSensitive(keyLabel: "k1", processChain: [ssh], host: "GitHub.com.")))
        try store.insert(AuditEvent(type: .signature, result: .denied, sensitive: AuditSensitive(keyLabel: "k2", host: "gitlab.com")))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter)
        await viewModel.ensureSuggestionIndex().value

        // Canonicalised, most frequent first.
        #expect(viewModel.indexedHosts == ["github.com", "gitlab.com"])
        #expect(viewModel.indexedProcessPaths == ["/usr/bin/ssh"])

        // Decrypted values must not outlive an unlocked panel.
        notificationCenter.post(name: PanelLockController.didLockNotification, object: nil)
        try await Task.sleep(nanoseconds: 100_000_000)
        #expect(viewModel.indexedHosts.isEmpty && viewModel.indexedProcessPaths.isEmpty)
    }

    @Test func testOperationAndStatusSearchAndDateGrouping() async throws {
        let store = try createTestStore()
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let today = Date()
        let yesterday = calendar.date(byAdding: .day, value: -1, to: today)!
        let twoDaysAgo = calendar.date(byAdding: .day, value: -2, to: today)!

        try store.insert(AuditEvent(
            time: twoDaysAgo, type: .signature, result: .allowed, reason: .viaGitGrant,
            sensitive: AuditSensitive(keyLabel: "git-key", processChain: [AuditProcess(executablePath: "/usr/bin/git", pid: 101)], host: "github.com")))
        try store.insert(AuditEvent(
            time: yesterday, type: .signature, result: .denied, reason: .userCancelled,
            sensitive: AuditSensitive(keyLabel: "ssh-key", processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 102)], host: "bastion.internal")))
        try store.insert(AuditEvent(
            time: today, type: .signature, result: .allowed, keyKind: .agent,
            sensitive: AuditSensitive(keyLabel: "agent-key", processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 103)], host: "build.internal")))

        let viewModel = HistoryViewModel(store: { store }, notificationCenter: notificationCenter, calendar: calendar)
        await viewModel.reload().value
        #expect(viewModel.records.count == 3)

        // Today / Yesterday come from the actual reference date and time zone.
        let sections = viewModel.groupedSections(referenceDate: today, locale: Locale(identifier: "en_US"))
        #expect(sections.count == 3)
        #expect(sections[0].title.hasPrefix("Today · "))
        #expect(sections[1].title.hasPrefix("Yesterday · "))
        #expect(sections.map(\.totalCount) == [1, 1, 1])

        // Result badge uses the shared vocabulary.
        viewModel.add(.result(.rejected))
        await viewModel.waitForLoad()
        #expect(viewModel.records.map(\.event.result) == [.denied])
        viewModel.clearFilters()
        await viewModel.waitForLoad()

        await commitText(viewModel, "git commit")
        #expect(viewModel.records.map(\.event.sensitive.keyLabel) == ["git-key"])
        viewModel.clearFilters()
        await viewModel.waitForLoad()
        await commitText(viewModel, "agent signature")
        #expect(viewModel.records.first?.event.keyKind == .agent)
        viewModel.clearFilters()
        await viewModel.waitForLoad()

        // Day bounds are inclusive calendar days in the model's time zone.
        let day = CalendarDay(yesterday, calendar: calendar)
        viewModel.setDateFrom(day)
        viewModel.setDateTo(day)
        await viewModel.waitForLoad()
        #expect(viewModel.records.map(\.event.sensitive.keyLabel) == ["ssh-key"])
        #expect(viewModel.totalMatching == nil || viewModel.totalMatching == 1)

        viewModel.clearFilters()
        await viewModel.waitForLoad()
        #expect(viewModel.filter.dateBounds.isEmpty)
        #expect(viewModel.records.count == 3)
    }
}
