import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport
@testable import Clavis

@MainActor
final class HistoryDraftAndPagingTests {
    private let fixture: ClavisTestFixture
    private let notificationCenter = NotificationCenter()

    init() throws {
        fixture = try ClavisTestFixture()
    }

    deinit { fixture.cleanup() }

    private func makeStore() throws -> AuditStore {
        try AuditStore(url: fixture.testRootURL.appendingPathComponent("audit-\(UUID().uuidString).db"))
    }

    private func makeViewModel(_ store: AuditStore, pageSize: Int = 200) -> HistoryViewModel {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let vm = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil },
                                  notificationCenter: notificationCenter, calendar: cal)
        vm.query.limit = pageSize
        return vm
    }

    private let base = Date(timeIntervalSince1970: 1_800_000_000)

    private func seed(_ store: AuditStore, count: Int, host: (Int) -> String? = { _ in "github.com" },
                      secondsApart: TimeInterval = 60) throws {
        for i in 0..<count {
            try store.insert(AuditEvent(
                time: base.addingTimeInterval(TimeInterval(i) * secondsApart),
                type: .signature, result: .allowed, reason: .viaPrompt,
                keyFingerprint: "SHA256:k\(i % 2)",
                sensitive: AuditSensitive(keyLabel: "k\(i % 2)", host: host(i))))
        }
    }

    // MARK: Draft vs committed

    @Test func test_009_typingNeverChangesResultsBadgesOrCount() async throws {
        let store = try makeStore()
        try seed(store, count: 6)
        let vm = makeViewModel(store)
        await vm.reload().value
        let before = (vm.records, vm.filter, vm.totalMatching)

        for text in ["H", "Host", "Host:", "Host:git", "Host:github.com", "Host:github.com Process:ssh"] {
            vm.updateDraft(text: text, caret: (text as NSString).length)
        }
        await vm.waitForLoad()

        #expect(vm.records == before.0)
        #expect(vm.filter == before.1)
        #expect(vm.totalMatching == before.2)
    }

    @Test func test_009_acceptingPrefixThenValueCommitsOneBadgeAndClosesSuggestions() async throws {
        let store = try makeStore()
        try seed(store, count: 4, host: { $0 % 2 == 0 ? "github.com" : "gitlab.com" })
        let vm = makeViewModel(store)
        await vm.ensureSuggestionIndex().value

        vm.updateDraft(text: "Ho", caret: 2)
        let prefix = try #require(vm.suggestions.first)
        #expect(prefix.title == "Host:")
        vm.accept(prefix)
        #expect(vm.draftText == "Host:")
        #expect(vm.filter.criteria.isEmpty)                    // prefix insertion is not a commit
        #expect(vm.suggestions.map(\.title).contains("github.com"))

        let value = try #require(vm.suggestions.first { $0.title == "github.com" })
        vm.accept(value)
        await vm.waitForLoad()

        #expect(vm.filter.criteria == [.host("github.com")])
        #expect(vm.draftText.isEmpty)
        #expect(vm.suggestions.isEmpty)                        // closed after committing
        #expect(vm.records.count == 2)
    }

    @Test func test_009_returnCommitsEveryTermAndClearsDraft() async throws {
        let store = try makeStore()
        try seed(store, count: 4)
        let vm = makeViewModel(store)

        vm.updateDraft(text: "Host:github.com Host:gitlab.com Result:Approved", caret: 0)
        #expect(vm.commitDraft())
        await vm.waitForLoad()

        #expect(vm.filter.criteria == [.host("github.com"), .host("gitlab.com"), .result(.approved)])
        #expect(vm.draftText.isEmpty)
    }

    @Test func test_009_incompleteOrInvalidDraftCommitsNothing() async throws {
        let store = try makeStore()
        let vm = makeViewModel(store)

        vm.updateDraft(text: "Host:", caret: 5)
        #expect(!vm.commitDraft())
        #expect(vm.draftError == nil)

        vm.updateDraft(text: "Hots:github.com", caret: 0)
        #expect(!vm.commitDraft())
        #expect(vm.draftError == .unknownPrefix("Hots"))
        #expect(vm.filter.criteria.isEmpty)

        // The error clears as soon as the user edits.
        vm.updateDraft(text: "Host:github.com", caret: 0)
        #expect(vm.draftError == nil)
    }

    @Test func test_009_typedKeyNameResolvesToStableFingerprint() async throws {
        let store = try makeStore()
        let vm = makeViewModel(store)
        vm.updateKeys([])  // no-op safety
        vm.keyChoicesForTesting([HistoryKeyChoice(fingerprint: "SHA256:k0", label: "Personal Mac")])

        vm.updateDraft(text: "Key:\"personal mac\"", caret: 0)
        #expect(vm.commitDraft())
        #expect(vm.filter.keyFingerprints == ["SHA256:k0"])
        #expect(vm.selectedKeyFingerprint == "SHA256:k0")
    }

    @Test func test_009_duplicateCommitIsIgnoredWithoutReload() async throws {
        let store = try makeStore()
        let vm = makeViewModel(store)
        #expect(vm.add(.host("a.com")))
        #expect(!vm.add(.host("a.com")))
        #expect(vm.filter.criteria.count == 1)
    }

    // MARK: Sorting and paging

    @Test func test_009_sortReversesDaysAndEventsAndKeepsFilters() async throws {
        let store = try makeStore()
        try seed(store, count: 6, secondsApart: 12 * 3600)   // 3 days, 2 events each
        let vm = makeViewModel(store)
        vm.add(.host("github.com"))
        await vm.waitForLoad()

        let newest = vm.records.map(\.event.time)
        #expect(newest == newest.sorted(by: >))
        let newestDays = vm.groupedSections(referenceDate: base).map(\.id)

        vm.setSortOrder(.oldestFirst)
        await vm.waitForLoad()
        let oldest = vm.records.map(\.event.time)
        #expect(oldest == oldest.sorted(by: <))
        #expect(vm.groupedSections(referenceDate: base).map(\.id) == newestDays.reversed())
        #expect(vm.filter.criteria == [.host("github.com")])
    }

    @Test func test_009_pagingWithSparseDecryptTimeMatchesIsContinuousAndUnique() async throws {
        let store = try makeStore()
        // Only every 7th event matches the host, forcing the scan to span many store batches.
        try seed(store, count: 1_400, host: { $0 % 7 == 0 ? "needle.example" : "hay.example" })
        let vm = makeViewModel(store, pageSize: 20)
        vm.add(.host("needle.example"))
        await vm.waitForLoad()
        #expect(vm.totalMatching == nil)           // not knowable without decrypting everything

        var guardCount = 0
        while vm.hasMore, guardCount < 50 {
            await vm.loadMore().value
            guardCount += 1
        }
        #expect(vm.records.count == 200)
        #expect(Set(vm.records.map(\.event.id)).count == 200)
        let times = vm.records.map(\.event.time)
        #expect(times == times.sorted(by: >))
        #expect(vm.totalMatching == 200)           // exact once the end is reached
    }

    @Test func test_009_sqlCriteriaGiveExactTotalBeforeLoadingEverything() async throws {
        let store = try makeStore()
        try seed(store, count: 50)
        let vm = makeViewModel(store, pageSize: 10)
        vm.add(.key("SHA256:k0"))
        await vm.waitForLoad()
        #expect(vm.records.count == 10)
        #expect(vm.totalMatching == 25)
        #expect(vm.hasMore)
    }

    @Test func test_009_supersededQueryNeverOverwritesNewerResults() async throws {
        let store = try makeStore()
        try seed(store, count: 40, host: { $0 % 2 == 0 ? "a.example" : "b.example" })
        let vm = makeViewModel(store)

        // Fire three queries back to back without awaiting; only the last may land.
        vm.add(.host("a.example"))
        vm.removeCriterion(id: HistoryCriterion.host("a.example").id)
        vm.add(.host("b.example"))
        await vm.waitForLoad()
        try await Task.sleep(nanoseconds: 150_000_000)

        #expect(vm.records.count == 20)
        #expect(vm.records.allSatisfy { $0.event.sensitive.host == "b.example" })
    }

    // MARK: Sticky-date handoff structure

    @Test func test_009_dayCrossingABatchStaysIncompleteUntilTheDayIsLoaded() async throws {
        let store = try makeStore()
        try seed(store, count: 5, secondsApart: 60)          // all on one day
        let vm = makeViewModel(store, pageSize: 2)
        await vm.reload().value

        var sections = vm.groupedSections(referenceDate: base)
        #expect(sections.count == 1)
        #expect(!sections[0].isComplete)                      // more of this day is unloaded
        #expect(HistorySectionSplit.split(sections[0]).handoff == nil)

        while vm.hasMore { await vm.loadMore().value }
        sections = vm.groupedSections(referenceDate: base)
        #expect(sections.count == 1 && sections[0].totalCount == 5)
        #expect(sections[0].isComplete)
        let split = HistorySectionSplit.split(sections[0])
        #expect(split.pinned.count == 4 && split.handoff != nil)
    }

    @Test func test_009_handoffSplitHandlesSingleEventAndMultiEventGroups() {
        func rec(_ seq: Int64) -> HistoryItem {
            .record(AuditRecord(seq: seq, event: AuditEvent(type: .signature, result: .allowed)))
        }
        let r1 = rec(1), r2 = rec(2), r3 = rec(3)   // random event UUIDs: build once, compare many
        let single = HistoryDaySection(id: "d1", title: "d1", totalCount: 1, items: [r1])
        let s1 = HistorySectionSplit.split(single)
        #expect(s1.pinned.isEmpty && s1.handoff == r1)

        let multi = HistoryDaySection(id: "d2", title: "d2", totalCount: 3, items: [r1, r2, r3])
        let s2 = HistorySectionSplit.split(multi)
        #expect(s2.pinned == [r1, r2] && s2.handoff == r3)

        // A trailing integrity gap is not an event: nothing is handed off.
        let gapped = HistoryDaySection(
            id: "d3", title: "d3", totalCount: 1,
            items: [rec(1), .gap(fromSeq: 2, toSeq: 3, missingCount: 2)])
        #expect(HistorySectionSplit.split(gapped).handoff == nil)
    }

    @Test func test_009_expandedStateKeysSurviveSortingBecauseTheyUseEventIDs() async throws {
        let store = try makeStore()
        try seed(store, count: 4)
        let vm = makeViewModel(store)
        await vm.reload().value
        let id = try #require(vm.records.first?.event.id)

        vm.setSortOrder(.oldestFirst)
        await vm.waitForLoad()
        #expect(vm.records.contains { $0.event.id == id })      // same identity, new position
    }
}

extension HistoryViewModel {
    /// Test seam: sets key choices without constructing SSHKeyInfo values.
    func keyChoicesForTesting(_ choices: [HistoryKeyChoice]) {
        setKeyChoices(choices)
    }
}
