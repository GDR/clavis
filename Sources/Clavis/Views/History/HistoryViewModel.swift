import Foundation
import LocalAuthentication
import ClavisCore

public enum HistoryItem: Identifiable, Equatable, Sendable {
    case record(AuditRecord)
    case gap(fromSeq: Int64, toSeq: Int64, missingCount: Int64)

    public var id: String {
        switch self {
        case .record(let record):
            return "record-\(record.seq)"
        case .gap(let fromSeq, let toSeq, _):
            return "gap-\(fromSeq)-\(toSeq)"
        }
    }

    public var record: AuditRecord? {
        if case .record(let r) = self { return r }
        return nil
    }

    public var isGap: Bool {
        if case .gap = self { return true }
        return false
    }
}

public struct HistoryDaySection: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let totalCount: Int
    public let items: [HistoryItem]
    /// False while later events of this day may still be unloaded (the section is the last
    /// loaded one and more history exists). Decides whether the last row may hand off the date.
    public let isComplete: Bool

    public init(id: String, title: String, totalCount: Int, items: [HistoryItem], isComplete: Bool = true) {
        self.id = id
        self.title = title
        self.totalCount = totalCount
        self.items = items
        self.isComplete = isComplete
    }
}

extension AuditQuery {
    public var hasFiltersExceptTimeRange: Bool {
        !types.isEmpty || !results.isEmpty || keyFingerprint != nil || !keyFingerprints.isEmpty
            || keyKind != nil || sessionID != nil
    }
}

@MainActor
public final class HistoryViewModel: ObservableObject {
    // MARK: Results
    /// Matching events loaded so far, in the active sort order.
    @Published public private(set) var records: [AuditRecord] = []
    @Published public private(set) var items: [HistoryItem] = []
    @Published public var sensitive: [Int64: AuditUnsealResult] = [:]
    @Published public var errorMessage: String?
    @Published public var isLoading: Bool = false
    @Published public var hasMore: Bool = false
    @Published public var isLoadingMore: Bool = false
    /// Exact total when the store can answer it (no decrypt-time criteria); otherwise nil.
    @Published public private(set) var totalMatching: Int?
    /// Scanned rows whose sealed fields could not be read (they cannot match host/process/text).
    @Published public private(set) var unreadableScanned: Int = 0

    @Published public var integrityReport: AuditIntegrityReport?
    @Published public var isCheckingIntegrity: Bool = false
    @Published public var integrityCheckError: String?
    @Published public var needsKeyContext: Bool = false

    // MARK: Committed query (single source of truth)
    /// Base scope that is not a badge: page size and the optional session scope.
    @Published public var query: AuditQuery = AuditQuery()
    @Published public private(set) var filter = HistoryFilter()

    // MARK: Draft (never affects results until committed)
    @Published public private(set) var draftText: String = ""
    @Published public private(set) var draftCaret: Int = 0
    @Published public private(set) var suggestions: [HistorySuggestion] = []
    @Published public private(set) var draftError: HistoryDraftDiagnostic?

    // MARK: Suggestion catalog
    @Published public private(set) var keyChoices: [HistoryKeyChoice] = []
    @Published public private(set) var indexedHosts: [String] = []
    @Published public private(set) var indexedProcessPaths: [String] = []

    // #121: Live audit event notification
    public static let didRecordAuditNotification = NSNotification.Name("com.clavis.auditEventRecorded")

    public var calendar: Calendar
    private let storeFactory: () throws -> AuditStore
    private let keyring: AuditKeyring?
    private let contextProvider: @MainActor () -> LAContext?
    private var lockObserver: Any?
    private var localObservers: [NSObjectProtocol] = []
    private var distributedObservers: [NSObjectProtocol] = []
    private var lastPrunedSeq: Int64 = 0
    private var cursor: AuditCursor?
    /// Bumped by every committed query change; stale async results are discarded.
    private var generation: Int = 0
    private var loadTask: Task<Void, Never>?
    private var suggestionIndexStale = true
    private var isIndexingSuggestions = false

    /// Upper bound of rows examined per suggestion-index build (newest first).
    nonisolated static let suggestionScanLimit = 5_000
    /// Rows examined per batch while scanning for decrypt-time criteria.
    nonisolated static let scanBatchSize = 500

    public nonisolated static func makeDefaultKeyring() -> AuditKeyring? {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return nil
        }
        #endif
        return KeychainAuditKeyring()
    }

    private let notificationCenter: NotificationCenter

    public init(
        initialKeyFingerprint: String? = nil,
        store: @escaping () throws -> AuditStore = { try AuditStore() },
        keyring: AuditKeyring? = HistoryViewModel.makeDefaultKeyring(),
        contextProvider: @escaping @MainActor () -> LAContext? = { PanelLockController.shared.unlockContext },
        notificationCenter: NotificationCenter = .default,
        calendar: Calendar = .current
    ) {
        self.storeFactory = store
        self.keyring = keyring
        self.contextProvider = contextProvider
        self.notificationCenter = notificationCenter
        self.calendar = calendar
        self.query.limit = 200
        if let initialKeyFingerprint {
            self.filter.open(forKey: initialKeyFingerprint)
        }
        self.lockObserver = notificationCenter.addObserver(
            forName: PanelLockController.didLockNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                // Decrypted values must not outlive an unlocked panel.
                self.sensitive.removeAll()
                self.needsKeyContext = false
                self.indexedHosts = []
                self.indexedProcessPaths = []
                self.suggestionIndexStale = true
                self.refreshSuggestions()
            }
        }

        // #121: Live auto-reload observers
        let liveNames: [NSNotification.Name] = [
            Self.didRecordAuditNotification,
            NSNotification.Name("com.clavis.agentSigned"),
            NSNotification.Name("com.clavis.agentRateLimited"),
            NSNotification.Name("com.clavis.agentSessionsChanged")
        ]
        for name in liveNames {
            let obs = notificationCenter.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.suggestionIndexStale = true
                    self?.reload()
                }
            }
            self.localObservers.append(obs)
        }

        if notificationCenter === NotificationCenter.default && !ClavisEnvironment.isTesting {
            let distCenter = DistributedNotificationCenter.default()
            for name in liveNames {
                let obs = distCenter.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                    Task { @MainActor [weak self] in
                        self?.suggestionIndexStale = true
                        self?.reload()
                    }
                }
                self.distributedObservers.append(obs)
            }
        }
    }

    deinit {
        if let lockObserver {
            notificationCenter.removeObserver(lockObserver)
        }
        for obs in localObservers {
            notificationCenter.removeObserver(obs)
        }
        let distCenter = DistributedNotificationCenter.default()
        for obs in distributedObservers {
            distCenter.removeObserver(obs)
        }
    }

    // MARK: - Committed filter actions (one reducer boundary; each triggers at most one reload)

    /// The sidebar selection, derived from the Key badges.
    public var selectedKeyFingerprint: String? { filter.soleKey }

    public func openForKey(_ fingerprint: String?) {
        var next = filter
        next.open(forKey: fingerprint)
        draftReset()
        apply(next, force: true)
    }

    public func selectSidebarKey(_ fingerprint: String) {
        var next = filter
        next.selectSidebarKey(fingerprint)
        apply(next)
    }

    @discardableResult
    public func add(_ criterion: HistoryCriterion) -> Bool {
        var next = filter
        guard next.add(criterion) else { return false }
        apply(next)
        return true
    }

    public func removeCriterion(id: String) {
        var next = filter
        guard next.remove(id: id) else { return }
        apply(next)
    }

    public func clearFilters() {
        var next = filter
        next.clearFilters()
        apply(next)
    }

    /// Returns false (state untouched) when the interval would be invalid.
    @discardableResult
    public func setDateFrom(_ day: CalendarDay?) -> Bool {
        var next = filter
        guard next.dateBounds.setFrom(day) else { return false }
        apply(next)
        return true
    }

    @discardableResult
    public func setDateTo(_ day: CalendarDay?) -> Bool {
        var next = filter
        guard next.dateBounds.setTo(day) else { return false }
        apply(next)
        return true
    }

    public func setSortOrder(_ order: AuditSortOrder) {
        var next = filter
        next.sortOrder = order
        apply(next)
    }

    /// Session scope (story 002 AC5) is separate from badges.
    public func setSessionScope(_ sessionID: String?) {
        guard query.sessionID != sessionID else { return }
        query.sessionID = sessionID
        reload()
    }

    private func apply(_ next: HistoryFilter, force: Bool = false) {
        guard force || next != filter else { return }
        filter = next
        reload()
    }

    // MARK: - Draft

    public func updateDraft(text: String, caret: Int) {
        guard text != draftText || caret != draftCaret else { return }
        draftText = text
        draftCaret = caret
        draftError = nil
        refreshSuggestions()
    }

    private func draftReset() {
        draftText = ""
        draftCaret = 0
        draftError = nil
        suggestions = []
    }

    public var catalog: HistorySuggestionCatalog {
        HistorySuggestionCatalog(keys: keyChoices, hosts: indexedHosts, processPaths: indexedProcessPaths)
    }

    /// Replaces the key list used for suggestions and for resolving typed key names.
    public func updateKeys(_ keys: [SSHKeyInfo]) {
        setKeyChoices(keys.map { HistoryKeyChoice(fingerprint: $0.fingerprint, label: $0.label) })
    }

    func setKeyChoices(_ choices: [HistoryKeyChoice]) {
        guard choices != keyChoices else { return }
        keyChoices = choices
        refreshSuggestions()
    }

    public func label(forKeyFingerprint fingerprint: String) -> String {
        keyChoices.first { $0.fingerprint == fingerprint }?.label ?? String(fingerprint.prefix(16))
    }

    public var completionContext: HistoryCompletionContext? {
        HistoryCompletionEngine.context(text: draftText, caret: draftCaret)
    }

    /// `+ Filter`: start a fresh term after whatever is already typed, so the prefix list shows.
    public func prepareForNewFilter() {
        var text = draftText
        if !text.isEmpty, let last = text.last, !last.isWhitespace { text += " " }
        let caret = (text as NSString).length
        draftText = text
        draftCaret = caret
        draftError = nil
        refreshSuggestions()
    }

    /// Recomputes the dropdown for the caret position. Never touches committed state.
    public func refreshSuggestions() {
        guard let context = HistoryCompletionEngine.context(text: draftText, caret: draftCaret) else {
            suggestions = []
            return
        }
        suggestions = HistoryCompletionEngine.suggestions(for: context, catalog: catalog)
    }

    /// Accepting a prefix edits the draft; accepting a value commits one badge and consumes its token.
    public func accept(_ suggestion: HistorySuggestion) {
        guard let context = HistoryCompletionEngine.context(text: draftText, caret: draftCaret) else { return }
        switch suggestion.kind {
        case .prefix(let field):
            let edit = HistoryCompletionEngine.insertPrefix(field, text: draftText, context: context)
            draftText = edit.text
            draftCaret = edit.caret
            draftError = nil
            refreshSuggestions()   // now offers the values for this prefix
        case .value(let criterion):
            let edit = HistoryCompletionEngine.removeToken(text: draftText, context: context)
            draftText = edit.text
            draftCaret = edit.caret
            draftError = nil
            add(criterion)
            suggestions = []       // closed after committing; the field keeps focus
        }
    }

    /// Return on a typed expression. Commits every term or none (and reports why).
    @discardableResult
    public func commitDraft() -> Bool {
        let parse = HistoryExpressionParser.parse(draftText)
        if let first = parse.diagnostics.first {
            draftError = first
            return false
        }
        guard !parse.hasIncompleteTerm, !parse.terms.isEmpty else { return false }
        let resolved = HistoryDraftResolver.resolve(parse, catalog: catalog)
        if let first = resolved.diagnostics.first {
            draftError = first
            return false
        }
        var next = filter
        for c in resolved.criteria { next.add(c) }
        draftReset()
        apply(next)
        return true
    }

    // MARK: - Display helpers

    public func resolvedSensitive(for record: AuditRecord) -> AuditSensitive {
        if let unsealed = sensitive[record.seq], case .plaintext(let sens) = unsealed {
            return sens
        }
        return record.event.sensitive
    }

    public nonisolated static func operationTitle(
        for record: AuditRecord,
        sensitive: AuditSensitive? = nil
    ) -> String {
        let sens = sensitive ?? record.event.sensitive
        switch record.event.type {
        case .signature:
            if record.event.keyKind == .agent || record.event.reason == .viaAgentSession {
                return "Agent signature"
            }
            let isGit = record.event.reason == .viaGitGrant
                || record.event.reason == .gitOnlyKeyNonGitPayload
                || record.event.reason == .gitAnchorUnavailable
                || sens.processChain.contains { proc in
                    let name = (proc.executablePath as NSString).lastPathComponent.lowercased()
                    return name == "git" || name.hasPrefix("git-") || name == "ssh-keygen"
                }
            if isGit {
                return "Git commit signature"
            }
            return "SSH authentication"
        case .sessionStart:
            return "Agent session started"
        case .sessionExtend:
            return "Agent session extended"
        case .sessionRevoke:
            return "Agent session revoked"
        case .sessionEnd:
            return "Agent session ended"
        case .policyChange:
            return "Signing policy updated"
        case .keyCreate:
            return "Key created"
        case .keyImport:
            return "Key imported"
        case .keyDelete:
            return "Key deleted"
        case .keyKindChange:
            return "Key purpose updated"
        case .lock:
            return "Control panel locked"
        case .securityAlert:
            return "Security alert"
        case .suppressed:
            return "Suppressed signing events"
        }
    }

    public nonisolated static func statusLabel(for result: AuditResult) -> String {
        HistoryResult(result).title
    }

    // MARK: - Gap detection

    public nonisolated static func computeItems(
        from records: [AuditRecord],
        prunedThroughSeq: Int64 = 0,
        hasFilters: Bool = false
    ) -> [HistoryItem] {
        guard !hasFilters else {
            return records.map { .record($0) }
        }
        guard records.count > 1 else {
            return records.map { .record($0) }
        }
        var result: [HistoryItem] = []
        result.reserveCapacity(records.count)
        for i in 0 ..< records.count {
            result.append(.record(records[i]))
            if i < records.count - 1 {
                let current = records[i]
                let next = records[i + 1]
                if current.seq - next.seq > 1 && next.seq > prunedThroughSeq {
                    let missingCount = current.seq - next.seq - 1
                    result.append(.gap(fromSeq: next.seq + 1, toSeq: current.seq - 1, missingCount: missingCount))
                }
            }
        }
        return result
    }

    private func rebuildItems() {
        // Sequence-gap tamper hints only make sense for the unfiltered, seq-descending view.
        let seqDescending = zip(records, records.dropFirst()).allSatisfy { $0.seq > $1.seq }
        let filtered = !filter.isEmpty || query.hasFiltersExceptTimeRange
            || filter.sortOrder != .newestFirst || !seqDescending
        items = Self.computeItems(from: records, prunedThroughSeq: lastPrunedSeq, hasFilters: filtered)
    }

    // MARK: - Day grouping

    public nonisolated static func dayLabel(
        for date: Date,
        referenceDate: Date = Date(),
        calendar: Calendar = .current,
        locale: Locale = .current
    ) -> String {
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.setLocalizedDateFormatFromTemplate("MMMMdyyyy")
        let formattedDate = formatter.string(from: date)
        if calendar.isDate(date, inSameDayAs: referenceDate) {
            return "Today · \(formattedDate)"
        }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: referenceDate),
           calendar.isDate(date, inSameDayAs: yesterday) {
            return "Yesterday · \(formattedDate)"
        }
        return formattedDate
    }

    public func groupedSections(
        referenceDate: Date = Date(),
        calendar: Calendar? = nil,
        locale: Locale = .current
    ) -> [HistoryDaySection] {
        guard !items.isEmpty else { return [] }
        let calendar = calendar ?? self.calendar

        let keyFormatter = DateFormatter()
        keyFormatter.locale = Locale(identifier: "en_US_POSIX")
        keyFormatter.calendar = calendar
        keyFormatter.timeZone = calendar.timeZone
        keyFormatter.dateFormat = "yyyy-MM-dd"

        var sectionOrder: [String] = []
        var sectionTitles: [String: String] = [:]
        var sectionItems: [String: [HistoryItem]] = [:]
        var sectionRecordCounts: [String: Int] = [:]
        var currentKey: String?

        for item in items {
            switch item {
            case .record(let record):
                let dayKey = keyFormatter.string(from: record.event.time)
                currentKey = dayKey
                if sectionItems[dayKey] == nil {
                    sectionOrder.append(dayKey)
                    sectionTitles[dayKey] = Self.dayLabel(
                        for: record.event.time, referenceDate: referenceDate, calendar: calendar, locale: locale)
                    sectionItems[dayKey] = []
                    sectionRecordCounts[dayKey] = 0
                }
                sectionItems[dayKey]?.append(item)
                sectionRecordCounts[dayKey, default: 0] += 1
            case .gap:
                let targetKey = currentKey ?? sectionOrder.last ?? "gaps"
                if sectionItems[targetKey] == nil {
                    sectionOrder.append(targetKey)
                    sectionTitles[targetKey] = "Integrity Alerts"
                    sectionItems[targetKey] = []
                }
                sectionItems[targetKey]?.append(item)
            }
        }

        let lastKey = sectionOrder.last
        return sectionOrder.map { key in
            HistoryDaySection(
                id: key,
                title: sectionTitles[key] ?? key,
                totalCount: sectionRecordCounts[key] ?? 0,
                items: sectionItems[key] ?? [],
                // The last loaded day may continue in the next, unloaded batch.
                isComplete: !(key == lastKey && hasMore)
            )
        }
    }

    // MARK: - Loading

    private struct Page: Sendable {
        var matched: [AuditRecord] = []
        var unsealed: [Int64: AuditUnsealResult] = [:]
        var nextCursor: AuditCursor?
        var exhausted = false
        var unreadable = 0
    }

    private struct PageResult: Sendable {
        var page: Page
        var prunedSeq: Int64
        var total: Int?
        var needsKey: Bool
    }

    /// Scans newest/oldest-first batches until `pageSize` matches (or the data ends). SQL answers key,
    /// result and date criteria; host/process/text are applied after decrypting each batch.
    private nonisolated static func fetchPage(
        factory: () throws -> AuditStore,
        keyring: AuditKeyring?,
        context: LAContext?,
        filter: HistoryFilter,
        base: AuditQuery,
        calendar: Calendar,
        cursor: AuditCursor?,
        pageSize: Int,
        wantTotal: Bool
    ) throws -> (Page, Int64, Int?) {
        let store = try factory()
        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
        // `base` carries scope that is not a badge (session, types, kind) plus any raw store
        // constraints; badge-derived criteria are layered on top and only ever narrow it.
        var template = filter.auditQuery(limit: pageSize, calendar: calendar, sessionID: base.sessionID)
        template.types = base.types
        template.keyKind = base.keyKind
        template.keyFingerprint = base.keyFingerprint
        if !base.results.isEmpty {
            template.results = template.results.isEmpty ? base.results : template.results.intersection(base.results)
        }
        if let from = base.from { template.from = max(from, template.from ?? from) }
        if let to = base.to { template.to = to }
        let scanning = filter.needsSensitiveScan
        template.limit = scanning ? max(pageSize, scanBatchSize) : pageSize

        var page = Page()
        var current = cursor
        while true {
            try Task.checkCancellation()
            var q = template
            q.cursor = current
            let batch = try store.query(q)
            for record in batch {
                let result = unsealer.open(record)
                var readable: AuditSensitive?
                if case .plaintext(let s) = result { readable = s } else { page.unreadable += 1 }
                if filter.matchesSensitiveCriteria(record, sensitive: readable) {
                    page.matched.append(record)
                    page.unsealed[record.seq] = result
                }
            }
            if let last = batch.last { current = AuditCursor(record: last) }
            if batch.count < template.limit {
                page.exhausted = true
                break
            }
            if page.matched.count >= pageSize { break }
        }
        page.nextCursor = current

        let prunedSeq = Int64((try? store.meta("pruned_through_seq")) ?? "0") ?? 0
        var total: Int?
        if wantTotal, !scanning {
            var countQuery = template
            countQuery.cursor = nil
            total = try? store.count(countQuery)
        }
        return (page, prunedSeq, total)
    }

    /// Awaits the in-flight (and any superseding) load. For tests and scripted flows.
    public func waitForLoad() async {
        while let task = loadTask {
            await task.value
            if loadTask == task { break }
        }
    }

    @discardableResult
    public func reload() -> Task<Void, Never> {
        generation += 1
        let gen = generation
        loadTask?.cancel()
        isLoading = true
        isLoadingMore = false
        errorMessage = nil

        let factory = storeFactory
        let keyring = keyring
        let context = contextProvider()
        let filter = filter
        let base = query
        let calendar = calendar
        let pageSize = max(1, base.limit)

        let task = Task.detached { [weak self] in
            let mode = (try? keyring?.currentMode()) ?? .passwordOrBiometry
            let needsKey = mode.requiresPIN && (keyring?.validateCurrent(context: context) != .ok)
            do {
                let (page, pruned, total) = try Self.fetchPage(
                    factory: factory, keyring: keyring, context: context, filter: filter,
                    base: base, calendar: calendar, cursor: nil, pageSize: pageSize, wantTotal: true)
                await MainActor.run {
                    guard let self, self.generation == gen else { return }
                    self.records = page.matched
                    self.sensitive = page.unsealed
                    self.cursor = page.nextCursor
                    self.hasMore = !page.exhausted
                    self.totalMatching = total ?? (page.exhausted ? page.matched.count : nil)
                    self.unreadableScanned = page.unreadable
                    self.needsKeyContext = needsKey
                    self.lastPrunedSeq = pruned
                    self.isLoading = false
                    self.rebuildItems()
                }
            } catch is CancellationError {
                // Superseded by a newer query; that load owns the loading state.
            } catch {
                await MainActor.run {
                    guard let self, self.generation == gen else { return }
                    self.needsKeyContext = needsKey
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
        loadTask = task
        return task
    }

    @discardableResult
    public func loadMore() -> Task<Void, Never> {
        guard !isLoadingMore, !isLoading, hasMore, let cursor else {
            return Task {}
        }
        let gen = generation
        isLoadingMore = true

        let factory = storeFactory
        let keyring = keyring
        let context = contextProvider()
        let filter = filter
        let base = query
        let calendar = calendar
        let pageSize = max(1, base.limit)

        let task = Task.detached { [weak self] in
            do {
                let (page, pruned, _) = try Self.fetchPage(
                    factory: factory, keyring: keyring, context: context, filter: filter,
                    base: base, calendar: calendar, cursor: cursor, pageSize: pageSize, wantTotal: false)
                await MainActor.run {
                    guard let self, self.generation == gen else { return }
                    // De-duplicate across batches by event identity.
                    var seen = Set(self.records.map(\.event.id))
                    for record in page.matched where seen.insert(record.event.id).inserted {
                        self.records.append(record)
                    }
                    for (seq, res) in page.unsealed { self.sensitive[seq] = res }
                    self.cursor = page.nextCursor
                    self.hasMore = !page.exhausted
                    if page.exhausted { self.totalMatching = self.records.count }
                    self.unreadableScanned += page.unreadable
                    self.lastPrunedSeq = pruned
                    self.isLoadingMore = false
                    self.rebuildItems()
                }
            } catch is CancellationError {
                await MainActor.run {
                    guard let self, self.generation == gen else { return }
                    self.isLoadingMore = false
                }
            } catch {
                await MainActor.run {
                    guard let self, self.generation == gen else { return }
                    self.errorMessage = error.localizedDescription
                    self.isLoadingMore = false
                }
            }
        }
        return task
    }

    // MARK: - Suggestion index (hosts / processes)

    /// Builds host/process suggestions from a bounded scan of the newest events. The values are
    /// decrypted data, so the cache is dropped on panel lock; unreadable rows contribute nothing.
    @discardableResult
    public func ensureSuggestionIndex() -> Task<Void, Never> {
        guard suggestionIndexStale, !isIndexingSuggestions else { return Task {} }
        isIndexingSuggestions = true
        let factory = storeFactory
        let keyring = keyring
        let context = contextProvider()
        return Task.detached { [weak self] in
            var hostCounts: [String: Int] = [:]
            var processCounts: [String: Int] = [:]
            if let store = try? factory() {
                let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
                var q = AuditQuery(limit: Self.scanBatchSize)
                q.orderByTime = true
                var scanned = 0
                scan: while scanned < Self.suggestionScanLimit, !Task.isCancelled {
                    guard let batch = try? store.query(q), !batch.isEmpty else { break }
                    for record in batch {
                        scanned += 1
                        guard case .plaintext(let s) = unsealer.open(record) else { continue }
                        if let host = s.host.map(HistoryCriterion.canonicalHost), !host.isEmpty {
                            hostCounts[host, default: 0] += 1
                        }
                        if let peer = s.processChain.first {
                            processCounts[peer.executablePath, default: 0] += 1
                        }
                    }
                    if batch.count < q.limit { break scan }
                    q.cursor = AuditCursor(record: batch.last!)
                }
            }
            func ranked(_ d: [String: Int]) -> [String] {
                d.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map(\.key)
            }
            let hosts = ranked(hostCounts), procs = ranked(processCounts)
            await MainActor.run {
                guard let self else { return }
                self.indexedHosts = hosts
                self.indexedProcessPaths = procs
                self.suggestionIndexStale = false
                self.isIndexingSuggestions = false
                self.refreshSuggestions()
            }
        }
    }

    public func export(to url: URL) throws {
        let data = AuditExporter.export(records, unsealed: sensitive)
        try data.write(to: url, options: .atomic)
    }

    @discardableResult
    public func checkIntegrity(days: Int = 7) -> Task<Void, Never> {
        isCheckingIntegrity = true
        integrityCheckError = nil
        let factory = self.storeFactory
        return Task.detached {
            do {
                let store = try factory()
                let reader = LogWitnessReader()
                let witness = reader.read(days: days)
                let report = try AuditIntegrityChecker.check(
                    store: store,
                    witness: witness,
                    now: Date(),
                    days: days
                )
                await MainActor.run {
                    self.integrityReport = report
                    self.isCheckingIntegrity = false
                }
            } catch {
                await MainActor.run {
                    self.integrityCheckError = error.localizedDescription
                    self.isCheckingIntegrity = false
                }
            }
        }
    }
}
