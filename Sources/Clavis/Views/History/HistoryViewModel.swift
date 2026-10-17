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

public struct HistoryHostSuggestion: Identifiable, Equatable, Sendable {
    public let host: String
    public let count: Int

    public var id: String { host }

    public init(host: String, count: Int) {
        self.host = host
        self.count = count
    }
}

public struct HistoryDaySection: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let totalCount: Int
    public let items: [HistoryItem]

    public init(id: String, title: String, totalCount: Int, items: [HistoryItem]) {
        self.id = id
        self.title = title
        self.totalCount = totalCount
        self.items = items
    }
}

extension AuditQuery {
    public var hasFiltersExceptTimeRange: Bool {
        !types.isEmpty || !results.isEmpty || keyFingerprint != nil || keyKind != nil || sessionID != nil
    }
}

@MainActor
public final class HistoryViewModel: ObservableObject {
    @Published public var records: [AuditRecord] = []
    @Published public var items: [HistoryItem] = []
    @Published public var sensitive: [Int64: AuditUnsealResult] = [:]
    @Published public var query: AuditQuery = AuditQuery()
    @Published public var errorMessage: String?
    @Published public var isLoading: Bool = false
    @Published public var integrityReport: AuditIntegrityReport?
    @Published public var isCheckingIntegrity: Bool = false
    @Published public var integrityCheckError: String?
    @Published public var needsKeyContext: Bool = false

    // #122: Search and filtering properties
    @Published public var searchText: String = "" {
        didSet {
            if searchText != oldValue {
                applyFiltering()
            }
        }
    }
    @Published public var filterKeyLabel: String? {
        didSet {
            if filterKeyLabel != oldValue {
                applyFiltering()
            }
        }
    }
    @Published public var filterRemoteHost: String? {
        didSet {
            if filterRemoteHost != oldValue {
                applyFiltering()
            }
        }
    }
    @Published public var filterProcessOrPID: String? {
        didSet {
            if filterProcessOrPID != oldValue {
                applyFiltering()
            }
        }
    }
    @Published public var selectedDate: Date? = nil {
        didSet {
            if selectedDate != oldValue {
                applyFiltering()
            }
        }
    }

    /// Inclusive calendar-day range filter (start of `dateRangeStart` … end of `dateRangeEnd`).
    @Published public var dateRangeStart: Date? = nil {
        didSet { if dateRangeStart != oldValue { applyFiltering() } }
    }
    @Published public var dateRangeEnd: Date? = nil {
        didSet { if dateRangeEnd != oldValue { applyFiltering() } }
    }

    // #123: Pagination properties
    @Published public var hasMore: Bool = false
    @Published public var isLoadingMore: Bool = false

    // #121: Live audit event notification
    public static let didRecordAuditNotification = NSNotification.Name("com.clavis.auditEventRecorded")

    private let storeFactory: () throws -> AuditStore
    private let keyring: AuditKeyring?
    private let contextProvider: @MainActor () -> LAContext?
    private var lockObserver: Any?
    private var localObservers: [NSObjectProtocol] = []
    private var distributedObservers: [NSObjectProtocol] = []
    private var rawRecords: [AuditRecord] = []
    private var lastPrunedSeq: Int64 = 0

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
        notificationCenter: NotificationCenter = .default
    ) {
        self.storeFactory = store
        self.keyring = keyring
        self.contextProvider = contextProvider
        self.notificationCenter = notificationCenter
        self.query.limit = 200
        if let initialKeyFingerprint {
            self.query.keyFingerprint = initialKeyFingerprint
        }
        self.lockObserver = notificationCenter.addObserver(
            forName: PanelLockController.didLockNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.sensitive.removeAll()
                self?.needsKeyContext = false
            }
        }

        // #121: Live auto-reload observers
        let localNames: [NSNotification.Name] = [
            Self.didRecordAuditNotification,
            NSNotification.Name("com.clavis.agentSigned"),
            NSNotification.Name("com.clavis.agentRateLimited"),
            NSNotification.Name("com.clavis.agentSessionsChanged")
        ]
        for name in localNames {
            let obs = notificationCenter.addObserver(
                forName: name,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.reload()
                }
            }
            self.localObservers.append(obs)
        }

        if notificationCenter === NotificationCenter.default && !ClavisEnvironment.isTesting {
            let distCenter = DistributedNotificationCenter.default()
            let distNames: [NSNotification.Name] = [
                Self.didRecordAuditNotification,
                NSNotification.Name("com.clavis.agentSigned"),
                NSNotification.Name("com.clavis.agentRateLimited"),
                NSNotification.Name("com.clavis.agentSessionsChanged")
            ]
            for name in distNames {
                let obs = distCenter.addObserver(
                    forName: name,
                    object: nil,
                    queue: .main
                ) { [weak self] _ in
                    Task { @MainActor [weak self] in
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

    public func computeItems(from records: [AuditRecord], prunedThroughSeq: Int64) -> [HistoryItem] {
        Self.computeItems(
            from: records,
            prunedThroughSeq: prunedThroughSeq,
            hasFilters: query.hasFiltersExceptTimeRange || hasCustomFilters
        )
    }

    private var hasCustomFilters: Bool {
        !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || (filterKeyLabel != nil && !filterKeyLabel!.isEmpty)
            || (filterRemoteHost != nil && !filterRemoteHost!.isEmpty)
            || (filterProcessOrPID != nil && !filterProcessOrPID!.isEmpty)
            || selectedDate != nil
            || dateRangeStart != nil
            || dateRangeEnd != nil
    }

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
        switch result {
        case .allowed:
            return "Approved"
        case .denied, .cancelled, .failed:
            return "Rejected"
        case .info:
            return "Recorded"
        }
    }

    public func recordMatchesFilter(_ record: AuditRecord, ignoreRemoteHost: Bool = false) -> Bool {
        let unsealed = sensitive[record.seq]
        let eventSensitive = record.event.sensitive
        let resolvedSens = resolvedSensitive(for: record)

        // 0. Selected date filter (calendar day match)
        if let selectedDate {
            if !Calendar.current.isDate(record.event.time, inSameDayAs: selectedDate) {
                return false
            }
        }
        // 0b. Inclusive day range
        let cal = Calendar.current
        if let start = dateRangeStart, record.event.time < cal.startOfDay(for: start) {
            return false
        }
        if let end = dateRangeEnd,
           let limit = cal.date(byAdding: .day, value: 1, to: cal.startOfDay(for: end)),
           record.event.time >= limit {
            return false
        }

        // 1. Search text (matches operation, result status, key label, fingerprint, remote host, process or PID, session ID)
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !q.isEmpty {
            var matched = false
            // Operation title & event type
            let opTitle = Self.operationTitle(for: record, sensitive: resolvedSens)
            if opTitle.localizedCaseInsensitiveContains(q)
                || record.event.type.rawValue.localizedCaseInsensitiveContains(q) {
                matched = true
            }
            // Result status ("Approved" / "Rejected" / rawValue)
            if !matched {
                let status = Self.statusLabel(for: record.event.result)
                if status.localizedCaseInsensitiveContains(q)
                    || record.event.result.rawValue.localizedCaseInsensitiveContains(q) {
                    matched = true
                }
            }
            // Fingerprint
            if !matched, let fp = record.event.keyFingerprint, fp.localizedCaseInsensitiveContains(q) {
                matched = true
            }
            // Session ID
            if !matched, let sid = record.event.sessionID, sid.localizedCaseInsensitiveContains(q) {
                matched = true
            }
            // Sensitive fields from unsealed result
            if !matched, let unsealed, case .plaintext(let sens) = unsealed {
                if let label = sens.keyLabel, label.localizedCaseInsensitiveContains(q) {
                    matched = true
                }
                if !matched, let host = sens.host, host.localizedCaseInsensitiveContains(q) {
                    matched = true
                }
                if !matched {
                    for proc in sens.processChain {
                        if proc.executablePath.localizedCaseInsensitiveContains(q)
                            || (proc.executablePath as NSString).lastPathComponent.localizedCaseInsensitiveContains(q)
                            || String(proc.pid).contains(q) {
                            matched = true
                            break
                        }
                    }
                }
            }
            // Sensitive fields from event.sensitive fallback
            if !matched {
                if let label = eventSensitive.keyLabel, label.localizedCaseInsensitiveContains(q) {
                    matched = true
                }
                if !matched, let host = eventSensitive.host, host.localizedCaseInsensitiveContains(q) {
                    matched = true
                }
                if !matched {
                    for proc in eventSensitive.processChain {
                        if proc.executablePath.localizedCaseInsensitiveContains(q)
                            || (proc.executablePath as NSString).lastPathComponent.localizedCaseInsensitiveContains(q)
                            || String(proc.pid).contains(q) {
                            matched = true
                            break
                        }
                    }
                }
            }
            if !matched {
                return false
            }
        }

        // 2. Specific key label filter
        if let keyLabel = filterKeyLabel, !keyLabel.isEmpty {
            let label: String? = {
                if let unsealed, case .plaintext(let sens) = unsealed {
                    return sens.keyLabel
                }
                return eventSensitive.keyLabel
            }()
            guard let l = label, l.localizedCaseInsensitiveContains(keyLabel) else {
                return false
            }
        }

        // 3. Specific remote host filter
        if !ignoreRemoteHost, let remoteHost = filterRemoteHost, !remoteHost.isEmpty {
            let host: String? = {
                if let unsealed, case .plaintext(let sens) = unsealed {
                    return sens.host
                }
                return eventSensitive.host
            }()
            guard let h = host, h.localizedCaseInsensitiveContains(remoteHost) else {
                return false
            }
        }

        // 4. Specific process or PID filter
        if let processOrPID = filterProcessOrPID, !processOrPID.isEmpty {
            let chain: [AuditProcess] = {
                if let unsealed, case .plaintext(let sens) = unsealed {
                    return sens.processChain
                }
                return eventSensitive.processChain
            }()
            let matched = chain.contains { proc in
                proc.executablePath.localizedCaseInsensitiveContains(processOrPID)
                    || (proc.executablePath as NSString).lastPathComponent.localizedCaseInsensitiveContains(processOrPID)
                    || String(proc.pid).contains(processOrPID)
            }
            if !matched {
                return false
            }
        }

        return true
    }

    public func hostSuggestions(matching queryText: String = "") -> [HistoryHostSuggestion] {
        let trimmed = queryText.trimmingCharacters(in: .whitespacesAndNewlines)
        var distinctHosts: [String] = []
        var seenHosts = Set<String>()
        var countsByHost: [String: Int] = [:]

        for record in rawRecords {
            let sens = resolvedSensitive(for: record)
            guard let rawHost = sens.host?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !rawHost.isEmpty else {
                continue
            }
            if !seenHosts.contains(rawHost) {
                seenHosts.insert(rawHost)
                distinctHosts.append(rawHost)
            }
            if recordMatchesFilter(record, ignoreRemoteHost: true) {
                countsByHost[rawHost, default: 0] += 1
            }
        }

        let matchingHosts = distinctHosts.filter { host in
            trimmed.isEmpty || host.localizedCaseInsensitiveContains(trimmed)
        }
        return matchingHosts.map { host in
            HistoryHostSuggestion(host: host, count: countsByHost[host, default: 0])
        }
    }

    public nonisolated static func dayLabel(
        for date: Date,
        referenceDate: Date = Date(),
        calendar: Calendar = .current
    ) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateFormat = "MMMM d, yyyy"
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
        calendar: Calendar = .current
    ) -> [HistoryDaySection] {
        guard !items.isEmpty else { return [] }

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
                        for: record.event.time,
                        referenceDate: referenceDate,
                        calendar: calendar
                    )
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

        return sectionOrder.map { key in
            HistoryDaySection(
                id: key,
                title: sectionTitles[key] ?? key,
                totalCount: sectionRecordCounts[key] ?? 0,
                items: sectionItems[key] ?? []
            )
        }
    }

    public func clearDateFilter() {
        selectedDate = nil
        dateRangeStart = nil
        dateRangeEnd = nil
    }

    public func resetFilters() {
        dateRangeStart = nil
        dateRangeEnd = nil
        searchText = ""
        filterKeyLabel = nil
        filterRemoteHost = nil
        filterProcessOrPID = nil
        selectedDate = nil
        query.keyFingerprint = nil
        query.keyKind = nil
        query.results = []
        query.types = []
        query.from = nil
        query.to = nil
        query.sessionID = nil
        applyFiltering()
    }

    public func applyFiltering(prunedSeq: Int64? = nil) {
        if let prunedSeq {
            self.lastPrunedSeq = prunedSeq
        }
        let filtered = rawRecords.filter { recordMatchesFilter($0) }
        self.records = filtered
        let hasAnyFilter = query.hasFiltersExceptTimeRange || hasCustomFilters
        self.items = HistoryViewModel.computeItems(
            from: filtered,
            prunedThroughSeq: self.lastPrunedSeq,
            hasFilters: hasAnyFilter
        )
    }

    @discardableResult
    public func reload() -> Task<Void, Never> {
        isLoading = true
        errorMessage = nil
        var currentQuery = query
        currentQuery.beforeSeq = nil

        let factory = self.storeFactory
        let keyring = self.keyring
        let context = self.contextProvider()
        return Task.detached {
            let mode = (try? keyring?.currentMode()) ?? .passwordOrBiometry
            let needsKey = mode.requiresPIN && (keyring?.validateCurrent(context: context) != .ok)
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                let prunedSeq = Int64((try? store.meta("pruned_through_seq")) ?? "0") ?? 0
                let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
                var unsealedMap: [Int64: AuditUnsealResult] = [:]
                for rec in fetched {
                    unsealedMap[rec.seq] = unsealer.open(rec)
                }
                let finalMap = unsealedMap
                await MainActor.run {
                    self.rawRecords = fetched
                    self.sensitive = finalMap
                    self.needsKeyContext = needsKey
                    self.hasMore = fetched.count >= currentQuery.limit
                    self.isLoading = false
                    self.applyFiltering(prunedSeq: prunedSeq)
                }
            } catch {
                await MainActor.run {
                    self.needsKeyContext = needsKey
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }

    @discardableResult
    public func loadMore() -> Task<Void, Never> {
        guard !isLoadingMore else {
            return Task {}
        }
        guard let lastSeq = rawRecords.last?.seq else {
            hasMore = false
            return Task {}
        }
        isLoadingMore = true
        var currentQuery = query
        currentQuery.beforeSeq = lastSeq

        let factory = self.storeFactory
        let keyring = self.keyring
        let context = self.contextProvider()
        return Task.detached {
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                let prunedSeq = Int64((try? store.meta("pruned_through_seq")) ?? "0") ?? 0
                let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
                var unsealedMap: [Int64: AuditUnsealResult] = [:]
                for rec in fetched {
                    unsealedMap[rec.seq] = unsealer.open(rec)
                }
                let finalMap = unsealedMap
                await MainActor.run {
                    self.rawRecords.append(contentsOf: fetched)
                    for (seq, res) in finalMap {
                        self.sensitive[seq] = res
                    }
                    self.hasMore = fetched.count >= currentQuery.limit
                    self.isLoadingMore = false
                    self.applyFiltering(prunedSeq: prunedSeq)
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isLoadingMore = false
                }
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
