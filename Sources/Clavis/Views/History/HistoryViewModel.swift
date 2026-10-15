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
    }

    public func recordMatchesFilter(_ record: AuditRecord) -> Bool {
        let unsealed = sensitive[record.seq]
        let eventSensitive = record.event.sensitive

        // 1. Search text (matches key label, fingerprint, remote host, process or PID, session ID)
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !q.isEmpty {
            var matched = false
            // Fingerprint
            if let fp = record.event.keyFingerprint, fp.localizedCaseInsensitiveContains(q) {
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
        if let remoteHost = filterRemoteHost, !remoteHost.isEmpty {
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
