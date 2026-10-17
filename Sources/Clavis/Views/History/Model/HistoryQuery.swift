import Foundation
import ClavisCore

// MARK: - Result vocabulary

/// User-facing result vocabulary shared by suggestions, badges and the filter.
/// Maps onto the store's `AuditResult` (several store results collapse into "Rejected").
public enum HistoryResult: String, CaseIterable, Hashable, Sendable {
    case approved, rejected, recorded

    public var title: String {
        switch self {
        case .approved: return "Approved"
        case .rejected: return "Rejected"
        case .recorded: return "Recorded"
        }
    }

    public var auditResults: Set<AuditResult> {
        switch self {
        case .approved: return [.allowed]
        case .rejected: return [.denied, .cancelled, .failed]
        case .recorded: return [.info]
        }
    }

    public init(_ result: AuditResult) {
        switch result {
        case .allowed: self = .approved
        case .denied, .cancelled, .failed: self = .rejected
        case .info: self = .recorded
        }
    }

    public init?(parsing text: String) {
        let needle = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard let match = Self.allCases.first(where: { $0.rawValue == needle }) else { return nil }
        self = match
    }
}

// MARK: - Criteria

public enum HistoryProcessMatch: Hashable, Sendable {
    /// Exact executable basename, case-insensitive (typed `Process:ssh`).
    case name(String)
    /// Exact executable path (chosen from suggestions; never collapses same-named binaries).
    case path(String)
}

/// One committed filter value == one badge. Values are canonical and typed;
/// display strings are derived at the view layer.
public enum HistoryCriterion: Hashable, Identifiable, Sendable {
    case host(String)               // canonical, see `canonicalHost`
    case process(HistoryProcessMatch)
    case key(String)                // key fingerprint (stable across renames)
    case result(HistoryResult)
    case text(String)               // trimmed free text; AND across terms

    public var id: String {
        switch self {
        case .host(let h): return "host:\(h)"
        case .process(.name(let n)): return "process:name:\(n)"
        case .process(.path(let p)): return "process:path:\(p)"
        case .key(let fp): return "key:\(fp)"
        case .result(let r): return "result:\(r.rawValue)"
        case .text(let t): return "text:\(t)"
        }
    }

    public var field: HistoryField? {
        switch self {
        case .host: return .host
        case .process: return .process
        case .key: return .key
        case .result: return .result
        case .text: return nil
        }
    }

    /// Hostnames are case-insensitive and may carry a trailing root dot.
    /// Filesystem paths are deliberately NOT canonicalised this way.
    public static func canonicalHost(_ raw: String) -> String {
        var h = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    public static func processMatch(forTyped raw: String) -> HistoryProcessMatch {
        let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.contains("/") ? .path(v) : .name(v.lowercased())
    }
}

/// Searchable field prefixes: `Host:`, `Process:`, `Key:`, `Result:`.
public enum HistoryField: String, CaseIterable, Identifiable, Sendable {
    case host, process, key, result

    public var id: String { rawValue }
    public var prefix: String {
        switch self {
        case .host: return "Host"
        case .process: return "Process"
        case .key: return "Key"
        case .result: return "Result"
        }
    }
    public var caption: String {
        switch self {
        case .host: return "Destination hostname"
        case .process: return "Executable name or path"
        case .key: return "Key name"
        case .result: return "Approved, rejected, or recorded"
        }
    }
    public var symbol: String {
        switch self {
        case .host: return "desktopcomputer"
        case .process: return "terminal"
        case .key: return "key"
        case .result: return "checkmark.circle"
        }
    }

    public init?(prefix: String) {
        let p = prefix.lowercased()
        guard let f = Self.allCases.first(where: { $0.prefix.lowercased() == p }) else { return nil }
        self = f
    }
}

// MARK: - Dates

/// A calendar day (no time) interpreted in a caller-supplied `Calendar`/time zone.
public struct CalendarDay: Hashable, Comparable, Sendable {
    public let year: Int
    public let month: Int
    public let day: Int

    public init(year: Int, month: Int, day: Int) {
        self.year = year; self.month = month; self.day = day
    }

    public init(_ date: Date, calendar: Calendar) {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        self.init(year: c.year ?? 1970, month: c.month ?? 1, day: c.day ?? 1)
    }

    public func startOfDay(in calendar: Calendar) -> Date {
        calendar.date(from: DateComponents(year: year, month: month, day: day)).map(calendar.startOfDay(for:))
            ?? Date(timeIntervalSince1970: 0)
    }

    /// Start of the following calendar day. Uses `Calendar` arithmetic, never 86 400 s.
    public func startOfNextDay(in calendar: Calendar) -> Date {
        calendar.date(byAdding: .day, value: 1, to: startOfDay(in: calendar)) ?? startOfDay(in: calendar)
    }

    public static func < (l: CalendarDay, r: CalendarDay) -> Bool {
        (l.year, l.month, l.day) < (r.year, r.month, r.day)
    }
}

/// Optional, independent inclusive day bounds. `nil` = unrestricted.
public struct HistoryDateBounds: Equatable, Sendable {
    public private(set) var from: CalendarDay?
    public private(set) var to: CalendarDay?

    public init(from: CalendarDay? = nil, to: CalendarDay? = nil) {
        self.from = from
        self.to = to
    }

    public var isEmpty: Bool { from == nil && to == nil }

    /// Rejects (returns false, no change) a start after the current end; never swaps silently.
    @discardableResult
    public mutating func setFrom(_ day: CalendarDay?) -> Bool {
        if let day, let to, day > to { return false }
        from = day
        return true
    }

    @discardableResult
    public mutating func setTo(_ day: CalendarDay?) -> Bool {
        if let day, let from, day < from { return false }
        to = day
        return true
    }

    /// `[start, endExclusive)` instants for the store. End is the start of the day AFTER `to`.
    public func range(in calendar: Calendar) -> (from: Date?, toExclusive: Date?) {
        (from?.startOfDay(in: calendar), to?.startOfNextDay(in: calendar))
    }

    public func contains(_ date: Date, in calendar: Calendar) -> Bool {
        let r = range(in: calendar)
        if let f = r.from, date < f { return false }
        if let t = r.toExclusive, date >= t { return false }
        return true
    }
}

// MARK: - Filter (committed state; single source of truth)

public struct HistoryFilter: Equatable, Sendable {
    /// Insertion-ordered so badges keep a stable, predictable order.
    public private(set) var criteria: [HistoryCriterion] = []
    public var dateBounds = HistoryDateBounds()
    public var sortOrder: AuditSortOrder = .newestFirst

    public init(criteria: [HistoryCriterion] = [], dateBounds: HistoryDateBounds = HistoryDateBounds(),
                sortOrder: AuditSortOrder = .newestFirst) {
        for c in criteria where !self.criteria.contains(c) { self.criteria.append(c) }
        self.dateBounds = dateBounds
        self.sortOrder = sortOrder
    }

    // Typed views
    public var hosts: Set<String> { Set(criteria.compactMap { if case .host(let h) = $0 { return h } else { return nil } }) }
    public var processes: Set<HistoryProcessMatch> { Set(criteria.compactMap { if case .process(let p) = $0 { return p } else { return nil } }) }
    public var keyFingerprints: [String] { criteria.compactMap { if case .key(let k) = $0 { return k } else { return nil } } }
    public var results: Set<HistoryResult> { Set(criteria.compactMap { if case .result(let r) = $0 { return r } else { return nil } }) }
    public var texts: [String] { criteria.compactMap { if case .text(let t) = $0 { return t } else { return nil } } }

    /// The sidebar selection is *derived*: exactly one Key badge selects that key; otherwise none.
    public var soleKey: String? {
        let keys = keyFingerprints
        return keys.count == 1 ? keys[0] : nil
    }

    public var isEmpty: Bool { criteria.isEmpty && dateBounds.isEmpty }

    /// True when committed criteria require decrypted fields (host/process/text),
    /// so neither the SQL layer nor an exact total can answer them alone.
    public var needsSensitiveScan: Bool {
        criteria.contains { c in
            switch c {
            case .host, .process, .text: return true
            case .key, .result: return false
            }
        }
    }

    // MARK: Reducer actions — the only way committed state changes.

    /// Adds a criterion. Returns false for an identical duplicate.
    @discardableResult
    public mutating func add(_ criterion: HistoryCriterion) -> Bool {
        guard !criteria.contains(criterion) else { return false }
        criteria.append(criterion)
        return true
    }

    @discardableResult
    public mutating func remove(id: String) -> Bool {
        guard let idx = criteria.firstIndex(where: { $0.id == id }) else { return false }
        criteria.remove(at: idx)
        return true
    }

    /// Opening History from key K: a fresh filter with exactly that Key badge (or none for "all keys").
    public mutating func open(forKey fingerprint: String?) {
        self = HistoryFilter(criteria: fingerprint.map { [.key($0)] } ?? [], sortOrder: sortOrder)
    }

    /// Sidebar click: replace every Key badge with exactly one; other criteria and dates stay.
    public mutating func selectSidebarKey(_ fingerprint: String) {
        let newKey = HistoryCriterion.key(fingerprint)
        if let firstIdx = criteria.firstIndex(where: { $0.field == .key }) {
            // Keep the badge's slot to avoid reordering unrelated badges.
            criteria.removeAll { $0.field == .key }
            criteria.insert(newKey, at: min(firstIdx, criteria.count))
        } else {
            criteria.insert(newKey, at: 0)
        }
    }

    /// Clears conditions and dates; keeps sort and — only when exactly one key is selected — that key.
    public mutating func clearFilters() {
        let keep = soleKey.map { [HistoryCriterion.key($0)] } ?? []
        criteria = keep
        dateBounds = HistoryDateBounds()
    }

    // MARK: Store query (SQL-answerable part)

    public func auditQuery(limit: Int, calendar: Calendar, sessionID: String?) -> AuditQuery {
        var q = AuditQuery(limit: limit)
        q.sortOrder = sortOrder
        q.orderByTime = true
        q.sessionID = sessionID
        q.keyFingerprints = Set(keyFingerprints)
        q.results = results.reduce(into: Set<AuditResult>()) { $0.formUnion($1.auditResults) }
        let r = dateBounds.range(in: calendar)
        q.from = r.from
        q.toExclusive = r.toExclusive
        return q
    }

    // MARK: Matching algebra

    /// (any host OR none) AND (any process OR none) AND (any key OR none)
    /// AND (any result OR none) AND all text terms AND date bounds.
    /// `sensitive == nil` means the sealed payload is unreadable: host/process/label
    /// criteria cannot match it.
    public func matches(_ record: AuditRecord, sensitive: AuditSensitive?, calendar: Calendar) -> Bool {
        guard dateBounds.contains(record.event.time, in: calendar) else { return false }
        let keys = keyFingerprints
        if !keys.isEmpty {
            guard let fp = record.event.keyFingerprint, keys.contains(fp) else { return false }
        }
        let rs = results
        if !rs.isEmpty, !rs.contains(HistoryResult(record.event.result)) { return false }
        return matchesSensitiveCriteria(record, sensitive: sensitive)
    }

    /// Only the criteria SQL cannot evaluate (host / process / text).
    public func matchesSensitiveCriteria(_ record: AuditRecord, sensitive: AuditSensitive?) -> Bool {
        let hs = hosts
        if !hs.isEmpty {
            guard let host = sensitive?.host, hs.contains(HistoryCriterion.canonicalHost(host)) else { return false }
        }
        let ps = processes
        if !ps.isEmpty {
            guard let peer = sensitive?.processChain.first, ps.contains(where: { Self.process(peer, matches: $0) }) else {
                return false
            }
        }
        for term in texts where !Self.record(record, sensitive: sensitive, containsText: term) {
            return false
        }
        return true
    }

    static func process(_ p: AuditProcess, matches m: HistoryProcessMatch) -> Bool {
        switch m {
        case .path(let path): return p.executablePath == path
        case .name(let name): return (p.executablePath as NSString).lastPathComponent.lowercased() == name
        }
    }

    /// Free-text semantics: case-insensitive substring over operation, type, result,
    /// key fingerprint, session id and (when readable) key label, host, process path/name/PID.
    static func record(_ record: AuditRecord, sensitive: AuditSensitive?, containsText q: String) -> Bool {
        func has(_ s: String?) -> Bool { s?.localizedCaseInsensitiveContains(q) ?? false }
        let e = record.event
        if has(HistoryViewModel.operationTitle(for: record, sensitive: sensitive))
            || has(e.type.rawValue)
            || has(HistoryViewModel.statusLabel(for: e.result))
            || has(e.result.rawValue)
            || has(e.keyFingerprint) || has(e.sessionID) { return true }
        guard let s = sensitive else { return false }
        if has(s.keyLabel) || has(s.host) { return true }
        return s.processChain.contains {
            has($0.executablePath) || has(($0.executablePath as NSString).lastPathComponent) || String($0.pid).contains(q)
        }
    }
}
