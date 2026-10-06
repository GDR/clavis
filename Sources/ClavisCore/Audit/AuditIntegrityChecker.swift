import Foundation

public struct AuditIntegrityReport: Equatable {
    public enum Status: Equatable {
        case ok
        case problems
        case unavailable(String)
    }

    public var status: Status
    public var missingRows: [(seq: Int64, loggedAt: Date?)]
    public var inconsistentRows: [Int64]
    public var unwitnessedRows: [Int64]
    public var truncatedTail: Bool
    public var gapsOutsideWindow: [ClosedRange<Int64>]
    public var checkedFrom: Date
    public var checkedRows: Int

    public init(
        status: Status,
        missingRows: [(seq: Int64, loggedAt: Date?)] = [],
        inconsistentRows: [Int64] = [],
        unwitnessedRows: [Int64] = [],
        truncatedTail: Bool = false,
        gapsOutsideWindow: [ClosedRange<Int64>] = [],
        checkedFrom: Date,
        checkedRows: Int = 0
    ) {
        self.status = status
        self.missingRows = missingRows
        self.inconsistentRows = inconsistentRows
        self.unwitnessedRows = unwitnessedRows
        self.truncatedTail = truncatedTail
        self.gapsOutsideWindow = gapsOutsideWindow
        self.checkedFrom = checkedFrom
        self.checkedRows = checkedRows
    }

    public static func == (lhs: AuditIntegrityReport, rhs: AuditIntegrityReport) -> Bool {
        guard lhs.status == rhs.status,
              lhs.inconsistentRows == rhs.inconsistentRows,
              lhs.unwitnessedRows == rhs.unwitnessedRows,
              lhs.truncatedTail == rhs.truncatedTail,
              lhs.gapsOutsideWindow == rhs.gapsOutsideWindow,
              abs(lhs.checkedFrom.timeIntervalSince1970 - rhs.checkedFrom.timeIntervalSince1970) < 0.001,
              lhs.checkedRows == rhs.checkedRows,
              lhs.missingRows.count == rhs.missingRows.count else {
            return false
        }
        for (l, r) in zip(lhs.missingRows, rhs.missingRows) {
            if l.seq != r.seq {
                return false
            }
            if let lDate = l.loggedAt, let rDate = r.loggedAt {
                if abs(lDate.timeIntervalSince1970 - rDate.timeIntervalSince1970) > 0.001 {
                    return false
                }
            } else if (l.loggedAt == nil) != (r.loggedAt == nil) {
                return false
            }
        }
        return true
    }
}

public enum AuditIntegrityChecker {
    public static func check(store: AuditStore, witness: WitnessReadResult, now: Date, days: Int) throws -> AuditIntegrityReport {
        let checkedFrom = now.addingTimeInterval(-Double(days) * 86400.0)

        // 1. .unavailable witness -> report .unavailable
        guard case .entries(let witnessEntries) = witness else {
            if case .unavailable(let reason) = witness {
                return AuditIntegrityReport(
                    status: .unavailable(reason),
                    checkedFrom: checkedFrom,
                    checkedRows: 0
                )
            }
            return AuditIntegrityReport(
                status: .unavailable("unknown"),
                checkedFrom: checkedFrom,
                checkedRows: 0
            )
        }

        // 2. pruned = Int64(meta("pruned_through_seq") ?? "0")
        let pruned = Int64(try store.meta("pruned_through_seq") ?? "0") ?? 0

        // 3. W = witness entries by seq (if duplicates: keep all; differing digests for one seq -> inconsistent)
        var witnessBySeq: [Int64: [AuditWitnessEntry]] = [:]
        var inconsistentSeqs = Set<Int64>()
        for w in witnessEntries {
            witnessBySeq[w.seq, default: []].append(w)
        }
        for (seq, list) in witnessBySeq {
            let digests = Set(list.map(\.digest))
            if digests.count > 1 {
                inconsistentSeqs.insert(seq)
            }
        }

        // 4. D = DB rows with seq > pruned and seq >= min(W.seq)
        let minWitnessSeq = witnessEntries.map(\.seq).min()
        let allRecords = try store.records(fromSeq: pruned + 1)
        var dbBySeq: [Int64: AuditRecord] = [:]
        for r in allRecords {
            dbBySeq[r.seq] = r
        }

        let dRecords: [AuditRecord]
        if let minWSeq = minWitnessSeq {
            dRecords = allRecords.filter { $0.seq >= minWSeq }
        } else {
            dRecords = allRecords
        }
        let checkedRows = dRecords.count

        // 5. For each w in W with w.seq > pruned: no row -> missing; row digest != w.digest -> inconsistent
        var missingRows: [(seq: Int64, loggedAt: Date?)] = []
        let witnessSeqs = witnessBySeq.keys.filter { $0 > pruned }.sorted()
        for seq in witnessSeqs {
            let entries = witnessBySeq[seq]!
            if let dbRow = dbBySeq[seq] {
                let rowDigest = AuditWitness.digest(for: dbRow)
                for w in entries {
                    if w.digest != rowDigest {
                        inconsistentSeqs.insert(seq)
                    }
                }
            } else {
                let loggedAt = entries.compactMap(\.loggedAt).first
                missingRows.append((seq: seq, loggedAt: loggedAt))
            }
        }

        // 6. For each DB row with time >= now - days and no witness -> unwitnessed (warning only, D4)
        var unwitnessedRows: [Int64] = []
        for r in allRecords where r.event.time >= checkedFrom {
            if witnessBySeq[r.seq] == nil {
                unwitnessedRows.append(r.seq)
            }
        }
        unwitnessedRows.sort()

        // 7. truncatedTail = (W.max.seq > D.max.seq); listed rows also appear in missing
        let maxWitnessSeq = witnessEntries.map(\.seq).max() ?? 0
        let maxDBSeq = allRecords.map(\.seq).max() ?? 0
        let truncatedTail = !witnessEntries.isEmpty && (maxWitnessSeq > maxDBSeq)

        // 8. Gaps in DB seq before min(W.seq) and > pruned -> gapsOutsideWindow
        var gapsOutsideWindow: [ClosedRange<Int64>] = []
        if let minWSeq = minWitnessSeq, minWSeq > pruned + 1 {
            let olderRecords = allRecords.filter { $0.seq < minWSeq && $0.seq > pruned }.sorted(by: { $0.seq < $1.seq })
            var expectedSeq = pruned + 1
            for r in olderRecords {
                if r.seq > expectedSeq {
                    gapsOutsideWindow.append(expectedSeq...(r.seq - 1))
                }
                expectedSeq = r.seq + 1
            }
            if minWSeq > expectedSeq {
                gapsOutsideWindow.append(expectedSeq...(minWSeq - 1))
            }
        }

        // 9. status = missing.isEmpty && inconsistent.isEmpty && !truncatedTail ? .ok : .problems
        let inconsistentList = Array(inconsistentSeqs).sorted()
        let status: AuditIntegrityReport.Status
        if missingRows.isEmpty && inconsistentList.isEmpty && !truncatedTail {
            status = .ok
        } else {
            status = .problems
        }

        return AuditIntegrityReport(
            status: status,
            missingRows: missingRows,
            inconsistentRows: inconsistentList,
            unwitnessedRows: unwitnessedRows,
            truncatedTail: truncatedTail,
            gapsOutsideWindow: gapsOutsideWindow,
            checkedFrom: checkedFrom,
            checkedRows: checkedRows
        )
    }
}
