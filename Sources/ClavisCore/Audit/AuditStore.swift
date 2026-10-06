import Foundation
import SQLite3

public enum AuditStoreError: Error, Equatable {
    case openFailed(Int32)
    case insecureLocation
    case prepareFailed(Int32)
    case stepFailed(Int32)
    case schemaTooNew(Int32)
}

public struct AuditEpoch: Equatable, Sendable {
    public let epochID: Data
    public let keyID: String
    public let epk: Data
    public let wrappedDEK: Data
    public let created: Date

    public init(epochID: Data, keyID: String, epk: Data, wrappedDEK: Data, created: Date = Date()) {
        self.epochID = epochID
        self.keyID = keyID
        self.epk = epk
        self.wrappedDEK = wrappedDEK
        self.created = created
    }

    public static func == (lhs: AuditEpoch, rhs: AuditEpoch) -> Bool {
        lhs.epochID == rhs.epochID
            && lhs.keyID == rhs.keyID
            && lhs.epk == rhs.epk
            && lhs.wrappedDEK == rhs.wrappedDEK
            && abs(lhs.created.timeIntervalSince1970 - rhs.created.timeIntervalSince1970) < 0.001
    }
}

public struct AuditQuery: Equatable {
    public var from: Date?
    public var to: Date?
    public var types: Set<AuditEventType> = []
    public var results: Set<AuditResult> = []
    public var keyFingerprint: String?
    public var keyKind: AuditKeyKind?
    public var sessionID: String?
    public var limit: Int = 500
    public var beforeSeq: Int64?

    public init(
        from: Date? = nil,
        to: Date? = nil,
        types: Set<AuditEventType> = [],
        results: Set<AuditResult> = [],
        keyFingerprint: String? = nil,
        keyKind: AuditKeyKind? = nil,
        sessionID: String? = nil,
        limit: Int = 500,
        beforeSeq: Int64? = nil
    ) {
        self.from = from
        self.to = to
        self.types = types
        self.results = results
        self.keyFingerprint = keyFingerprint
        self.keyKind = keyKind
        self.sessionID = sessionID
        self.limit = limit
        self.beforeSeq = beforeSeq
    }
}

public final class AuditStore {
    private static var customDefaultURL: URL?
    public static var defaultURL: URL {
        get {
            if let custom = customDefaultURL {
                return custom
            }
            if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
                return FileManager.default.temporaryDirectory.appendingPathComponent("clavis-audit-test.db")
            }
            return FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".config/clavis", isDirectory: true)
                .appendingPathComponent("audit.db", isDirectory: false)
        }
        set {
            customDefaultURL = newValue
        }
    }

    private let queue = DispatchQueue(label: "com.clavis.audit.store")
    private var db: OpaquePointer?
    private let url: URL

    private static let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    public init(url: URL = AuditStore.defaultURL) throws {
        self.url = url
        let dir = url.deletingLastPathComponent()
        try SecureFS.createDirectory(at: dir)
        guard SecureFS.isDirectorySecure(at: dir) else {
            throw AuditStoreError.insecureLocation
        }

        var fileStat = stat()
        if lstat(url.path, &fileStat) == 0 {
            if (fileStat.st_mode & S_IFMT) != S_IFREG {
                throw AuditStoreError.insecureLocation
            }
        }

        var resolvedDirBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let resolvedDirPath: String
        if realpath(dir.path, &resolvedDirBuffer) != nil {
            resolvedDirPath = String(cString: resolvedDirBuffer)
        } else {
            resolvedDirPath = dir.path
        }
        let resolvedURL = URL(fileURLWithPath: resolvedDirPath).appendingPathComponent(url.lastPathComponent)

        var rawDb: OpaquePointer?
        let openResult = SecureFS.withUmask(0o077) {
            sqlite3_open_v2(
                resolvedURL.path,
                &rawDb,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_FULLMUTEX,
                nil
            )
        }

        guard openResult == SQLITE_OK, let dbHandle = rawDb else {
            if let rawDb = rawDb {
                sqlite3_close(rawDb)
            }
            throw AuditStoreError.openFailed(openResult)
        }

        self.db = dbHandle
        chmod(resolvedURL.path, 0o600)
        Self.enforceAuxiliaryPermissions(for: resolvedURL)

        try executePragmas(on: dbHandle)
        try migrate(on: dbHandle)
    }

    deinit {
        close()
    }

    public func close() {
        queue.sync {
            if let dbHandle = db {
                sqlite3_close(dbHandle)
                db = nil
            }
        }
    }

    private static func enforceAuxiliaryPermissions(for url: URL) {
        let walPath = url.path + "-wal"
        let shmPath = url.path + "-shm"
        if FileManager.default.fileExists(atPath: walPath) {
            chmod(walPath, 0o600)
        }
        if FileManager.default.fileExists(atPath: shmPath) {
            chmod(shmPath, 0o600)
        }
    }

    private func executePragmas(on dbHandle: OpaquePointer) throws {
        let pragmas = [
            "PRAGMA journal_mode=WAL;",
            "PRAGMA synchronous=NORMAL;",
            "PRAGMA busy_timeout=2000;",
            "PRAGMA foreign_keys=ON;"
        ]
        for pragma in pragmas {
            if sqlite3_exec(dbHandle, pragma, nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
        }
    }

    private func migrate(on dbHandle: OpaquePointer) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(dbHandle, "PRAGMA user_version;", -1, &stmt, nil) == SQLITE_OK else {
            throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
        }
        defer { sqlite3_finalize(stmt) }

        var currentVersion: Int32
        if sqlite3_step(stmt) == SQLITE_ROW {
            currentVersion = sqlite3_column_int(stmt, 0)
        } else {
            currentVersion = 0
        }

        if currentVersion == 0 {
            let schemaSQL = """
            BEGIN IMMEDIATE;
            CREATE TABLE events (
              seq              INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id         TEXT    NOT NULL UNIQUE,
              time             REAL    NOT NULL,
              type             TEXT    NOT NULL,
              result           TEXT    NOT NULL,
              reason           TEXT,
              key_fingerprint  TEXT,
              key_kind         TEXT,
              session_id       TEXT,
              count            INTEGER NOT NULL DEFAULT 1,
              sensitive_format INTEGER NOT NULL,
              sensitive        BLOB    NOT NULL
            ) STRICT;
            CREATE INDEX idx_events_time    ON events(time);
            CREATE INDEX idx_events_key     ON events(key_fingerprint, time);
            CREATE INDEX idx_events_session ON events(session_id, time);
            CREATE INDEX idx_events_result  ON events(result, time);
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
            COMMIT;
            """
            var execErr: UnsafeMutablePointer<CChar>?
            if sqlite3_exec(dbHandle, schemaSQL, nil, nil, &execErr) != SQLITE_OK {
                let code = sqlite3_errcode(dbHandle)
                sqlite3_free(execErr)
                throw AuditStoreError.stepFailed(code)
            }
            if sqlite3_exec(dbHandle, "PRAGMA user_version = 1;", nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
            currentVersion = 1
        }

        if currentVersion == 1 {
            let v2SQL = """
            BEGIN IMMEDIATE;
            CREATE TABLE epochs (
              epoch_id    BLOB    PRIMARY KEY,
              key_id      TEXT    NOT NULL,
              epk         BLOB    NOT NULL,
              wrapped_dek BLOB    NOT NULL,
              created     REAL    NOT NULL
            ) STRICT;
            CREATE INDEX idx_events_format ON events(sensitive_format, seq);
            COMMIT;
            """
            var execErr: UnsafeMutablePointer<CChar>?
            if sqlite3_exec(dbHandle, v2SQL, nil, nil, &execErr) != SQLITE_OK {
                let code = sqlite3_errcode(dbHandle)
                sqlite3_free(execErr)
                throw AuditStoreError.stepFailed(code)
            }
            if sqlite3_exec(dbHandle, "PRAGMA user_version = 2;", nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
            currentVersion = 2
        } else if currentVersion > 2 {
            sqlite3_close(dbHandle)
            self.db = nil
            throw AuditStoreError.schemaTooNew(currentVersion)
        }
    }

    @discardableResult
    public func insert(_ event: AuditEvent, sensitiveFormat: Int, sensitiveBlob: Data) throws -> Int64 {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }

            let sql = """
            INSERT INTO events (
              event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_text(stmt, 1, event.id.uuidString, -1, Self.SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 2, event.time.timeIntervalSince1970)
            sqlite3_bind_text(stmt, 3, event.type.rawValue, -1, Self.SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, event.result.rawValue, -1, Self.SQLITE_TRANSIENT)

            if let reason = event.reason {
                sqlite3_bind_text(stmt, 5, reason.rawValue, -1, Self.SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 5)
            }

            if let kf = event.keyFingerprint {
                sqlite3_bind_text(stmt, 6, kf, -1, Self.SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 6)
            }

            if let kk = event.keyKind {
                sqlite3_bind_text(stmt, 7, kk.rawValue, -1, Self.SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 7)
            }

            if let sid = event.sessionID {
                sqlite3_bind_text(stmt, 8, sid, -1, Self.SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 8)
            }

            sqlite3_bind_int(stmt, 9, Int32(event.count))
            sqlite3_bind_int(stmt, 10, Int32(sensitiveFormat))

            _ = sensitiveBlob.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 11, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }

            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }

            Self.enforceAuxiliaryPermissions(for: url)
            return sqlite3_last_insert_rowid(dbHandle)
        }
    }

    @discardableResult
    public func insert(_ event: AuditEvent) throws -> Int64 {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let sensitiveData = try encoder.encode(event.sensitive)
        return try insert(event, sensitiveFormat: 0, sensitiveBlob: sensitiveData)
    }

    public func query(_ q: AuditQuery) throws -> [AuditRecord] {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }

            var clauses: [String] = []
            typealias Binder = (OpaquePointer, inout Int32) -> Void
            var binders: [Binder] = []

            if let from = q.from {
                clauses.append("time >= ?")
                let t = from.timeIntervalSince1970
                binders.append { stmt, idx in
                    sqlite3_bind_double(stmt, idx, t)
                    idx += 1
                }
            }

            if let to = q.to {
                clauses.append("time <= ?")
                let t = to.timeIntervalSince1970
                binders.append { stmt, idx in
                    sqlite3_bind_double(stmt, idx, t)
                    idx += 1
                }
            }

            if !q.types.isEmpty {
                let placeholders = q.types.map { _ in "?" }.joined(separator: ", ")
                clauses.append("type IN (\(placeholders))")
                let sortedTypes = q.types.sorted(by: { $0.rawValue < $1.rawValue })
                for t in sortedTypes {
                    let raw = t.rawValue
                    binders.append { stmt, idx in
                        sqlite3_bind_text(stmt, idx, raw, -1, Self.SQLITE_TRANSIENT)
                        idx += 1
                    }
                }
            }

            if !q.results.isEmpty {
                let placeholders = q.results.map { _ in "?" }.joined(separator: ", ")
                clauses.append("result IN (\(placeholders))")
                let sortedResults = q.results.sorted(by: { $0.rawValue < $1.rawValue })
                for r in sortedResults {
                    let raw = r.rawValue
                    binders.append { stmt, idx in
                        sqlite3_bind_text(stmt, idx, raw, -1, Self.SQLITE_TRANSIENT)
                        idx += 1
                    }
                }
            }

            if let kf = q.keyFingerprint {
                clauses.append("key_fingerprint = ?")
                binders.append { stmt, idx in
                    sqlite3_bind_text(stmt, idx, kf, -1, Self.SQLITE_TRANSIENT)
                    idx += 1
                }
            }

            if let kk = q.keyKind {
                clauses.append("key_kind = ?")
                let raw = kk.rawValue
                binders.append { stmt, idx in
                    sqlite3_bind_text(stmt, idx, raw, -1, Self.SQLITE_TRANSIENT)
                    idx += 1
                }
            }

            if let sid = q.sessionID {
                clauses.append("session_id = ?")
                binders.append { stmt, idx in
                    sqlite3_bind_text(stmt, idx, sid, -1, Self.SQLITE_TRANSIENT)
                    idx += 1
                }
            }

            if let bs = q.beforeSeq {
                clauses.append("seq < ?")
                binders.append { stmt, idx in
                    sqlite3_bind_int64(stmt, idx, bs)
                    idx += 1
                }
            }

            let whereSQL = clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND ")
            let sql = """
            SELECT seq, event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
            FROM events
            \(whereSQL)
            ORDER BY seq DESC
            LIMIT ?;
            """

            binders.append { stmt, idx in
                sqlite3_bind_int(stmt, idx, Int32(q.limit))
                idx += 1
            }

            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            var bindIndex: Int32 = 1
            for binder in binders {
                binder(stmt!, &bindIndex)
            }

            var records: [AuditRecord] = []
            let decoder = JSONDecoder()

            while sqlite3_step(stmt) == SQLITE_ROW {
                records.append(extractRecord(from: stmt!, decoder: decoder))
            }

            return records
        }
    }

    public func count() throws -> Int {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, "SELECT COUNT(*) FROM events;", -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_step(stmt) == SQLITE_ROW else {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
            return Int(sqlite3_column_int(stmt, 0))
        }
    }

    public func prune(olderThan cutoff: Date, maxRows: Int) throws -> Int {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }

            if sqlite3_exec(dbHandle, "BEGIN IMMEDIATE;", nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }

            var rollback = true
            defer {
                if rollback {
                    sqlite3_exec(dbHandle, "ROLLBACK;", nil, nil, nil)
                }
            }

            let cutoffTime = cutoff.timeIntervalSince1970
            var maxSeqOlder: Int64 = 0
            var olderCount: Int = 0

            // 1. Find max seq and count for time < cutoff
            var statStmt: OpaquePointer?
            if sqlite3_prepare_v2(dbHandle, "SELECT COALESCE(MAX(seq), 0), COUNT(*) FROM events WHERE time < ?;", -1, &statStmt, nil) == SQLITE_OK {
                sqlite3_bind_double(statStmt, 1, cutoffTime)
                if sqlite3_step(statStmt) == SQLITE_ROW {
                    maxSeqOlder = sqlite3_column_int64(statStmt, 0)
                    olderCount = Int(sqlite3_column_int(statStmt, 1))
                }
                sqlite3_finalize(statStmt)
            }

            // Delete older rows
            var delStmt: OpaquePointer?
            if sqlite3_prepare_v2(dbHandle, "DELETE FROM events WHERE time < ?;", -1, &delStmt, nil) == SQLITE_OK {
                sqlite3_bind_double(delStmt, 1, cutoffTime)
                _ = sqlite3_step(delStmt)
                sqlite3_finalize(delStmt)
            }

            // 2. Count remaining rows
            var countStmt: OpaquePointer?
            var remainingCount = 0
            if sqlite3_prepare_v2(dbHandle, "SELECT COUNT(*) FROM events;", -1, &countStmt, nil) == SQLITE_OK {
                if sqlite3_step(countStmt) == SQLITE_ROW {
                    remainingCount = Int(sqlite3_column_int(countStmt, 0))
                }
                sqlite3_finalize(countStmt)
            }

            var excessCount = 0
            var maxSeqExcess: Int64 = 0

            if remainingCount > maxRows {
                excessCount = remainingCount - maxRows
                // Find max seq of the oldest excess rows
                var excessStmt: OpaquePointer?
                let excessSql = "SELECT COALESCE(MAX(seq), 0) FROM (SELECT seq FROM events ORDER BY seq ASC LIMIT ?);"
                if sqlite3_prepare_v2(dbHandle, excessSql, -1, &excessStmt, nil) == SQLITE_OK {
                    sqlite3_bind_int(excessStmt, 1, Int32(excessCount))
                    if sqlite3_step(excessStmt) == SQLITE_ROW {
                        maxSeqExcess = sqlite3_column_int64(excessStmt, 0)
                    }
                    sqlite3_finalize(excessStmt)
                }

                // Delete excess oldest rows
                var delExcessStmt: OpaquePointer?
                let delExcessSql = "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY seq ASC LIMIT ?);"
                if sqlite3_prepare_v2(dbHandle, delExcessSql, -1, &delExcessStmt, nil) == SQLITE_OK {
                    sqlite3_bind_int(delExcessStmt, 1, Int32(excessCount))
                    _ = sqlite3_step(delExcessStmt)
                    sqlite3_finalize(delExcessStmt)
                }
            }

            let totalDeleted = olderCount + excessCount
            let highestDeletedSeq = max(maxSeqOlder, maxSeqExcess)

            if highestDeletedSeq > 0 {
                let currentPruned = Int64(try metaLocked(on: dbHandle, key: "pruned_through_seq") ?? "0") ?? 0
                let newPruned = max(currentPruned, highestDeletedSeq)
                try setMetaLocked(on: dbHandle, key: "pruned_through_seq", value: String(newPruned))
            }

            if sqlite3_exec(dbHandle, "COMMIT;", nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
            rollback = false

            return totalDeleted
        }
    }

    public func meta(_ key: String) throws -> String? {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            return try metaLocked(on: dbHandle, key: key)
        }
    }

    private func metaLocked(on dbHandle: OpaquePointer, key: String) throws -> String? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(dbHandle, "SELECT value FROM meta WHERE key = ?;", -1, &stmt, nil) == SQLITE_OK else {
            throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, key, -1, Self.SQLITE_TRANSIENT)
        if sqlite3_step(stmt) == SQLITE_ROW {
            return String(cString: sqlite3_column_text(stmt, 0))
        }
        return nil
    }

    public func setMeta(_ key: String, _ value: String) throws {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            try setMetaLocked(on: dbHandle, key: key, value: value)
        }
    }

    private func setMetaLocked(on dbHandle: OpaquePointer, key: String, value: String) throws {
        let sql = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, key, -1, Self.SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, value, -1, Self.SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
        }
    }

    public func insertEpoch(_ e: AuditEpoch) throws {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = "INSERT OR IGNORE INTO epochs (epoch_id, key_id, epk, wrapped_dek, created) VALUES (?, ?, ?, ?, ?);"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            _ = e.epochID.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 1, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            sqlite3_bind_text(stmt, 2, e.keyID, -1, Self.SQLITE_TRANSIENT)
            _ = e.epk.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 3, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            _ = e.wrappedDEK.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 4, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            sqlite3_bind_double(stmt, 5, e.created.timeIntervalSince1970)

            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
        }
    }

    public func epoch(id: Data) throws -> AuditEpoch? {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = "SELECT epoch_id, key_id, epk, wrapped_dek, created FROM epochs WHERE epoch_id = ?;"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            _ = id.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 1, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }

            guard sqlite3_step(stmt) == SQLITE_ROW else {
                return nil
            }
            return extractEpoch(from: stmt!)
        }
    }

    public func epochs() throws -> [AuditEpoch] {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = "SELECT epoch_id, key_id, epk, wrapped_dek, created FROM epochs ORDER BY created ASC;"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            var list: [AuditEpoch] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let epoch = extractEpoch(from: stmt!) {
                    list.append(epoch)
                }
            }
            return list
        }
    }

    public func updateEpochWrap(id: Data, keyID: String, epk: Data, wrappedDEK: Data) throws {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = "UPDATE epochs SET key_id = ?, epk = ?, wrapped_dek = ? WHERE epoch_id = ?;"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_text(stmt, 1, keyID, -1, Self.SQLITE_TRANSIENT)
            _ = epk.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 2, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            _ = wrappedDEK.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 3, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            _ = id.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 4, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }

            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
        }
    }

    private func extractEpoch(from stmt: OpaquePointer) -> AuditEpoch? {
        guard let epochIdPtr = sqlite3_column_blob(stmt, 0),
              let epkPtr = sqlite3_column_blob(stmt, 2),
              let wrappedPtr = sqlite3_column_blob(stmt, 3) else {
            return nil
        }
        let epochID = Data(bytes: epochIdPtr, count: Int(sqlite3_column_bytes(stmt, 0)))
        let keyID = String(cString: sqlite3_column_text(stmt, 1))
        let epk = Data(bytes: epkPtr, count: Int(sqlite3_column_bytes(stmt, 2)))
        let wrappedDEK = Data(bytes: wrappedPtr, count: Int(sqlite3_column_bytes(stmt, 3)))
        let created = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
        return AuditEpoch(epochID: epochID, keyID: keyID, epk: epk, wrappedDEK: wrappedDEK, created: created)
    }

    public func legacyPlaintextRows(limit: Int) throws -> [AuditRecord] {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = """
            SELECT seq, event_id, time, type, result, reason, key_fingerprint, key_kind, session_id, count, sensitive_format, sensitive
            FROM events
            WHERE sensitive_format = 0
            ORDER BY seq ASC
            LIMIT ?;
            """
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int(stmt, 1, Int32(limit))

            var records: [AuditRecord] = []
            let decoder = JSONDecoder()

            while sqlite3_step(stmt) == SQLITE_ROW {
                records.append(extractRecord(from: stmt!, decoder: decoder))
            }
            return records
        }
    }

    private func extractRecord(from stmt: OpaquePointer, decoder: JSONDecoder) -> AuditRecord {
        let seq = sqlite3_column_int64(stmt, 0)
        let eventIdStr = String(cString: sqlite3_column_text(stmt, 1))
        let eventId = UUID(uuidString: eventIdStr) ?? UUID()
        let time = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
        let typeStr = String(cString: sqlite3_column_text(stmt, 3))
        let type = AuditEventType(rawValue: typeStr) ?? .signature
        let resultStr = String(cString: sqlite3_column_text(stmt, 4))
        let result = AuditResult(rawValue: resultStr) ?? .info

        let reason: AuditReason?
        if sqlite3_column_type(stmt, 5) != SQLITE_NULL {
            reason = AuditReason(rawValue: String(cString: sqlite3_column_text(stmt, 5)))
        } else {
            reason = nil
        }

        let keyFingerprint: String?
        if sqlite3_column_type(stmt, 6) != SQLITE_NULL {
            keyFingerprint = String(cString: sqlite3_column_text(stmt, 6))
        } else {
            keyFingerprint = nil
        }

        let keyKind: AuditKeyKind?
        if sqlite3_column_type(stmt, 7) != SQLITE_NULL {
            keyKind = AuditKeyKind(rawValue: String(cString: sqlite3_column_text(stmt, 7)))
        } else {
            keyKind = nil
        }

        let sessionID: String?
        if sqlite3_column_type(stmt, 8) != SQLITE_NULL {
            sessionID = String(cString: sqlite3_column_text(stmt, 8))
        } else {
            sessionID = nil
        }

        let count = Int(sqlite3_column_int(stmt, 9))
        let sensitiveFormat = Int(sqlite3_column_int(stmt, 10))

        var blobData = Data()
        if let blobPtr = sqlite3_column_blob(stmt, 11) {
            let byteCount = Int(sqlite3_column_bytes(stmt, 11))
            blobData = Data(bytes: blobPtr, count: byteCount)
        }

        let sensitive: AuditSensitive
        let sealedSensitive: Data?
        if sensitiveFormat == 0 {
            sensitive = (try? decoder.decode(AuditSensitive.self, from: blobData)) ?? AuditSensitive()
            sealedSensitive = nil
        } else if sensitiveFormat == 1 {
            sensitive = AuditSensitive(keyLabel: nil, processChain: [], host: nil)
            sealedSensitive = blobData
        } else {
            sensitive = AuditSensitive(keyLabel: nil, processChain: [], host: nil)
            sealedSensitive = nil
        }

        let event = AuditEvent(
            id: eventId,
            time: time,
            type: type,
            result: result,
            reason: reason,
            keyFingerprint: keyFingerprint,
            keyKind: keyKind,
            sessionID: sessionID,
            count: count,
            sensitive: sensitive
        )
        return AuditRecord(seq: seq, event: event, sensitiveFormat: sensitiveFormat, sealedSensitive: sealedSensitive)
    }

    public func replaceSensitive(seq: Int64, expectedFormat: Int, newFormat: Int, blob: Data) throws -> Bool {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            let sql = "UPDATE events SET sensitive_format = ?, sensitive = ? WHERE seq = ? AND sensitive_format = ?;"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw AuditStoreError.prepareFailed(sqlite3_errcode(dbHandle))
            }
            defer { sqlite3_finalize(stmt) }

            sqlite3_bind_int(stmt, 1, Int32(newFormat))
            _ = blob.withUnsafeBytes { raw in
                sqlite3_bind_blob(stmt, 2, raw.baseAddress, Int32(raw.count), Self.SQLITE_TRANSIENT)
            }
            sqlite3_bind_int64(stmt, 3, seq)
            sqlite3_bind_int(stmt, 4, Int32(expectedFormat))

            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }

            return sqlite3_changes(dbHandle) > 0
        }
    }

    public func checkpoint() throws {
        try queue.sync {
            guard let dbHandle = db else {
                throw AuditStoreError.stepFailed(SQLITE_MISUSE)
            }
            if sqlite3_exec(dbHandle, "PRAGMA wal_checkpoint(TRUNCATE);", nil, nil, nil) != SQLITE_OK {
                throw AuditStoreError.stepFailed(sqlite3_errcode(dbHandle))
            }
        }
    }
}
