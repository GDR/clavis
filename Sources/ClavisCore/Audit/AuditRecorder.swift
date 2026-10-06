import Foundation

public protocol AuditRecording: AnyObject {
    func record(_ event: AuditEvent)
}

public final class AuditRecorder: AuditRecording {
    public static let shared = AuditRecorder()

    private let storeFactory: () throws -> AuditStore
    private let now: () -> Date
    private let floodThreshold: Int
    private let floodWindow: TimeInterval
    private let retentionAge: TimeInterval
    private let retentionMaxRows: Int
    private let pruneEvery: Int

    private let queue = DispatchQueue(label: "com.clavis.audit.recorder")
    private var store: AuditStore?
    private var lastOpenFailureTime: Date?
    private var insertCounter = 0

    private struct FloodKey: Hashable {
        let type: AuditEventType
        let result: AuditResult
        let reason: AuditReason?
        let keyFingerprint: String?
    }

    private struct FloodBucket {
        var windowStart: Date
        var countInWindow: Int
        var suppressedCount: Int
    }

    private var buckets: [FloodKey: FloodBucket] = [:]

    public init(
        storeFactory: @escaping () throws -> AuditStore = { try AuditStore() },
        now: @escaping () -> Date = Date.init,
        floodThreshold: Int = 30,
        floodWindow: TimeInterval = 60,
        retentionAge: TimeInterval = 90 * 24 * 3600,
        retentionMaxRows: Int = 100_000,
        pruneEvery: Int = 1000
    ) {
        self.storeFactory = storeFactory
        self.now = now
        self.floodThreshold = floodThreshold
        self.floodWindow = floodWindow
        self.retentionAge = retentionAge
        self.retentionMaxRows = retentionMaxRows
        self.pruneEvery = pruneEvery
    }

    public func record(_ event: AuditEvent) {
        queue.sync {
            let currentTime = now()
            guard let store = getOrOpenStoreLocked(currentTime: currentTime) else {
                return
            }

            drainExpiredBucketsLocked(currentTime: currentTime, store: store)

            if isExempt(event) {
                insertEventLocked(event, into: store, currentTime: currentTime)
                return
            }

            let key = FloodKey(
                type: event.type,
                result: event.result,
                reason: event.reason,
                keyFingerprint: event.keyFingerprint
            )

            if var bucket = buckets[key] {
                if currentTime.timeIntervalSince(bucket.windowStart) < floodWindow {
                    if bucket.countInWindow < floodThreshold {
                        bucket.countInWindow += 1
                        buckets[key] = bucket
                        insertEventLocked(event, into: store, currentTime: currentTime)
                    } else {
                        bucket.suppressedCount += 1
                        buckets[key] = bucket
                    }
                } else {
                    if bucket.suppressedCount > 0 {
                        let aggEvent = AuditEvent(
                            time: bucket.windowStart.addingTimeInterval(floodWindow),
                            type: .suppressed,
                            result: key.result,
                            reason: key.reason,
                            keyFingerprint: key.keyFingerprint,
                            count: bucket.suppressedCount,
                            sensitive: AuditSensitive()
                        )
                        insertEventLocked(aggEvent, into: store, currentTime: currentTime)
                    }
                    buckets[key] = FloodBucket(windowStart: currentTime, countInWindow: 1, suppressedCount: 0)
                    insertEventLocked(event, into: store, currentTime: currentTime)
                }
            } else {
                buckets[key] = FloodBucket(windowStart: currentTime, countInWindow: 1, suppressedCount: 0)
                insertEventLocked(event, into: store, currentTime: currentTime)
            }
        }
    }

    public func flush() {
        queue.sync {
            let currentTime = now()
            guard let store = getOrOpenStoreLocked(currentTime: currentTime) else {
                return
            }

            for (key, bucket) in buckets {
                if bucket.suppressedCount > 0 {
                    let aggEvent = AuditEvent(
                        time: currentTime,
                        type: .suppressed,
                        result: key.result,
                        reason: key.reason,
                        keyFingerprint: key.keyFingerprint,
                        count: bucket.suppressedCount,
                        sensitive: AuditSensitive()
                    )
                    insertEventLocked(aggEvent, into: store, currentTime: currentTime)
                }
            }
            buckets.removeAll()
        }
    }

    private func isExempt(_ event: AuditEvent) -> Bool {
        switch event.type {
        case .keyCreate, .keyImport, .keyDelete, .keyKindChange, .lock:
            return true
        case .signature:
            return event.result == .allowed
        default:
            return false
        }
    }

    private func getOrOpenStoreLocked(currentTime: Date) -> AuditStore? {
        if let currentStore = store {
            return currentStore
        }
        if let lastFail = lastOpenFailureTime, currentTime.timeIntervalSince(lastFail) < 30 {
            return nil
        }
        do {
            let newStore = try storeFactory()
            self.store = newStore
            self.lastOpenFailureTime = nil
            try? newStore.prune(olderThan: currentTime.addingTimeInterval(-retentionAge), maxRows: retentionMaxRows)
            return newStore
        } catch {
            self.lastOpenFailureTime = currentTime
            ClavisLogger.log("AUDIT", "Failed to open audit store: \(error.localizedDescription)")
            return nil
        }
    }

    private func drainExpiredBucketsLocked(currentTime: Date, store: AuditStore) {
        var expiredKeys: [FloodKey] = []
        for (key, bucket) in buckets {
            if currentTime.timeIntervalSince(bucket.windowStart) >= floodWindow {
                if bucket.suppressedCount > 0 {
                    let aggEvent = AuditEvent(
                        time: bucket.windowStart.addingTimeInterval(floodWindow),
                        type: .suppressed,
                        result: key.result,
                        reason: key.reason,
                        keyFingerprint: key.keyFingerprint,
                        count: bucket.suppressedCount,
                        sensitive: AuditSensitive()
                    )
                    insertEventLocked(aggEvent, into: store, currentTime: currentTime)
                }
                expiredKeys.append(key)
            }
        }
        for key in expiredKeys {
            buckets.removeValue(forKey: key)
        }
    }

    private func insertEventLocked(_ event: AuditEvent, into store: AuditStore, currentTime: Date) {
        do {
            try store.insert(event)
            insertCounter += 1
            if insertCounter % pruneEvery == 0 {
                try? store.prune(olderThan: currentTime.addingTimeInterval(-retentionAge), maxRows: retentionMaxRows)
            }
        } catch {
            ClavisLogger.log("AUDIT", "Failed to insert audit event: \(error.localizedDescription)")
        }
    }
}
