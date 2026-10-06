import Foundation

public final class AuditResealer: @unchecked Sendable {
    private let storeFactory: () throws -> AuditStore
    private let sealer: AuditSealer
    private let batchSize: Int
    private let interval: TimeInterval
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.clavis.audit.resealer")
    private var isRunning = false

    public init(
        storeFactory: @escaping () throws -> AuditStore = { try AuditStore() },
        sealer: AuditSealer = AuditSealer(keyring: KeychainAuditKeyring()),
        batchSize: Int = 200,
        interval: TimeInterval = 60
    ) {
        self.storeFactory = storeFactory
        self.sealer = sealer
        self.batchSize = batchSize
        self.interval = interval
    }

    public func start() {
        queue.async {
            guard !self.isRunning else { return }
            self.isRunning = true
            self.runBatchLocked()
            self.scheduleTimerLocked()
        }
    }

    public func stop() {
        queue.async {
            self.isRunning = false
            self.timer?.cancel()
            self.timer = nil
        }
    }

    @discardableResult
    public func runBatch() -> Int {
        queue.sync {
            runBatchLocked()
        }
    }

    @discardableResult
    private func runBatchLocked() -> Int {
        do {
            let store = try storeFactory()
            let rows = try store.legacyPlaintextRows(limit: batchSize)
            guard !rows.isEmpty else {
                self.isRunning = false
                self.timer?.cancel()
                self.timer = nil
                return 0
            }
            var count = 0
            for record in rows {
                let (fmt, blob) = sealer.seal(record.event, store: store)
                let ok = try store.replaceSensitive(
                    seq: record.seq,
                    expectedFormat: 0,
                    newFormat: fmt,
                    blob: blob
                )
                if ok { count += 1 }
            }
            if rows.count < batchSize {
                self.isRunning = false
                self.timer?.cancel()
                self.timer = nil
            }
            return count
        } catch {
            return 0
        }
    }

    private func scheduleTimerLocked() {
        guard isRunning else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            self?.runBatchLocked()
        }
        self.timer = timer
        timer.resume()
    }
}
