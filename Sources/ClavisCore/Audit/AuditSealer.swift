import Foundation
import CryptoKit

public final class AuditSealer: @unchecked Sendable {
    private let keyring: AuditKeyring
    private let now: () -> Date
    private let maxEpochAge: TimeInterval
    private let maxEpochRows: Int

    private let lock = NSLock()
    private struct ActiveEpoch {
        let epochID: Data
        let dek: SymmetricKey
        let keyID: String
        let created: Date
        var rows: Int
    }
    private var currentEpoch: ActiveEpoch?
    private var observer: NSObjectProtocol?

    public init(
        keyring: AuditKeyring,
        now: @escaping () -> Date = Date.init,
        maxEpochAge: TimeInterval = 3600,
        maxEpochRows: Int = 1000
    ) {
        self.keyring = keyring
        self.now = now
        self.maxEpochAge = maxEpochAge
        self.maxEpochRows = maxEpochRows

        self.observer = DistributedNotificationCenter.default().addObserver(
            forName: KeychainAuditKeyring.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.lock.lock()
            self?.currentEpoch = nil
            self?.lock.unlock()
        }
    }

    deinit {
        if let observer = observer {
            DistributedNotificationCenter.default().removeObserver(observer)
        }
    }

    /// Returns (format, blob). Never throws: on any error returns (2, Data()).
    public func seal(_ event: AuditEvent, store: AuditStore) -> (Int, Data) {
        lock.lock()
        defer { lock.unlock() }

        do {
            let active = try getOrRotateEpochLocked(store: store)
            let aad = AuditCrypto.rowAAD(
                eventID: event.id,
                time: event.time,
                type: event.type,
                fingerprint: event.keyFingerprint
            )
            let blob = try AuditCrypto.sealRow(
                event.sensitive,
                dek: active.dek,
                epochID: active.epochID,
                aad: aad
            )
            currentEpoch?.rows += 1
            return (1, blob)
        } catch {
            return (2, Data())
        }
    }

    private func getOrRotateEpochLocked(store: AuditStore) throws -> ActiveEpoch {
        let currentTime = now()
        let pubKey = try keyring.currentPublicKey()

        if let epoch = currentEpoch {
            let isTooOld = currentTime.timeIntervalSince(epoch.created) >= maxEpochAge
            let isTooManyRows = epoch.rows >= maxEpochRows
            let isKeyChanged = epoch.keyID != pubKey.keyID
            if !isTooOld && !isTooManyRows && !isKeyChanged {
                return epoch
            }
        }

        let epochID = AuditCrypto.newEpochID()
        let dek = AuditCrypto.newDEK()
        let (epk, wrappedDEK) = try AuditCrypto.wrapDEK(
            dek,
            epochID: epochID,
            keyID: pubKey.keyID,
            to: pubKey.publicKey
        )
        let epochRecord = AuditEpoch(
            epochID: epochID,
            keyID: pubKey.keyID,
            epk: epk,
            wrappedDEK: wrappedDEK,
            created: currentTime
        )
        try store.insertEpoch(epochRecord)

        let newEpoch = ActiveEpoch(
            epochID: epochID,
            dek: dek,
            keyID: pubKey.keyID,
            created: currentTime,
            rows: 0
        )
        currentEpoch = newEpoch
        return newEpoch
    }
}
