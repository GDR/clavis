import Foundation
import CryptoKit
import LocalAuthentication

public enum AuditUnsealResult: Equatable, Sendable {
    case plaintext(AuditSensitive)
    case omitted
    case unreadable
}

public final class AuditUnsealer: @unchecked Sendable {
    private let keyring: AuditKeyring
    private let store: AuditStore
    private let context: LAContext?
    private let lock = NSLock()
    private var dekCache: [Data: SymmetricKey] = [:]
    private var failedEpochs: Set<Data> = []

    public init(keyring: AuditKeyring, store: AuditStore, context: LAContext?) {
        self.keyring = keyring
        self.store = store
        self.context = context
    }

    public func open(_ r: AuditRecord) -> AuditUnsealResult {
        switch r.sensitiveFormat {
        case 0:
            return .plaintext(r.event.sensitive)
        case 2:
            return .omitted
        case 1:
            guard let blob = r.sealedSensitive,
                  let epochID = AuditCrypto.epochID(ofSealedRow: blob) else {
                return .unreadable
            }

            let aad = AuditCrypto.rowAAD(
                eventID: r.event.id,
                time: r.event.time,
                type: r.event.type,
                fingerprint: r.event.keyFingerprint
            )

            lock.lock()
            defer { lock.unlock() }

            if let dek = dekCache[epochID] {
                do {
                    let sensitive = try AuditCrypto.openRow(blob, dek: dek, aad: aad)
                    return .plaintext(sensitive)
                } catch {
                    return .unreadable
                }
            }

            if failedEpochs.contains(epochID) {
                return .unreadable
            }

            do {
                guard let epoch = try store.epoch(id: epochID) else {
                    failedEpochs.insert(epochID)
                    return .unreadable
                }

                let dek = try AuditCrypto.unwrapDEK(
                    epk: epoch.epk,
                    wrapped: epoch.wrappedDEK,
                    epochID: epoch.epochID,
                    keyID: epoch.keyID,
                    agree: { peerPub in
                        try self.keyring.agree(keyID: epoch.keyID, with: peerPub, context: self.context)
                    }
                )

                dekCache[epochID] = dek
                let sensitive = try AuditCrypto.openRow(blob, dek: dek, aad: aad)
                return .plaintext(sensitive)
            } catch {
                failedEpochs.insert(epochID)
                return .unreadable
            }
        default:
            return .unreadable
        }
    }
}
