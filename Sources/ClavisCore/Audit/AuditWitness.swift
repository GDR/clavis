import CryptoKit
import Foundation
import OSLog

public struct AuditWitnessEntry: Equatable, Sendable {
    public let seq: Int64
    public let eventID: UUID
    public let type: String
    public let result: String
    public let fingerprint: String?
    public let digest: String
    public let loggedAt: Date?

    public init(
        seq: Int64,
        eventID: UUID,
        type: String,
        result: String,
        fingerprint: String?,
        digest: String,
        loggedAt: Date? = nil
    ) {
        self.seq = seq
        self.eventID = eventID
        self.type = type
        self.result = result
        self.fingerprint = fingerprint
        self.digest = digest
        self.loggedAt = loggedAt
    }
}

public protocol AuditWitnessWriting: AnyObject {
    func write(_ e: AuditWitnessEntry)
}

public final class OSLogAuditWitness: AuditWitnessWriting {
    private let logger = Logger(subsystem: "com.clavis.audit", category: "witness")

    public init() {}

    public func write(_ e: AuditWitnessEntry) {
        let line = AuditWitness.line(e)
        logger.notice("\(line, privacy: .public)")
    }
}

public enum AuditWitness {
    public static func digest(
        seq: Int64,
        eventID: UUID,
        time: Date,
        type: String,
        result: String,
        reason: String?,
        fingerprint: String?,
        kind: String?,
        session: String?,
        count: Int,
        sensitiveFormat: Int,
        sensitiveBlob: Data
    ) -> String {
        let normalizedTime = Date(timeIntervalSince1970: time.timeIntervalSince1970)
        let bitPatternStr = String(normalizedTime.timeIntervalSinceReferenceDate.bitPattern)
        let blobBase64 = (sensitiveFormat == 1) ? sensitiveBlob.base64EncodedString() : ""
        let payload = "w1|\(seq)|\(eventID.uuidString.lowercased())|\(bitPatternStr)|\(type)|\(result)|\(reason ?? "")|\(fingerprint ?? "")|\(kind ?? "")|\(session ?? "")|\(count)|\(sensitiveFormat)|\(blobBase64)"
        let hash = SHA256.hash(data: Data(payload.utf8))
        return hash.prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    public static func digest(for record: AuditRecord) -> String {
        digest(
            seq: record.seq,
            eventID: record.event.id,
            time: record.event.time,
            type: record.event.type.rawValue,
            result: record.event.result.rawValue,
            reason: record.event.reason?.rawValue,
            fingerprint: record.event.keyFingerprint,
            kind: record.event.keyKind?.rawValue,
            session: record.event.sessionID,
            count: record.event.count,
            sensitiveFormat: record.sensitiveFormat,
            sensitiveBlob: record.sealedSensitive ?? Data()
        )
    }

    public static func line(_ e: AuditWitnessEntry) -> String {
        let fp = e.fingerprint ?? "-"
        return "w1 seq=\(e.seq) eid=\(e.eventID.uuidString.lowercased()) type=\(e.type) result=\(e.result) fp=\(fp) h=\(e.digest)"
    }

    public static func parse(line: String) -> AuditWitnessEntry? {
        let parts = line.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 7, parts[0] == "w1" else {
            return nil
        }

        var map: [String: String] = [:]
        for part in parts.dropFirst() {
            let s = String(part)
            guard s.filter({ $0 == "=" }).count == 1 else {
                return nil
            }
            let kv = s.split(separator: "=", omittingEmptySubsequences: false)
            guard kv.count == 2 else { return nil }
            let key = String(kv[0])
            let val = String(kv[1])
            guard !key.isEmpty, !val.isEmpty else { return nil }
            guard map[key] == nil else { return nil }
            map[key] = val
        }

        guard map.count == 6 else { return nil }

        guard let seqStr = map["seq"], let seq = Int64(seqStr) else { return nil }
        guard let eidStr = map["eid"], eidStr.count == 36, let eid = UUID(uuidString: eidStr) else { return nil }
        guard let type = map["type"] else { return nil }
        guard let result = map["result"] else { return nil }
        guard let fpStr = map["fp"] else { return nil }
        let fingerprint = (fpStr == "-") ? nil : fpStr

        guard let h = map["h"], h.count == 32 else { return nil }
        let hexSet = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        guard h.unicodeScalars.allSatisfy({ hexSet.contains($0) }) else { return nil }

        return AuditWitnessEntry(
            seq: seq,
            eventID: eid,
            type: type,
            result: result,
            fingerprint: fingerprint,
            digest: h.lowercased(),
            loggedAt: nil
        )
    }
}
