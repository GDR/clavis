import Foundation
import CryptoKit
import Security

public enum AuditExporter {

    public static func randomSalt() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status == errSecSuccess {
            return Data(bytes)
        }
        return Data((0..<16).map { _ in UInt8.random(in: 0...255) })
    }

    private static func hashString(_ string: String, salt: Data) -> String {
        let key = SymmetricKey(data: salt)
        let mac = HMAC<SHA256>.authenticationCode(for: Data(string.utf8), using: key)
        let hex = mac.map { String(format: "%02x", $0) }.joined()
        return "h:" + String(hex.prefix(12))
    }

    private struct ExportProcess: Codable {
        let executablePath: String
        let pid: Int32
    }

    private struct ExportRecord: Codable {
        let seq: Int64
        let time: String
        let type: String
        let result: String
        let reason: String?
        let keyFingerprint: String?
        let keyKind: String?
        let sessionID: String?
        let count: Int
        let keyLabel: String?
        let processChain: [ExportProcess]
        let host: String?
    }

    /// Exports records in JSON Lines format, one object per record, newest first.
    public static func export(
        _ records: [AuditRecord],
        unsealed: [Int64: AuditUnsealResult] = [:],
        salt: Data = randomSalt()
    ) -> Data {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]

        let sortedRecords = records.sorted { $0.seq > $1.seq }

        var lines: [String] = []
        for record in sortedRecords {
            let event = record.event
            let timeString = formatter.string(from: event.time)

            let resolvedSensitive: AuditSensitive?
            if let result = unsealed[record.seq] {
                switch result {
                case .plaintext(let s):
                    resolvedSensitive = s
                case .omitted, .unreadable:
                    resolvedSensitive = nil
                }
            } else if record.sensitiveFormat == 0 {
                resolvedSensitive = event.sensitive
            } else {
                resolvedSensitive = nil
            }

            let redactedLabel = resolvedSensitive?.keyLabel.map { hashString($0, salt: salt) }
            let redactedChain = resolvedSensitive?.processChain.map { proc in
                ExportProcess(
                    executablePath: hashString(proc.executablePath, salt: salt),
                    pid: proc.pid
                )
            } ?? []

            let exportRec = ExportRecord(
                seq: record.seq,
                time: timeString,
                type: event.type.rawValue,
                result: event.result.rawValue,
                reason: event.reason?.rawValue,
                keyFingerprint: event.keyFingerprint,
                keyKind: event.keyKind?.rawValue,
                sessionID: event.sessionID,
                count: event.count,
                keyLabel: redactedLabel,
                processChain: redactedChain,
                host: resolvedSensitive?.host
            )

            if let lineData = try? encoder.encode(exportRec),
               let lineStr = String(data: lineData, encoding: .utf8) {
                lines.append(lineStr)
            }
        }

        if lines.isEmpty {
            return Data()
        }
        let output = lines.joined(separator: "\n") + "\n"
        return Data(output.utf8)
    }
}
