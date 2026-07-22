import Foundation

public struct Ed25519KeyInfo: Identifiable, Codable, Equatable {
    public var id: String { label }
    public let label: String
    public let publicKeyOpenSSH: String
    public let publicKeyBlob: Data
    public let fingerprint: String
    public let createdAt: Date

    public init(label: String, publicKeyOpenSSH: String, publicKeyBlob: Data, fingerprint: String, createdAt: Date = Date()) {
        self.label = label
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint
        self.createdAt = createdAt
    }
}

public enum SessionTimeout: String, CaseIterable, Identifiable, Codable {
    case never = "Off (Always Prompt)"
    case fiveMinutes = "5 Minutes"
    case fifteenMinutes = "15 Minutes"
    case oneHour = "1 Hour"

    public var id: String { rawValue }

    public var timeInterval: TimeInterval? {
        switch self {
        case .never: return nil
        case .fiveMinutes: return 300
        case .fifteenMinutes: return 900
        case .oneHour: return 3600
        }
    }
}

public extension Data {
    init?(hexString: String) {
        let cleanHex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanHex.count % 2 == 0 else { return nil }
        var data = Data(capacity: cleanHex.count / 2)
        var i = cleanHex.startIndex
        while i < cleanHex.endIndex {
            let j = cleanHex.index(i, offsetBy: 2)
            let bytes = cleanHex[i..<j]
            guard let num = UInt8(bytes, radix: 16) else { return nil }
            data.append(num)
            i = j
        }
        self = data
    }
}
