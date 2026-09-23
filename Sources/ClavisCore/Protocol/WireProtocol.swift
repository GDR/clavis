import Foundation

public struct DataReader {
    private let data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    public mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.endIndex else { return nil }
        var value: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &value) { ptr in
            data.copyBytes(to: ptr, from: offset..<offset+4)
        }
        offset += 4
        return UInt32(bigEndian: value)
    }

    public mutating func readWireData() -> Data? {
        guard let length32 = readUInt32() else { return nil }
        let length = Int(length32)
        guard length >= 0, offset + length <= data.endIndex else { return nil }
        let result = Data(data.subdata(in: offset..<offset+length))
        offset += length
        return result
    }

    public mutating func readWireString() -> String? {
        guard let data = readWireData() else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public var isEOF: Bool {
        offset >= data.endIndex
    }

    public var remainingBytes: Int {
        max(0, data.endIndex - offset)
    }
}

public extension Data {
    mutating func appendWireString(_ string: String) {
        let data = Data(string.utf8)
        appendWireData(data)
    }

    mutating func appendWireData(_ data: Data) {
        var length = UInt32(data.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { append(contentsOf: $0) }
        append(data)
    }

    mutating func appendWireUInt32(_ value: UInt32) {
        var big = value.bigEndian
        Swift.withUnsafeBytes(of: &big) { append(contentsOf: $0) }
    }

    // Helper to format an integer as an SSH mpint (RFC 4251 section 5)
    static func encodeSSHMPint(_ bytes: Data) -> Data {
        var d = bytes
        while d.count > 1 && d.first == 0 {
            d.removeFirst()
        }
        var res = Data()
        if let first = d.first, first & 0x80 != 0 {
            var withZero = Data([0x00])
            withZero.append(d)
            var len = UInt32(withZero.count).bigEndian
            Swift.withUnsafeBytes(of: &len) { res.append(contentsOf: $0) }
            res.append(withZero)
        } else {
            var len = UInt32(d.count).bigEndian
            Swift.withUnsafeBytes(of: &len) { res.append(contentsOf: $0) }
            res.append(d)
        }
        return res
    }
}
