import Foundation

/// Represents a validated OpenSSH SSHSIG payload as used by Git for commit and tag signing.
///
/// Format (per OpenSSH PROTOCOL.sshsig):
/// ```text
/// byte[6] "SSHSIG"
/// string  namespace (must be "git" for Git signing)
/// string  reserved  (must be empty)
/// string  hash_algorithm ("sha256" or "sha512")
/// string  H(message) (32 bytes for sha256, 64 bytes for sha512)
/// ```
public struct SSHSIGPayload: Equatable {
    public static let magic = Data("SSHSIG".utf8)

    public let namespace: String
    public let hashAlgorithm: String
    public let messageHash: Data

    public init(namespace: String, hashAlgorithm: String, messageHash: Data) {
        self.namespace = namespace
        self.hashAlgorithm = hashAlgorithm
        self.messageHash = messageHash
    }

    /// Strict parser for OpenSSH SSHSIG wire data.
    /// Returns nil if the payload is not a valid Git SSHSIG payload.
    public static func parse(from data: Data) -> SSHSIGPayload? {
        guard data.count >= 6 else { return nil }
        guard data.prefix(6) == magic else { return nil }

        var reader = DataReader(data: Data(data.dropFirst(6)))
        guard let namespace = reader.readWireString(),
              let reserved = reader.readWireString(),
              let hashAlgorithm = reader.readWireString(),
              let messageHash = reader.readWireData() else {
            return nil
        }

        // 1. Namespace must be exactly "git"
        guard namespace == "git" else { return nil }

        // 2. Reserved field must be empty
        guard reserved.isEmpty else { return nil }

        // 3. Hash algorithm must be sha256 or sha512
        guard hashAlgorithm == "sha256" || hashAlgorithm == "sha512" else { return nil }

        // 4. Digest length must strictly match the hash algorithm
        if hashAlgorithm == "sha256" && messageHash.count != 32 { return nil }
        if hashAlgorithm == "sha512" && messageHash.count != 64 { return nil }

        // 5. Must have consumed the exact entire data without trailing bytes
        guard reader.isEOF else { return nil }

        return SSHSIGPayload(
            namespace: namespace,
            hashAlgorithm: hashAlgorithm,
            messageHash: messageHash
        )
    }

    /// Serializes to the wire format for testing and fixture generation.
    public func serialize() -> Data {
        var result = Self.magic
        result.appendWireString(namespace)
        result.appendWireString("") // reserved
        result.appendWireString(hashAlgorithm)
        result.appendWireData(messageHash)
        return result
    }
}
