import Foundation

/// Process-local generations protect pending requests from policy ABA changes.
/// Restarting the daemon discards every request and grant, so no epoch persists.
/// Both listeners must use the same instance; routing is not an identity boundary.
public final class KeyPolicyGenerations: @unchecked Sendable {
    public static let shared = KeyPolicyGenerations()
    private let lock = NSLock()
    private var generations: [String: UUID] = [:]
    private var fingerprintsByLabel: [String: String] = [:]
    public init() {}

    public func current(for key: SSHKeyInfo) -> UUID {
        lock.lock()
        defer { lock.unlock() }
        fingerprintsByLabel[key.label] = key.fingerprint
        if let generation = generations[key.fingerprint] { return generation }
        let generation = UUID()
        generations[key.fingerprint] = generation
        return generation
    }

    public func matches(fingerprint: String, generation: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generations[fingerprint] == generation
    }

    public func invalidate(label: String, fingerprint: String? = nil) {
        lock.lock()
        defer { lock.unlock() }
        guard let fingerprint = fingerprint ?? fingerprintsByLabel[label] else { return }
        generations[fingerprint] = UUID()
        // Keep the old-label mapping so rename revocation also invalidates a
        // request that was authorized before the public index was renamed.
        fingerprintsByLabel[label] = fingerprint
    }
}
