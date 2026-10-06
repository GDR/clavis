import Foundation
import LocalAuthentication

public enum AgentSessionGrantError: Error, Equatable {
    case grantInvalidated
}

public final class AgentSessionGrant: @unchecked Sendable {
    private let lock = NSLock()
    private let key: Ed25519KeyInfo?
    private let context: LAContext?
    private var isInvalidated = false

    public init(key: Ed25519KeyInfo, context: LAContext) {
        self.key = key
        self.context = context
    }

    internal init() {
        self.key = nil
        self.context = nil
    }

    public func sign(_ data: Data, using keyManager: KeychainManager) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard !isInvalidated, let key = key, let context = context else {
            throw AgentSessionGrantError.grantInvalidated
        }

        return try keyManager.signSSH(
            key: key,
            data: data,
            prompt: "",
            useCache: false,
            existingContext: context,
            allowedPurposes: [.agent]
        )
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        guard !isInvalidated else { return }
        isInvalidated = true
        context?.invalidate()
    }
}
