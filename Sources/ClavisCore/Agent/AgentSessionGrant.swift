import Foundation
import LocalAuthentication
import CryptoKit
import Security

public enum AgentSessionGrantError: Error, Equatable {
    case grantInvalidated
}

public final class AgentSessionGrant: @unchecked Sendable {
    private let lock = NSLock()
    private let key: SSHKeyInfo?
    private let context: LAContext?
    private var isInvalidated = false
    private var hardwareSigner: (@Sendable (Data) throws -> Data)?

    public convenience init(key: SSHKeyInfo, context: LAContext) {
        self.init(key: key, context: context, hardwareSigner: nil)
    }

    public init(
        key: SSHKeyInfo,
        context: LAContext,
        hardwareSigner: (@Sendable (Data) throws -> Data)? = nil
    ) {
        self.key = key
        self.context = context
        self.hardwareSigner = hardwareSigner
    }

    internal init() {
        self.key = nil
        self.context = nil
        self.hardwareSigner = nil
    }

    public var isValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !isInvalidated && !SystemEventMonitor.isSessionLockedOrOffConsole()
    }

    public func sign(_ data: Data, using keyManager: KeychainManager? = nil) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        if SystemEventMonitor.isSessionLockedOrOffConsole() {
            if !isInvalidated {
                isInvalidated = true
                hardwareSigner = nil
                context?.invalidate()
            }
            throw AgentSessionGrantError.grantInvalidated
        }

        guard !isInvalidated, let key = key else {
            throw AgentSessionGrantError.grantInvalidated
        }

        if let hardwareSigner {
            return try hardwareSigner(data)
        }

        guard let context = context, let keyManager = keyManager else {
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
        hardwareSigner = nil
        context?.invalidate()
    }

    deinit {
        invalidate()
    }
}
