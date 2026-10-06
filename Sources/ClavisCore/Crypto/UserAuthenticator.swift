import Foundation
import LocalAuthentication

public protocol UserAuthenticating {
    @discardableResult
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext

    @discardableResult
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext
}

public extension UserAuthenticating {
    @discardableResult
    func authenticate(reason: String) throws -> LAContext {
        try authenticate(reason: reason, policy: .deviceOwnerAuthentication)
    }

    @discardableResult
    func authenticate(reason: String) async throws -> LAContext {
        try await authenticate(reason: reason, policy: .deviceOwnerAuthentication)
    }
}

public enum UserAuthenticationError: LocalizedError {
    case timedOut
    case rejected(Error?)

    public var errorDescription: String? {
        switch self {
        case .timedOut:
            return ClavisUIStrings.Auth.errorTimedOut
        case .rejected(let error):
            return error?.localizedDescription ?? ClavisUIStrings.Auth.errorRejected
        }
    }
}

public final class LocalUserAuthenticator: UserAuthenticating {
    public init() {}

    @discardableResult
    public func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
        ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator: prompting system authentication (policy: \(policy), reason: \"\(reason)\")")
        let context = LAContext()
        context.localizedReason = reason
        if policy == .deviceOwnerAuthenticationWithBiometrics {
            context.localizedFallbackTitle = ""
        }

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Void, Error>?

        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            if success {
                ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator: prompt SUCCEEDED (reason: \"\(reason)\")")
                result = .success(())
            } else {
                ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator: prompt FAILED: \(String(describing: error)) (reason: \"\(reason)\")")
                result = .failure(UserAuthenticationError.rejected(error))
            }
            semaphore.signal()
        }

        guard semaphore.wait(timeout: .now() + 60) == .success else {
            ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator: prompt TIMED OUT (reason: \"\(reason)\")")
            context.invalidate()
            throw UserAuthenticationError.timedOut
        }

        switch result {
        case .success:
            return context
        case .failure(let error):
            throw error
        case nil:
            throw UserAuthenticationError.rejected(nil)
        }
    }

    @discardableResult
    public func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
        ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator (async): prompting system authentication (policy: \(policy), reason: \"\(reason)\")")
        let context = LAContext()
        context.localizedReason = reason
        if policy == .deviceOwnerAuthenticationWithBiometrics {
            context.localizedFallbackTitle = ""
        }
        do {
            guard try await context.evaluatePolicy(policy, localizedReason: reason) else {
                ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator (async): prompt REJECTED (reason: \"\(reason)\")")
                throw UserAuthenticationError.rejected(nil)
            }
            ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator (async): prompt SUCCEEDED (reason: \"\(reason)\")")
            return context
        } catch {
            ClavisLogger.promptDebug("clavis-code", "LocalUserAuthenticator (async): prompt ERROR: \(error.localizedDescription) (reason: \"\(reason)\")")
            throw error
        }
    }
}
