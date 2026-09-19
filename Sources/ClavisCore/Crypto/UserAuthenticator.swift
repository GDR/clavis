import Foundation
import LocalAuthentication

public protocol UserAuthenticating {
    @discardableResult
    func authenticate(reason: String) throws -> LAContext

    @discardableResult
    func authenticate(reason: String) async throws -> LAContext
}

public enum UserAuthenticationError: LocalizedError {
    case timedOut
    case rejected(Error?)

    public var errorDescription: String? {
        switch self {
        case .timedOut:
            return "User authentication timed out"
        case .rejected(let error):
            return error?.localizedDescription ?? "User authentication failed or was cancelled"
        }
    }
}

public final class LocalUserAuthenticator: UserAuthenticating {
    public init() {}

    @discardableResult
    public func authenticate(reason: String) throws -> LAContext {
        let context = LAContext()
        context.localizedReason = reason

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Void, Error>?

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            if success {
                result = .success(())
            } else {
                result = .failure(UserAuthenticationError.rejected(error))
            }
            semaphore.signal()
        }

        guard semaphore.wait(timeout: .now() + 60) == .success else {
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
    public func authenticate(reason: String) async throws -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
            throw UserAuthenticationError.rejected(nil)
        }
        return context
    }
}
