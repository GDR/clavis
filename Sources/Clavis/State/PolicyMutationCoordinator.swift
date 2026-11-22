import AppKit
import ClavisCore
import Foundation
import LocalAuthentication
import Observation

/// Owns the single in-window authenticated settings request shown by `AuthenticationRequestView`.
///
/// Responsibilities (the view itself is presentation only):
/// - stage one immutable request and keep the original setting effective while it is pending;
/// - act as the `AsyncUserAuthenticating` presenter: create a FRESH `LAContext`, publish it so the
///   embedded Touch ID view mounts BEFORE evaluation, then evaluate `.deviceOwnerAuthentication` once;
/// - return that context to the mutation layer (`KeychainManager`), which validates the authenticated
///   record and persists exactly once and owns the context lifetime;
/// - cancel/invalidate on Escape, close, lifecycle or target change; late completions are rejected.
@Observable
@MainActor
public final class PolicyMutationCoordinator: AsyncUserAuthenticating {
    /// Immutable staged request. `original` is the revision the request was staged against.
    public struct Request: Equatable, Sendable {
        public let id: UUID
        public let keyID: String
        public let label: String
        public let original: KeyAccessProfile
        public let originalTimeout: KeyGracePeriod
        public let originalStoredTimeout: KeyGracePeriod?
        public let type: KeyType?
        public let capabilities: KeyCapabilities?
        public let unlockedTimeout: KeyGracePeriod?
    }

    enum Intent { case retry, password, cancel }

    public private(set) var request: Request?
    private(set) var phase: AuthenticationRequestView.Phase = .waiting {
        didSet { announceIfNeeded(oldValue) }
    }
    /// The exact context being evaluated; nil in password mode so the system shows its own dialog.
    private(set) var embeddedContext: LAContext?

    public var isPending: Bool { request != nil }

    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var intentContinuation: CheckedContinuation<Intent, Never>?
    @ObservationIgnored private var activeContext: LAContext?
    @ObservationIgnored private var cancelRequested = false
    @ObservationIgnored private var switchToPassword = false
    @ObservationIgnored private var authenticationSucceeded = false

    public init() {}

    // MARK: - Staging

    /// Stages a request and runs it. One request at a time; a second call while pending is ignored.
    /// `completion` receives nil on success or the failure; cancellation completes silently.
    public func submit(
        key: SSHKeyInfo,
        type: KeyType? = nil,
        capabilities: KeyCapabilities? = nil,
        unlockedTimeout: KeyGracePeriod? = nil,
        appState: AppState,
        completion: @escaping (Error?) -> Void
    ) {
        guard request == nil else { return }
        let staged = Request(
            id: UUID(), keyID: key.id, label: key.label,
            original: key.effectiveAccessProfile,
            originalTimeout: key.effectiveUnlockedTimeout,
            originalStoredTimeout: key.unlockedTimeout,
            type: type, capabilities: capabilities, unlockedTimeout: unlockedTimeout
        )
        request = staged
        phase = .waiting
        embeddedContext = nil
        cancelRequested = false
        switchToPassword = false
        task = Task { [weak self] in
            await self?.run(staged, appState: appState, completion: completion)
        }
    }

    private func isCurrent(_ staged: Request) -> Bool { request?.id == staged.id }

    private func run(_ staged: Request, appState: AppState, completion: @escaping (Error?) -> Void) async {
        while true {
            authenticationSucceeded = false
            do {
                try await appState.changeAccessProfile(
                    label: staged.label, type: staged.type, capabilities: staged.capabilities,
                    unlockedTimeout: staged.unlockedTimeout,
                    expectedCurrent: staged.original,
                    expectedTimeout: staged.originalTimeout,
                    authenticator: self
                )
                guard isCurrent(staged), !Task.isCancelled else { return }
                finish()
                completion(nil)
                return
            } catch {
                guard isCurrent(staged), !Task.isCancelled else { return }
                if authenticationSucceeded, !(error is PolicyMutationError) {
                    // Save failure: the effective setting is unchanged; offer a safe retry that
                    // goes through the mutation boundary (and a fresh authentication) again.
                    phase = .saveFailed
                    let intent = await waitForIntent()
                    guard isCurrent(staged), !Task.isCancelled else { return }
                    if intent == .retry {
                        phase = .waiting
                        continue
                    }
                    finish()
                    return
                }
                let wasCancelled = Self.isCancellation(error)
                finish()
                if !wasCancelled { completion(error) }
                return
            }
        }
    }

    // MARK: - Intents (never proof of authentication)

    func retry() { resolveIntent(.retry) }

    func usePassword() {
        guard request != nil, phase != .saving else { return }
        if intentContinuation != nil {
            resolveIntent(.password)
        } else {
            // Evaluation in flight: end it; the presenter loop restarts in password mode.
            switchToPassword = true
            activeContext?.invalidate()
        }
    }

    /// Escape, close button, parent-window close, target change, lock: no mutation, state unchanged.
    public func cancel() {
        guard request != nil else { return }
        cancelRequested = true
        intentContinuation?.resume(returning: .cancel)
        intentContinuation = nil
        activeContext?.invalidate()
        task?.cancel()
        finish()
    }

    /// Cancels when the staged target disappeared or changed underneath the pending request.
    func cancelIfTargetChanged(keys: [SSHKeyInfo]) {
        guard let request else { return }
        guard let current = keys.first(where: { $0.id == request.keyID }),
              current.effectiveAccessProfile == request.original,
              current.unlockedTimeout == request.originalStoredTimeout else {
            cancel()
            return
        }
    }

    private func resolveIntent(_ intent: Intent) {
        intentContinuation?.resume(returning: intent)
        intentContinuation = nil
    }

    private func waitForIntent() async -> Intent {
        await withCheckedContinuation { continuation in
            intentContinuation = continuation
        }
    }

    private func finish() {
        request = nil
        embeddedContext = nil
        activeContext = nil
        intentContinuation?.resume(returning: .cancel)
        intentContinuation = nil
        task = nil
        cancelRequested = false
        switchToPassword = false
        authenticationSucceeded = false
        phase = .waiting
    }

    // MARK: - AsyncUserAuthenticating (presenter)

    public func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
        var passwordMode = false
        while true {
            try Task.checkCancellation()
            if cancelRequested { throw CancellationError() }

            let context = LAContext()
            context.localizedReason = reason
            activeContext = context

            var probeError: NSError?
            let canUsePolicy = context.canEvaluatePolicy(policy, error: &probeError)
            let biometricsReady = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)

            if !canUsePolicy {
                // Public API outcome only (e.g. no passcode set); never invent failure counts.
                phase = .unavailable
                embeddedContext = nil
                context.invalidate()
                switch await waitForIntent() {
                case .cancel: throw CancellationError()
                case .retry, .password: continue
                }
            }

            if !passwordMode && biometricsReady {
                // Mount the embedded sensor view BEFORE evaluating so it binds to this exact context.
                embeddedContext = context
                phase = .waiting
                await Task.yield()
                await Task.yield()
            } else {
                embeddedContext = nil
                phase = biometricsReady ? .waiting : .unavailable
            }

            do {
                let ok = try await withTaskCancellationHandler {
                    try await context.evaluatePolicy(policy, localizedReason: reason)
                } onCancel: {
                    context.invalidate()
                }
                guard ok else { throw UserAuthenticationError.rejected(nil) }
                guard !cancelRequested, !Task.isCancelled else {
                    context.invalidate()
                    throw CancellationError()
                }
                authenticationSucceeded = true
                embeddedContext = nil
                phase = .saving
                // Ownership of the context passes to the mutation layer, which invalidates it.
                return context
            } catch {
                context.invalidate()
                embeddedContext = nil
                if cancelRequested || Task.isCancelled { throw CancellationError() }
                if switchToPassword {
                    switchToPassword = false
                    passwordMode = true
                    continue
                }
                let code = (error as? LAError)?.code
                switch code {
                case .userCancel, .appCancel, .systemCancel:
                    throw CancellationError()
                case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet:
                    phase = .unavailable
                default:
                    phase = .failed
                }
                switch await waitForIntent() {
                case .cancel: throw CancellationError()
                case .retry: passwordMode = false
                case .password: passwordMode = true
                }
            }
        }
    }

    // MARK: - Helpers

    private static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let la = error as? LAError {
            return la.code == .userCancel || la.code == .appCancel || la.code == .systemCancel
        }
        return AuditEvent.isUserCancellation(error)
    }

    private func announceIfNeeded(_ old: AuthenticationRequestView.Phase) {
        guard request != nil, old != phase else { return }
        let text: String
        switch phase {
        case .failed: text = "Not recognized. Try again."
        case .unavailable: text = "Touch ID unavailable"
        case .saving: text = "Saving"
        case .saveFailed: text = "Couldn’t save. Try again."
        case .authenticated: text = "Authentication complete"
        case .waiting: return
        }
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [.announcement: text]
        )
    }
}
