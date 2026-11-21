import AppKit
import Foundation
import LocalAuthentication
import ClavisCore

/// Bridges synchronous `clavis-agent` signing policy checks (`SigningPolicyEvaluator`)
/// to the 1-step MacBook Notch Touch ID prompt (`NotchPromptWindowController`), returning
/// the in-process evaluated `LAContext` that authorizes Secure Enclave signing.
public final class NotchSigningPromptAuthenticator: SigningPromptAuthenticating, @unchecked Sendable {
    public let defaultTimeout: TimeInterval

    public init(defaultTimeout: TimeInterval = 60.0) {
        self.defaultTimeout = defaultTimeout
    }

    public static func makeNotchRequest(from request: SigningAuthenticationRequest) -> NotchPromptRequest {
        let keyType = request.key.effectiveAccessProfile.type
        let policy = request.key.effectiveBiometricPolicy
        let confirmationMode = NotchConfirmationMode(biometricPolicy: policy)
        let allowsPassword = NotchConfirmationMode.allowsPasswordFallback(for: policy)

        let rawDescription = "\(request.callerName ?? request.peerPath) (PID \(request.peerPid))"
        let callerInfo = AppKitGitSigningGracePresenter.resolveCallerMetadata(
            rawDescription: rawDescription,
            pid: request.peerPid,
            executablePath: request.peerPath,
            overrideCallerName: request.callerName,
            keyType: keyType
        )

        let warningText: String? = (callerInfo.agentWarning == nil && request.isForwardedAgent)
            ? "Forwarded SSH agent\nRemote host requested a signature via agent forwarding"
            : nil

        return NotchPromptRequest(
            callerName: callerInfo.callerName,
            callerPath: callerInfo.callerPath,
            processChain: callerInfo.processChain,
            keyLabel: request.key.label,
            keyType: keyType,
            keyTypeSubtitle: keyType == .bot ? "Agent key" : "Personal key",
            destination: request.destination,
            operation: request.operationLabel,
            warningText: warningText,
            agentWarning: callerInfo.agentWarning,
            initialScope: NotchSessionScope.from(gracePeriod: request.defaultScope) ?? .once,
            showsScopeSelector: request.allowsSessionScope,
            allowsPasswordFallback: allowsPassword,
            confirmationMode: confirmationMode
        )
    }

    public func authenticateSigningRequest(_ request: SigningAuthenticationRequest) throws -> SigningAuthenticationOutcome {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            let ctx = try LocalUserAuthenticator().authenticate(
                reason: request.reason,
                policy: request.key.effectiveBiometricPolicy.laPolicy
            )
            return SigningAuthenticationOutcome(context: ctx, selectedScope: .always)
        }
        #endif

        guard GitSigningPrompt.sessionCheckProvider() else {
            let ctx = try LocalUserAuthenticator().authenticate(
                reason: request.reason,
                policy: request.key.effectiveBiometricPolicy.laPolicy
            )
            return SigningAuthenticationOutcome(context: ctx, selectedScope: .always)
        }

        let notchRequest = Self.makeNotchRequest(from: request)
        let authReason = request.reason
        let hardwarePasswordAuthenticator: @MainActor () async -> LAContext? = {
            await Task.detached(priority: .userInitiated) {
                let context = LAContext()
                context.localizedReason = authReason
                do {
                    let ok = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: authReason)
                    if ok {
                        return context
                    }
                    context.invalidate()
                    return nil
                } catch {
                    context.invalidate()
                    return nil
                }
            }.value
        }

        let semaphore = DispatchSemaphore(value: 0)
        let box = OutcomeBox()

        Task { @MainActor in
            box.outcome = await NotchPromptWindowController.shared.presentForAuthentication(
                request: notchRequest,
                hardwarePasswordAuthenticator: hardwarePasswordAuthenticator
            )
            semaphore.signal()
        }

        let waitResult = semaphore.wait(timeout: .now() + defaultTimeout)
        if waitResult == .timedOut {
            Task { @MainActor in
                NotchPromptWindowController.shared.dismiss()
            }
            throw UserAuthenticationError.timedOut
        }

        guard let outcome = box.outcome, let context = outcome.context else {
            throw UserAuthenticationError.rejected(LAError(.userCancel))
        }

        return SigningAuthenticationOutcome(
            context: context,
            selectedScope: outcome.scope.keyGracePeriod
        )
    }

    private final class OutcomeBox: @unchecked Sendable {
        var outcome: NotchAuthenticatedOutcome?
    }
}
