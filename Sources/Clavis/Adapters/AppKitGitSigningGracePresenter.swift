import AppKit
import ClavisCore

public struct AppKitGitSigningGracePresenter: GitSigningGracePresenter {
    public let defaultTimeout: TimeInterval

    public init(defaultTimeout: TimeInterval = 30.0) {
        self.defaultTimeout = defaultTimeout
    }

    public func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
        if ClavisEnvironment.isTesting || Thread.isMainThread {
            return GitSigningPrompt.displayModal(keyLabel: keyLabel, clientDesc: clientDesc, timeout: timeout)
        }
        let semaphore = DispatchSemaphore(value: 0)
        let box = ResultBox()
        Task { @MainActor in
            let keyType = AppState.shared.keys.first(where: { $0.label == keyLabel })?.effectiveAccessProfile.type ?? .personal
            box.choice = await self.presentNotchPrompt(
                keyLabel: keyLabel,
                clientDesc: clientDesc,
                keyType: keyType
            )
            semaphore.signal()
        }
        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            Task { @MainActor in
                NotchPromptWindowController.shared.dismiss()
            }
            return .cancel
        }
        return box.choice
    }

    private final class ResultBox: @unchecked Sendable {
        var choice: GitSigningPromptChoice = .cancel
    }

    public func prompt(keyLabel: String, clientDesc: String) -> GitSigningPromptChoice {
        prompt(keyLabel: keyLabel, clientDesc: clientDesc, timeout: defaultTimeout)
    }

    /// Builds a `NotchPromptRequest` for a Git / SSH signing prompt (`S-08` / `INV-09`).
    public static func makeNotchRequest(
        keyLabel: String,
        clientDesc: String,
        keyType: KeyType = .personal,
        operation: String = "commit -S",
        initialScope: NotchSessionScope = .fifteenMinutes
    ) -> NotchPromptRequest {
        NotchPromptRequest(
            callerName: clientDesc,
            processChain: "git → ssh-keygen",
            keyLabel: keyLabel,
            keyType: keyType,
            operation: operation,
            initialScope: initialScope,
            showsScopeSelector: true
        )
    }

    /// Maps a `NotchPromptResult` into `GitSigningPromptChoice`.
    public static func mapResultToGraceChoice(_ result: NotchPromptResult) -> GitSigningPromptChoice {
        switch result {
        case .approved(let scope, _):
            return scope.gitSigningPromptChoice
        case .denied:
            return .cancel
        }
    }

    @MainActor
    public func presentNotchPrompt(
        keyLabel: String,
        clientDesc: String,
        keyType: KeyType = .personal,
        operation: String = "commit -S",
        initialScope: NotchSessionScope = .fifteenMinutes
    ) async -> GitSigningPromptChoice {
        let request = Self.makeNotchRequest(
            keyLabel: keyLabel,
            clientDesc: clientDesc,
            keyType: keyType,
            operation: operation,
            initialScope: initialScope
        )
        let result = await NotchPromptWindowController.shared.present(request: request)
        return Self.mapResultToGraceChoice(result)
    }
}
