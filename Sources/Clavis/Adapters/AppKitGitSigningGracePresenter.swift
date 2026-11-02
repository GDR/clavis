import AppKit
import ClavisCore

public struct AppKitGitSigningGracePresenter: GitSigningGracePresenter {
    public let defaultTimeout: TimeInterval

    public init(defaultTimeout: TimeInterval = 30.0) {
        self.defaultTimeout = defaultTimeout
    }

    public func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
        GitSigningPrompt.displayModal(keyLabel: keyLabel, clientDesc: clientDesc, timeout: timeout)
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
