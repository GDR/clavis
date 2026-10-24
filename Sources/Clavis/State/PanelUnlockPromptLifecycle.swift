import Foundation

/// Authentication-sheet dismissal returns focus to the locked window. That
/// focus is not a new request to authenticate, regardless of elapsed time.
struct PanelUnlockPromptLifecycle {
    enum Trigger {
        case presentation
        case windowFocus
        case explicitOpen
    }

    private(set) var generation = UUID()
    private(set) var automaticAttemptConsumed = false

    mutating func claimAutomaticAttempt(
        trigger: Trigger,
        isLocked: Bool,
        isAuthenticating: Bool
    ) -> Bool {
        guard isLocked, !isAuthenticating else { return false }
        if trigger == .explicitOpen {
            automaticAttemptConsumed = false
        }
        guard !automaticAttemptConsumed else { return false }
        automaticAttemptConsumed = true
        return true
    }

    /// Manual attempts remain available, but their dismissal must not start an
    /// additional automatic attempt when the window becomes key again.
    mutating func beganManualAttempt() -> UUID {
        automaticAttemptConsumed = true
        return generation
    }

    mutating func didLock(wasAlreadyLocked: Bool, suppressAutomaticAttempt: Bool = false) {
        generation = UUID()
        if suppressAutomaticAttempt {
            automaticAttemptConsumed = true
        } else if !wasAlreadyLocked {
            automaticAttemptConsumed = false
        }
    }

    func acceptsCompletion(from generation: UUID) -> Bool {
        self.generation == generation
    }
}
