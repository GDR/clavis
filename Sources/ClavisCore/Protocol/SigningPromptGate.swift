import Foundation

public enum SigningPromptGateError: LocalizedError, Equatable {
    case coolingDown

    public var errorDescription: String? {
        "Too many denied authentication prompts; signing requests are temporarily refused."
    }
}

/// Serializes interactive authentication prompts and throttles prompt spam.
///
/// Any local process (or a forwarded agent) may request signatures in a loop. Without
/// a gate each request opens its own Touch ID / password prompt, which trains users to
/// approve blindly. The gate:
/// - allows one authentication prompt at a time (others wait their turn), and
/// - after `maxConsecutiveDenials` cancelled/failed prompts in a row, refuses further
///   requests without showing any UI. The first lockout lasts `cooldown` seconds
///   (60 by default). Each later lockout doubles that interval, capped at 15 minutes.
/// A successful authentication resets the denial counter and the cooldown escalation.
public final class SigningPromptGate: @unchecked Sendable {
    /// Longest refusal after repeated authentication failures.
    static let maximumCooldown: TimeInterval = 15 * 60

    private let serial = NSLock()
    private let maxConsecutiveDenials: Int
    private let baseCooldown: TimeInterval
    private let now: () -> Date
    private var consecutiveDenials = 0
    private var lockoutsSinceSuccess = 0
    private var blockedUntil: Date?

    public init(
        maxConsecutiveDenials: Int = 3,
        cooldown: TimeInterval = 60,
        now: @escaping () -> Date = Date.init
    ) {
        self.maxConsecutiveDenials = max(1, maxConsecutiveDenials)
        self.baseCooldown = max(0, cooldown)
        self.now = now
    }

    /// Runs `body` (which is expected to present an authentication prompt) exclusively.
    /// Only `UserAuthenticationError`s count as denials; other failures are neutral.
    public func run<T>(_ body: () throws -> T) throws -> T {
        serial.lock()
        defer { serial.unlock() }

        if let until = blockedUntil {
            if now() < until { throw SigningPromptGateError.coolingDown }
            blockedUntil = nil
            consecutiveDenials = 0
        }

        do {
            let result = try body()
            consecutiveDenials = 0
            lockoutsSinceSuccess = 0
            return result
        } catch {
            if error is UserAuthenticationError {
                consecutiveDenials += 1
                if consecutiveDenials >= maxConsecutiveDenials {
                    let interval = currentCooldown()
                    blockedUntil = now().addingTimeInterval(interval)
                    lockoutsSinceSuccess += 1
                    ClavisLogger.log("SECURITY_ALERT", "Signing prompts denied \(consecutiveDenials) times in a row; refusing requests for \(Int(interval))s.")
                }
            }
            throw error
        }
    }

    /// Refusal length for the lockout about to start. Doubles after each lockout and
    /// never exceeds `maximumCooldown`.
    private func currentCooldown() -> TimeInterval {
        let cap = Self.maximumCooldown
        var interval = min(baseCooldown, cap)
        for _ in 0..<lockoutsSinceSuccess {
            if interval >= cap { return cap }
            let doubled = interval * 2
            interval = doubled >= cap ? cap : doubled
        }
        return interval
    }
}
