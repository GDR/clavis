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
///   requests for `cooldown` seconds without showing any UI.
/// A successful authentication resets the counter.
public final class SigningPromptGate: @unchecked Sendable {
    private let serial = NSLock()
    private let maxConsecutiveDenials: Int
    private let cooldown: TimeInterval
    private let now: () -> Date
    private var consecutiveDenials = 0
    private var blockedUntil: Date?

    public init(
        maxConsecutiveDenials: Int = 3,
        cooldown: TimeInterval = 15,
        now: @escaping () -> Date = Date.init
    ) {
        self.maxConsecutiveDenials = max(1, maxConsecutiveDenials)
        self.cooldown = max(0, cooldown)
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
            return result
        } catch {
            if error is UserAuthenticationError {
                consecutiveDenials += 1
                if consecutiveDenials >= maxConsecutiveDenials {
                    blockedUntil = now().addingTimeInterval(cooldown)
                    ClavisLogger.log("SECURITY_ALERT", "Signing prompts denied \(consecutiveDenials) times in a row; refusing requests for \(Int(cooldown))s.")
                }
            }
            throw error
        }
    }
}
