import Foundation

public struct TokenBucket: Sendable, Equatable {
    public let burst: Int
    public let refillPerMinute: Int
    public private(set) var tokens: Double
    public private(set) var lastRefill: Date

    public init(burst: Int, refillPerMinute: Int, now: Date = Date()) {
        self.burst = burst
        self.refillPerMinute = refillPerMinute
        self.tokens = Double(burst)
        self.lastRefill = now
    }

    public mutating func take(now: Date = Date()) -> Bool {
        let elapsed = max(0, now.timeIntervalSince(lastRefill))
        let refillRate = Double(refillPerMinute) / 60.0
        tokens = min(Double(burst), tokens + (elapsed * refillRate))
        lastRefill = now

        if tokens >= 1.0 {
            tokens -= 1.0
            return true
        }
        return false
    }
}
