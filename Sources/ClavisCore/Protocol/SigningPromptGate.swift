import Foundation

public enum SigningPromptGateError: LocalizedError, Equatable {
    case coolingDown
    case clientDisconnected
    case queueFull

    public var errorDescription: String? {
        switch self {
        case .coolingDown:
            return "Too many denied authentication prompts; signing requests are temporarily refused."
        case .clientDisconnected:
            return "Client disconnected before authentication prompt was displayed."
        case .queueFull:
            return "Too many pending authentication prompts for this requester."
        }
    }
}

/// Identifies a requesting process for queue capping and denial tracking.
public struct Requester: Hashable, Sendable, CustomStringConvertible {
    public let executablePath: String
    public let pid: pid_t

    public init(executablePath: String, pid: pid_t) {
        self.executablePath = executablePath
        self.pid = pid
    }

    public init(processPath: String, pid: pid_t) {
        self.executablePath = processPath
        self.pid = pid
    }

    public var description: String {
        "\(executablePath) (PID \(pid))"
    }
}

/// Serializes interactive authentication prompts and throttles prompt spam.
///
/// Any local process (or a forwarded agent) may request signatures in a loop. Without
/// a gate each request opens its own Touch ID / password prompt, which trains users to
/// approve blindly. The gate:
/// - allows one authentication prompt at a time (others wait their turn),
/// - drops requests if the client socket is already closed before prompt display,
/// - caps queue per requester (path + pid) to max 1 waiting + 1 active, and
/// - tracks denials and escalates lockout per requester (60s base doubling up to 15m),
///   with a smaller global ceiling to defend against distributed/forking flood attacks.
/// A successful authentication resets denial counters and cooldown escalation.
public final class SigningPromptGate: @unchecked Sendable {
    public typealias Requester = ClavisCore.Requester

    /// Longest refusal after repeated authentication failures for a specific requester.
    public static let maximumCooldown: TimeInterval = 15 * 60
    /// Smaller global ceiling for refusal interval.
    public static let globalMaximumCooldown: TimeInterval = 60

    private struct DenialTracker {
        var consecutiveDenials = 0
        var lockoutsSinceSuccess = 0
        var blockedUntil: Date?

        mutating func recordDenial(now: Date, baseCooldown: TimeInterval, maxCooldown: TimeInterval, threshold: Int) -> TimeInterval? {
            consecutiveDenials += 1
            if consecutiveDenials >= threshold {
                let interval = calculateCooldown(baseCooldown: baseCooldown, maxCooldown: maxCooldown)
                blockedUntil = now.addingTimeInterval(interval)
                lockoutsSinceSuccess += 1
                return interval
            }
            return nil
        }

        mutating func reset() {
            consecutiveDenials = 0
            lockoutsSinceSuccess = 0
            blockedUntil = nil
        }

        private func calculateCooldown(baseCooldown: TimeInterval, maxCooldown: TimeInterval) -> TimeInterval {
            var interval = min(baseCooldown, maxCooldown)
            for _ in 0..<lockoutsSinceSuccess {
                if interval >= maxCooldown { return maxCooldown }
                let doubled = interval * 2
                interval = doubled >= maxCooldown ? maxCooldown : doubled
            }
            return interval
        }
    }

    private let lock = NSCondition()
    private let maxConsecutiveDenials: Int
    private let baseCooldown: TimeInterval
    private let globalMaxConsecutiveDenials: Int
    private let now: () -> Date

    // Per-requester and global denial tracking
    private var requesterTrackers: [Requester: DenialTracker] = [:]
    private var globalTracker = DenialTracker()
    private let defaultRequester = Requester(executablePath: "", pid: 0)

    // Concurrency and per-requester queue tracking
    private var hasActivePrompt = false
    private var activeRequester: Requester?
    private var waitingCounts: [Requester: Int] = [:]
    private var currentTicket: UInt64 = 0
    private var nextTicket: UInt64 = 0

    public init(
        maxConsecutiveDenials: Int = 3,
        cooldown: TimeInterval = 60,
        globalMaxConsecutiveDenials: Int = 5,
        now: @escaping () -> Date = Date.init
    ) {
        self.maxConsecutiveDenials = max(1, maxConsecutiveDenials)
        self.baseCooldown = max(0, cooldown)
        self.globalMaxConsecutiveDenials = max(self.maxConsecutiveDenials + 1, globalMaxConsecutiveDenials)
        self.now = now
    }

    /// Checks if a client socket is alive via poll(POLLIN | POLLHUP) with zero timeout.
    public static func isSocketAlive(_ fd: Int32) -> Bool {
        guard fd >= 0 else { return true }
        var pfd = pollfd(fd: fd, events: Int16(POLLIN | POLLHUP), revents: 0)
        let ret = poll(&pfd, 1, 0)
        if ret < 0 { return false }
        if ret == 0 { return true }
        if (pfd.revents & Int16(POLLHUP | POLLERR | POLLNVAL)) != 0 {
            return false
        }
        if (pfd.revents & Int16(POLLIN)) != 0 {
            var byte: UInt8 = 0
            let peek = recv(fd, &byte, 1, MSG_PEEK)
            if peek <= 0 {
                return false
            }
        }
        return false
    }

    /// Runs `body` (which is expected to present an authentication prompt) exclusively.
    /// Only `UserAuthenticationError`s count as denials; other failures are neutral.
    public func run<T>(
        requester: Requester? = nil,
        clientSocket: Int32? = nil,
        _ body: () throws -> T
    ) throws -> T {
        lock.lock()

        let effectiveReq = requester ?? defaultRequester

        // 1. Initial fast checks before queueing
        // Global lockout check
        if let until = globalTracker.blockedUntil {
            if now() < until {
                lock.unlock()
                throw SigningPromptGateError.coolingDown
            }
            globalTracker.blockedUntil = nil
            globalTracker.consecutiveDenials = 0
        }

        // Requester lockout check
        if let until = requesterTrackers[effectiveReq]?.blockedUntil {
            if now() < until {
                lock.unlock()
                throw SigningPromptGateError.coolingDown
            }
            requesterTrackers[effectiveReq]?.blockedUntil = nil
            requesterTrackers[effectiveReq]?.consecutiveDenials = 0
        }

        // Fast-fail socket check if already dead
        if let sock = clientSocket, !Self.isSocketAlive(sock) {
            lock.unlock()
            throw SigningPromptGateError.clientDisconnected
        }

        // Cap queue per requester: max 1 waiting + 1 active
        if let req = requester {
            let isActive = (hasActivePrompt && activeRequester == req)
            let activeCount = isActive ? 1 : 0
            let waitingCount = waitingCounts[req, default: 0]
            if (activeCount >= 1 && waitingCount >= 1) || waitingCount >= 1 {
                lock.unlock()
                throw SigningPromptGateError.queueFull
            }
        }

        // 2. Allocate ticket
        let myTicket = nextTicket
        nextTicket += 1
        if let req = requester {
            waitingCounts[req, default: 0] += 1
        }

        // 3. Wait for our turn
        while hasActivePrompt || myTicket != currentTicket {
            lock.wait()
        }

        // Our turn has arrived: decrement waiting count
        if let req = requester {
            waitingCounts[req, default: 1] -= 1
        }

        // 4. Re-check socket liveness and lockout right before showing prompt
        if let sock = clientSocket, !Self.isSocketAlive(sock) {
            currentTicket += 1
            lock.broadcast()
            lock.unlock()
            throw SigningPromptGateError.clientDisconnected
        }

        if let until = globalTracker.blockedUntil, now() < until {
            currentTicket += 1
            lock.broadcast()
            lock.unlock()
            throw SigningPromptGateError.coolingDown
        }

        if let until = requesterTrackers[effectiveReq]?.blockedUntil, now() < until {
            currentTicket += 1
            lock.broadcast()
            lock.unlock()
            throw SigningPromptGateError.coolingDown
        }

        // Mark prompt active and release lock during prompt presentation
        hasActivePrompt = true
        activeRequester = requester
        lock.unlock()

        // 5. Execute prompt body
        var bodyError: Error?
        var result: T?
        do {
            result = try body()
        } catch {
            bodyError = error
        }

        // 6. Complete turn and update counters under lock
        lock.lock()
        hasActivePrompt = false
        activeRequester = nil
        currentTicket += 1
        lock.broadcast()

        if let error = bodyError {
            if error is UserAuthenticationError {
                // Per-requester denial
                var reqTracker = requesterTrackers[effectiveReq] ?? DenialTracker()
                if let interval = reqTracker.recordDenial(
                    now: now(),
                    baseCooldown: baseCooldown,
                    maxCooldown: Self.maximumCooldown,
                    threshold: maxConsecutiveDenials
                ) {
                    ClavisLogger.log(
                        "SECURITY_ALERT",
                        "Signing prompts denied \(reqTracker.consecutiveDenials) times in a row for requester \(effectiveReq); refusing requests for \(Int(interval))s."
                    )
                }
                requesterTrackers[effectiveReq] = reqTracker

                // Global denial with smaller ceiling
                if let interval = globalTracker.recordDenial(
                    now: now(),
                    baseCooldown: min(baseCooldown, Self.globalMaximumCooldown),
                    maxCooldown: Self.globalMaximumCooldown,
                    threshold: globalMaxConsecutiveDenials
                ) {
                    ClavisLogger.log(
                        "SECURITY_ALERT",
                        "Signing prompts denied \(globalTracker.consecutiveDenials) times globally; refusing requests for \(Int(interval))s."
                    )
                }

                // Bound cache size
                if requesterTrackers.count > 100 {
                    let currentTime = now()
                    requesterTrackers = requesterTrackers.filter { _, tracker in
                        if let blocked = tracker.blockedUntil {
                            return currentTime < blocked
                        }
                        return tracker.consecutiveDenials > 0
                    }
                }
            }
            lock.unlock()
            throw error
        }

        // Success: reset denials
        requesterTrackers[effectiveReq]?.reset()
        globalTracker.reset()
        lock.unlock()

        return result!
    }
}
