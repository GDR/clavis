import AppKit
import ClavisCore

public final class AppKitSleepObserver: SystemSleepObserving, @unchecked Sendable {
    private let lock = NSLock()
    private var observerTokens: [any NSObjectProtocol] = []

    public init() {}

    public func startObserving(onSleep: @escaping @Sendable () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        stopObservingLocked()
        let center = NSWorkspace.shared.notificationCenter
        let notifications = [
            NSWorkspace.willSleepNotification,
            NSWorkspace.screensDidSleepNotification,
            NSWorkspace.sessionDidResignActiveNotification
        ]
        for name in notifications {
            let token = center.addObserver(
                forName: name,
                object: nil,
                queue: nil
            ) { _ in
                onSleep()
            }
            observerTokens.append(token)
        }
    }

    public func stopObserving() {
        lock.lock()
        defer { lock.unlock() }
        stopObservingLocked()
    }

    private func stopObservingLocked() {
        let center = NSWorkspace.shared.notificationCenter
        for token in observerTokens {
            center.removeObserver(token)
        }
        observerTokens.removeAll()
    }

    deinit {
        stopObserving()
    }
}
