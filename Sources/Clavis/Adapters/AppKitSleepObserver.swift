import AppKit
import ClavisCore

public final class AppKitSleepObserver: SystemSleepObserving, @unchecked Sendable {
    private let lock = NSLock()
    private var observerToken: (any NSObjectProtocol)?

    public init() {}

    public func startObserving(onSleep: @escaping @Sendable () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        stopObservingLocked()
        observerToken = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: nil
        ) { _ in
            onSleep()
        }
    }

    public func stopObserving() {
        lock.lock()
        defer { lock.unlock() }
        stopObservingLocked()
    }

    private func stopObservingLocked() {
        if let token = observerToken {
            NSWorkspace.shared.notificationCenter.removeObserver(token)
            observerToken = nil
        }
    }

    deinit {
        stopObserving()
    }
}
