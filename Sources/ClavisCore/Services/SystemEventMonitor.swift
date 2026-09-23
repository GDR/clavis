import Foundation
import AppKit
import IOKit
import IOKit.pwr_mgt

typealias DarwinNotifyHandler = @convention(block) (Int32) -> Void

@_silgen_name("notify_register_dispatch")
private func sys_notify_register_dispatch(
    _ name: UnsafePointer<CChar>,
    _ out_token: UnsafeMutablePointer<Int32>,
    _ queue: DispatchQueue,
    _ handler: (@escaping DarwinNotifyHandler)
) -> UInt32

@_silgen_name("notify_post")
private func sys_notify_post(_ name: UnsafePointer<CChar>) -> UInt32

@_silgen_name("notify_cancel")
private func sys_notify_cancel(_ token: Int32) -> UInt32

/// Centralized monitor for system lock and sleep events.
///
/// Designed to reliably receive screen lock and sleep events in both GUI applications
/// and headless background daemons (such as `clavis-agent`) that run on Grand Central
/// Dispatch queues without an active `CFRunLoop`.
public final class SystemEventMonitor: @unchecked Sendable {
    public static let shared = SystemEventMonitor()

    public static var customScreenLockNotificationName: String? = nil {
        didSet {
            shared.reloadDarwinNotification()
        }
    }

    private let lock = NSLock()
    private var handlers: [String: () -> Void] = [:]
    private var darwinToken: Int32?
    private var rootPort: io_connect_t = 0
    private var notifier: io_object_t = 0
    private var portRef: IONotificationPortRef?
    private let queue = DispatchQueue(label: "com.clavis.system-events", qos: .userInitiated)

    public init() {
        setupDarwinNotifications()
        setupPowerMonitoring()
        setupWorkspaceNotifications()
    }

    deinit {
        stop()
    }

    public static func postDarwinNotification(_ name: String) {
        _ = sys_notify_post(name)
    }

    public func addHandler(id: String, handler: @escaping () -> Void) {
        lock.lock()
        handlers[id] = handler
        lock.unlock()
    }

    public func removeHandler(id: String) {
        lock.lock()
        handlers.removeValue(forKey: id)
        lock.unlock()
    }

    public func notifyHandlers() {
        lock.lock()
        let currentHandlers = Array(handlers.values)
        lock.unlock()
        for handler in currentHandlers {
            handler()
        }
    }

    public func reloadDarwinNotification() {
        lock.lock()
        defer { lock.unlock() }
        if let token = darwinToken {
            _ = sys_notify_cancel(token)
            darwinToken = nil
        }
        setupDarwinNotificationsLocked()
    }

    private func setupDarwinNotifications() {
        lock.lock()
        defer { lock.unlock() }
        setupDarwinNotificationsLocked()
    }

    private func setupDarwinNotificationsLocked() {
        let name = Self.customScreenLockNotificationName ?? "com.apple.screenIsLocked"
        var token: Int32 = 0
        let status = sys_notify_register_dispatch(name, &token, queue) { [weak self] _ in
            ClavisLogger.log("SYSTEM_EVENT", "Screen lock detected via Darwin notification.")
            self?.notifyHandlers()
        }
        if status == 0 {
            darwinToken = token
        }
    }

    private func setupPowerMonitoring() {
        let callback: IOServiceInterestCallback = { (refcon, service, messageType, messageArgument) in
            guard let refcon = refcon else { return }
            let monitor = Unmanaged<SystemEventMonitor>.fromOpaque(refcon).takeUnretainedValue()
            // 0xe0000280 = kIOMessageSystemWillSleep
            // 0xe0000270 = kIOMessageCanSystemSleep
            if messageType == 0xe0000280 || messageType == 0xe0000270 {
                ClavisLogger.log("SYSTEM_EVENT", "System sleep detected via IOKit power notification.")
                monitor.notifyHandlers()
                IOAllowPowerChange(monitor.rootPort, Int(bitPattern: messageArgument))
            }
        }

        let refcon = Unmanaged.passUnretained(self).toOpaque()
        rootPort = IORegisterForSystemPower(refcon, &portRef, callback, &notifier)
        if let port = portRef {
            IONotificationPortSetDispatchQueue(port, queue)
        }
    }

    private func setupWorkspaceNotifications() {
        DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.notifyHandlers()
        }
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.notifyHandlers()
        }
    }

    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        if let token = darwinToken {
            _ = sys_notify_cancel(token)
            darwinToken = nil
        }
        if notifier != 0 {
            IODeregisterForSystemPower(&notifier)
            notifier = 0
        }
        if let port = portRef {
            IONotificationPortDestroy(port)
            portRef = nil
        }
        if rootPort != 0 {
            IOServiceClose(rootPort)
            rootPort = 0
        }
    }
}
