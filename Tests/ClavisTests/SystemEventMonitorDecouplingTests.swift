import XCTest
@testable import ClavisCore
@testable import Clavis

final class MockSleepObserver: SystemSleepObserving, @unchecked Sendable {
    private let lock = NSLock()
    private var callback: (@Sendable () -> Void)?
    private(set) var isObserving: Bool = false
    private(set) var startObservingCallCount: Int = 0
    private(set) var stopObservingCallCount: Int = 0

    func startObserving(onSleep: @escaping @Sendable () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        isObserving = true
        startObservingCallCount += 1
        callback = onSleep
    }

    func stopObserving() {
        lock.lock()
        defer { lock.unlock() }
        isObserving = false
        stopObservingCallCount += 1
        callback = nil
    }

    func triggerSleep() {
        lock.lock()
        let cb = callback
        lock.unlock()
        cb?()
    }
}

final class SystemEventMonitorDecouplingTests: ClavisBaseTestCase {

    override func tearDownWithError() throws {
        SystemEventMonitor.defaultSleepObserverFactory = nil
        try super.tearDownWithError()
    }

    func testSystemEventMonitor_withConfiguredSleepObserver_firesHandlersOnSleep() {
        let mockObserver = MockSleepObserver()
        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver
        )
        defer { monitor.stop() }

        XCTAssertTrue(mockObserver.isObserving)
        XCTAssertEqual(mockObserver.startObservingCallCount, 1)

        var handlerCalled = false
        monitor.addHandler(id: "test-sleep-handler") {
            handlerCalled = true
        }

        mockObserver.triggerSleep()
        XCTAssertTrue(handlerCalled, "SystemEventMonitor handlers should be invoked when sleep observer fires")
    }

    func testSystemEventMonitor_stop_stopsSleepObserver() {
        let mockObserver = MockSleepObserver()
        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver
        )

        XCTAssertTrue(mockObserver.isObserving)

        monitor.stop()

        XCTAssertFalse(mockObserver.isObserving)
        XCTAssertEqual(mockObserver.stopObservingCallCount, 1)
    }

    func testSystemEventMonitor_setSleepObserver_replacesPreviousObserver() {
        let mockObserver1 = MockSleepObserver()
        let mockObserver2 = MockSleepObserver()

        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver1
        )
        defer { monitor.stop() }

        XCTAssertTrue(mockObserver1.isObserving)

        monitor.setSleepObserver(mockObserver2)

        XCTAssertFalse(mockObserver1.isObserving)
        XCTAssertEqual(mockObserver1.stopObservingCallCount, 1)
        XCTAssertTrue(mockObserver2.isObserving)
        XCTAssertEqual(mockObserver2.startObservingCallCount, 1)

        var handler2CallCount = 0
        monitor.addHandler(id: "handler-2") {
            handler2CallCount += 1
        }

        mockObserver2.triggerSleep()
        XCTAssertEqual(handler2CallCount, 1)

        // Triggering old observer should do nothing since it was stopped and unreferenced
        mockObserver1.triggerSleep()
        XCTAssertEqual(handler2CallCount, 1)
    }

    func testSystemEventMonitor_defaultSleepObserverFactoryFallback() {
        let mockObserver = MockSleepObserver()
        SystemEventMonitor.defaultSleepObserverFactory = {
            mockObserver
        }

        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: nil
        )
        defer { monitor.stop() }

        XCTAssertTrue(mockObserver.isObserving)
        XCTAssertEqual(mockObserver.startObservingCallCount, 1)
    }

    func testSystemEventMonitor_withoutSleepObserver_operatesNormally() {
        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: nil
        )
        defer { monitor.stop() }

        var handlerCalled = false
        monitor.addHandler(id: "manual-notify") {
            handlerCalled = true
        }

        monitor.notifyHandlers()
        XCTAssertTrue(handlerCalled)

        handlerCalled = false
        monitor.removeHandler(id: "manual-notify")
        monitor.notifyHandlers()
        XCTAssertFalse(handlerCalled)
    }

    func testAppKitSleepObserver_startAndStopObserving() {
        let observer = AppKitSleepObserver()
        observer.startObserving { }
        observer.stopObserving()
        // Idempotent stop
        observer.stopObserving()
    }
}
