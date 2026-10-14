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
        SystemEventMonitor.customSessionActiveValidator = nil
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
        let lock = NSLock()
        var fireCount = 0
        observer.startObserving {
            lock.lock()
            fireCount += 1
            lock.unlock()
        }

        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.screensDidSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)

        lock.lock()
        let countAfterPosts = fireCount
        lock.unlock()
        XCTAssertEqual(countAfterPosts, 3, "AppKitSleepObserver must fire on sleep, display sleep, and session resign")

        observer.stopObserving()
        // Idempotent stop
        observer.stopObserving()

        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        lock.lock()
        let countAfterStop = fireCount
        lock.unlock()
        XCTAssertEqual(countAfterStop, 3)
    }

    func test_F8_customSessionActiveValidatorInvalidatesGrants() throws {
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)
        let myPid = getpid()
        let myStart = ProcessInspector.processStartTime(pid: myPid) ?? 100
        let approved = GitApprovedProcess(pid: myPid, startTime: myStart, path: "/usr/bin/git")

        let gitGrant = graceManager.recordGrant(
            keyLabel: "f8-git-key",
            clientIdentity: "/usr/bin/git",
            duration: 300,
            maxOperations: 10,
            context: .init(),
            approvedProcess: approved,
            hardwareSigner: { _ in Data("sig".utf8) }
        )
        graceManager.recordGitSignature(for: "f8-git-key", clientIdentity: "/usr/bin/git")

        let keyMgr = makeKeyManager()
        let agentKey = try keyMgr.generateKey(label: "f8-agent-key", keyPurpose: .agent)
        let agentGrant = AgentSessionGrant(
            key: agentKey,
            context: .init(),
            hardwareSigner: { _ in Data("agent-sig".utf8) }
        )

        XCTAssertTrue(gitGrant.isValid)
        XCTAssertTrue(agentGrant.isValid)
        XCTAssertNotNil(graceManager.getValidGrant(for: "f8-git-key"))
        XCTAssertTrue(graceManager.hasRecentGitSignature(for: "f8-git-key", clientIdentity: "/usr/bin/git"))

        // Simulate locked / off-console session via customSessionActiveValidator
        SystemEventMonitor.customSessionActiveValidator = { false }
        XCTAssertTrue(SystemEventMonitor.isSessionLockedOrOffConsole())

        XCTAssertFalse(gitGrant.isValid)
        XCTAssertNil(graceManager.getValidGrant(for: "f8-git-key"))
        XCTAssertFalse(graceManager.hasRecentGitSignature(for: "f8-git-key", clientIdentity: "/usr/bin/git"))
        XCTAssertThrowsError(try gitGrant.sign(Data("payload".utf8))) { error in
            XCTAssertEqual(error as? AgentSessionGrantError, .grantInvalidated)
        }

        XCTAssertFalse(agentGrant.isValid)
        XCTAssertThrowsError(try agentGrant.sign(Data("payload".utf8))) { error in
            XCTAssertEqual(error as? AgentSessionGrantError, .grantInvalidated)
        }

        // Restoring active session does not resurrect permanently invalidated grants
        SystemEventMonitor.customSessionActiveValidator = { true }
        XCTAssertFalse(SystemEventMonitor.isSessionLockedOrOffConsole())
        XCTAssertFalse(gitGrant.isValid)
        XCTAssertFalse(agentGrant.isValid)
    }
}
