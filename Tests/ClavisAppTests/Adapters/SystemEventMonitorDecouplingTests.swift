import Foundation
import Testing
import AppKit
@testable import ClavisCore
@testable import ClavisTestSupport
@testable import Clavis

final class MockSleepObserver: SystemSleepObserving, @unchecked Sendable {
    private let lock = NSLock()
    private var callback: (@Sendable () -> Void)?
    private var _isObserving: Bool = false
    private var _startObservingCallCount: Int = 0
    private var _stopObservingCallCount: Int = 0

    var isObserving: Bool {
        lock.lock(); defer { lock.unlock() }
        return _isObserving
    }
    var startObservingCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _startObservingCallCount
    }
    var stopObservingCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _stopObservingCallCount
    }

    func startObserving(onSleep: @escaping @Sendable () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        _isObserving = true
        _startObservingCallCount += 1
        callback = onSleep
    }

    func stopObserving() {
        lock.lock()
        defer { lock.unlock() }
        _isObserving = false
        _stopObservingCallCount += 1
        callback = nil
    }

    func triggerSleep() {
        lock.lock()
        let cb = callback
        lock.unlock()
        cb?()
    }
}

@Suite(.serialized)
struct SystemEventMonitorDecouplingTests {

    @Test func testSystemEventMonitor_withConfiguredSleepObserver_firesHandlersOnSleep() {
        let mockObserver = MockSleepObserver()
        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver
        )
        defer { monitor.stop() }

        #expect(mockObserver.isObserving)
        #expect(mockObserver.startObservingCallCount == 1)

        var handlerCalled = false
        monitor.addHandler(id: "test-sleep-handler") {
            handlerCalled = true
        }

        mockObserver.triggerSleep()
        #expect(handlerCalled, "SystemEventMonitor handlers should be invoked when sleep observer fires")
    }

    @Test func testSystemEventMonitor_stop_stopsSleepObserver() {
        let mockObserver = MockSleepObserver()
        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver
        )

        #expect(mockObserver.isObserving)

        monitor.stop()

        #expect(!mockObserver.isObserving)
        #expect(mockObserver.stopObservingCallCount == 1)
    }

    @Test func testSystemEventMonitor_setSleepObserver_replacesPreviousObserver() {
        let mockObserver1 = MockSleepObserver()
        let mockObserver2 = MockSleepObserver()

        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: mockObserver1
        )
        defer { monitor.stop() }

        #expect(mockObserver1.isObserving)

        monitor.setSleepObserver(mockObserver2)

        #expect(!mockObserver1.isObserving)
        #expect(mockObserver1.stopObservingCallCount == 1)
        #expect(mockObserver2.isObserving)
        #expect(mockObserver2.startObservingCallCount == 1)

        var handler2CallCount = 0
        monitor.addHandler(id: "handler-2") {
            handler2CallCount += 1
        }

        mockObserver2.triggerSleep()
        #expect(handler2CallCount == 1)

        // Triggering old observer should do nothing since it was stopped and unreferenced
        mockObserver1.triggerSleep()
        #expect(handler2CallCount == 1)
    }

    @Test func testSystemEventMonitor_defaultSleepObserverFactoryFallback() {
        let mockObserver = MockSleepObserver()
        SystemEventMonitor.defaultSleepObserverFactory = {
            mockObserver
        }
        defer { SystemEventMonitor.defaultSleepObserverFactory = nil }

        let monitor = SystemEventMonitor(
            observeDarwinEvents: false,
            observeIOKitPower: false,
            observeDistributedNotifications: false,
            sleepObserver: nil
        )
        defer { monitor.stop() }

        #expect(mockObserver.isObserving)
        #expect(mockObserver.startObservingCallCount == 1)
    }

    @Test func testSystemEventMonitor_withoutSleepObserver_operatesNormally() {
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
        #expect(handlerCalled)

        handlerCalled = false
        monitor.removeHandler(id: "manual-notify")
        monitor.notifyHandlers()
        #expect(!handlerCalled)
    }

    @Test func testAppKitSleepObserver_startAndStopObserving() {
        final class CounterBox: @unchecked Sendable {
            private let lock = NSLock()
            private var count = 0
            func increment() {
                lock.lock()
                count += 1
                lock.unlock()
            }
            func value() -> Int {
                lock.lock()
                defer { lock.unlock() }
                return count
            }
        }
        let observer = AppKitSleepObserver()
        let counter = CounterBox()
        observer.startObserving {
            counter.increment()
        }

        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.screensDidSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)

        let countAfterPosts = counter.value()
        #expect(countAfterPosts == 3, "AppKitSleepObserver must fire on sleep, display sleep, and session resign")

        observer.stopObserving()
        // Idempotent stop
        observer.stopObserving()

        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        let countAfterStop = counter.value()
        #expect(countAfterStop == 3)
    }

    @Test func test_F8_customSessionActiveValidatorInvalidatesGrants() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

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

        let keyMgr = fixture.makeKeyManager()
        let agentKey = try keyMgr.generateKey(label: "f8-agent-key", keyPurpose: .agent)
        let agentGrant = AgentSessionGrant(
            key: agentKey,
            context: .init(),
            hardwareSigner: { _ in Data("agent-sig".utf8) }
        )

        #expect(gitGrant.isValid)
        #expect(agentGrant.isValid)
        #expect(graceManager.getValidGrant(for: "f8-git-key") != nil)
        #expect(graceManager.hasRecentGitSignature(for: "f8-git-key", clientIdentity: "/usr/bin/git"))

        // Simulate locked / off-console session via task-local mockSessionValidator
        var lockedContext = fixture.context
        lockedContext.mockSessionValidator = { false }
        TestContextScope.$current.withValue(lockedContext) {
            #expect(SystemEventMonitor.isSessionLockedOrOffConsole())

            #expect(!gitGrant.isValid)
            #expect(graceManager.getValidGrant(for: "f8-git-key") == nil)
            #expect(!graceManager.hasRecentGitSignature(for: "f8-git-key", clientIdentity: "/usr/bin/git"))
            #expect(throws: AgentSessionGrantError.grantInvalidated) {
                try gitGrant.sign(Data("payload".utf8))
            }

            #expect(!agentGrant.isValid)
            #expect(throws: AgentSessionGrantError.grantInvalidated) {
                try agentGrant.sign(Data("payload".utf8))
            }
        }

        // Restoring active session does not resurrect permanently invalidated grants
        var activeContext = fixture.context
        activeContext.mockSessionValidator = { true }
        TestContextScope.$current.withValue(activeContext) {
            #expect(!SystemEventMonitor.isSessionLockedOrOffConsole())
            #expect(!gitGrant.isValid)
            #expect(!agentGrant.isValid)
        }
    }
}
