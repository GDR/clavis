import XCTest
@testable import ClavisCore
@testable import Clavis

private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T

    init(_ value: T) {
        self._value = value
    }

    var value: T {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _value
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _value = newValue
        }
    }
}

final class SingleInstanceLockDecouplingTests: ClavisBaseTestCase {

    override func tearDownWithError() throws {
        SingleInstanceLock.processActivator = nil
        try super.tearDownWithError()
    }

    func testLockConflict_withConfiguredActivator_invokesActivatorWithOwnerPID() throws {
        let lockURL = testRootURL.appendingPathComponent("conflict_test_\(UUID().uuidString).lock")
        let primaryLock = SingleInstanceLock(name: "primary", bringToFrontOnConflict: true, customLockFileURL: lockURL)
        defer {
            primaryLock.release()
            try? FileManager.default.removeItem(at: lockURL)
        }

        XCTAssertTrue(primaryLock.acquire(), "Primary lock must be acquired successfully")
        XCTAssertEqual(primaryLock.lockOwnerPID, getpid(), "Owner PID should match current process PID")

        let activatedPID = LockedBox<pid_t?>(nil)
        let secondaryLock = SingleInstanceLock(
            name: "secondary",
            bringToFrontOnConflict: true,
            customLockFileURL: lockURL,
            processActivator: { pid in
                activatedPID.value = pid
            }
        )
        defer { secondaryLock.release() }

        let acquiredSecondary = secondaryLock.acquire()
        XCTAssertFalse(acquiredSecondary, "Secondary lock acquisition must fail when file is locked")
        XCTAssertEqual(activatedPID.value, getpid(), "Configured activator must be invoked with owner PID on conflict")
    }

    func testLockConflict_withoutConfiguredActivator_failsGracefully() throws {
        let lockURL = testRootURL.appendingPathComponent("conflict_no_act_\(UUID().uuidString).lock")
        let primaryLock = SingleInstanceLock(name: "primary", bringToFrontOnConflict: true, customLockFileURL: lockURL)
        defer {
            primaryLock.release()
            try? FileManager.default.removeItem(at: lockURL)
        }

        XCTAssertTrue(primaryLock.acquire())

        SingleInstanceLock.processActivator = nil
        let secondaryLock = SingleInstanceLock(
            name: "secondary",
            bringToFrontOnConflict: true,
            customLockFileURL: lockURL,
            processActivator: nil
        )
        defer { secondaryLock.release() }

        let acquiredSecondary = secondaryLock.acquire()
        XCTAssertFalse(acquiredSecondary, "Secondary lock acquisition must fail gracefully without activator")
    }

    func testLockConflict_whenBringToFrontFalse_doesNotInvokeActivator() throws {
        let lockURL = testRootURL.appendingPathComponent("conflict_no_bring_\(UUID().uuidString).lock")
        let primaryLock = SingleInstanceLock(name: "primary", bringToFrontOnConflict: false, customLockFileURL: lockURL)
        defer {
            primaryLock.release()
            try? FileManager.default.removeItem(at: lockURL)
        }

        XCTAssertTrue(primaryLock.acquire())

        let activatorCalled = LockedBox(false)
        let secondaryLock = SingleInstanceLock(
            name: "secondary",
            bringToFrontOnConflict: false,
            customLockFileURL: lockURL,
            processActivator: { _ in
                activatorCalled.value = true
            }
        )
        defer { secondaryLock.release() }

        let acquiredSecondary = secondaryLock.acquire()
        XCTAssertFalse(acquiredSecondary)
        XCTAssertFalse(activatorCalled.value, "Activator must NOT be called when bringToFrontOnConflict is false")
    }

    func testStaticProcessActivatorFallback() throws {
        let lockURL = testRootURL.appendingPathComponent("static_fallback_\(UUID().uuidString).lock")
        let primaryLock = SingleInstanceLock(name: "primary", bringToFrontOnConflict: true, customLockFileURL: lockURL)
        defer {
            primaryLock.release()
            try? FileManager.default.removeItem(at: lockURL)
        }

        XCTAssertTrue(primaryLock.acquire())

        let staticActivatedPID = LockedBox<pid_t?>(nil)
        SingleInstanceLock.processActivator = { pid in
            staticActivatedPID.value = pid
        }

        let secondaryLock = SingleInstanceLock(
            name: "secondary",
            bringToFrontOnConflict: true,
            customLockFileURL: lockURL,
            processActivator: nil
        )
        defer { secondaryLock.release() }

        let acquiredSecondary = secondaryLock.acquire()
        XCTAssertFalse(acquiredSecondary)
        XCTAssertEqual(staticActivatedPID.value, getpid(), "Static processActivator must be used as fallback when instance activator is nil")
    }

    func testAppKitProcessActivator_invalidPID_doesNotCrash() {
        AppKitProcessActivator.activate(processIdentifier: 999999)
    }
}
