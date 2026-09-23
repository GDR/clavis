import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class DaemonLifecycleTests: ClavisBaseTestCase {

    func testLoggerUsesPrivatePermissionsAndRotates() throws {
        ClavisLogger.customMaximumLogFileSize = 256
        for index in 0..<8 {
            ClavisLogger.log("TEST", "entry-\(index)-\(String(repeating: "x", count: 80))")
        }

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let logAttributes = try FileManager.default.attributesOfItem(atPath: logURL.path)
        XCTAssertEqual((logAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: logURL.deletingLastPathComponent().path)
        XCTAssertEqual((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        XCTAssertTrue(FileManager.default.fileExists(atPath: "\(logURL.path).1"))
    }


    func testLoggerEscapesEmbeddedNewlines() throws {
        ClavisLogger.log("TEST\nFORGED", "message\r\n[AUTH] forged")

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let contents = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertEqual(contents.split(separator: "\n").count, 1)
        XCTAssertTrue(contents.contains("TEST\\nFORGED"))
        XCTAssertTrue(contents.contains("message\\r\\n[AUTH] forged"))
    }


    func testSingleInstanceLockAcquireAndRelease() {
        let tempURL = testRootURL.appendingPathComponent("clavis_test_\(UUID().uuidString).lock")
        SingleInstanceLock.customLockFileURL = tempURL
        defer {
            SingleInstanceLock.shared.release()
            SingleInstanceLock.customLockFileURL = nil
            try? FileManager.default.removeItem(at: tempURL)
        }

        let lock = SingleInstanceLock.shared
        lock.release()

        XCTAssertTrue(lock.acquire())
        XCTAssertTrue(lock.acquire())

        let fd = open(tempURL.path, O_RDWR)
        if fd >= 0 {
            let flockRes = flock(fd, LOCK_EX | LOCK_NB)
            XCTAssertEqual(flockRes, -1)
            XCTAssertEqual(errno, EWOULDBLOCK)
            close(fd)
        }

        lock.release()
        let fd2 = open(tempURL.path, O_RDWR)
        if fd2 >= 0 {
            let flockRes2 = flock(fd2, LOCK_EX | LOCK_NB)
            XCTAssertEqual(flockRes2, 0)
            flock(fd2, LOCK_UN)
            close(fd2)
        }
    }


    func testSingleInstanceLockGuiAndAgentConcurrency() throws {
        let guiURL = testRootURL.appendingPathComponent("test_gui_\(UUID().uuidString).lock")
        let agentURL = testRootURL.appendingPathComponent("test_agent_\(UUID().uuidString).lock")

        let guiLock = SingleInstanceLock(name: "test-gui", bringToFrontOnConflict: false, customLockFileURL: guiURL)
        let agentLock = SingleInstanceLock(name: "test-agent", bringToFrontOnConflict: false, customLockFileURL: agentURL)

        defer {
            guiLock.release()
            agentLock.release()
            try? FileManager.default.removeItem(at: guiURL)
            try? FileManager.default.removeItem(at: agentURL)
        }

        // Both GUI and Agent locks must acquire successfully simultaneously
        XCTAssertTrue(guiLock.acquire())
        XCTAssertTrue(agentLock.acquire())

        // lockOwnerPID should identify this process
        XCTAssertEqual(guiLock.lockOwnerPID, getpid())
        XCTAssertEqual(agentLock.lockOwnerPID, getpid())

        // A second instance trying to acquire the same file must fail
        let duplicateGuiLock = SingleInstanceLock(name: "test-gui-dup", bringToFrontOnConflict: false, customLockFileURL: guiURL)
        XCTAssertFalse(duplicateGuiLock.acquire())

        // Release GUI lock; duplicate can now acquire
        guiLock.release()
        XCTAssertTrue(duplicateGuiLock.acquire())
        duplicateGuiLock.release()
    }

    func testSingleInstanceLockStaleLockIgnored() throws {
        let staleURL = testRootURL.appendingPathComponent("test_stale_\(UUID().uuidString).lock")
        defer { try? FileManager.default.removeItem(at: staleURL) }

        // Write PID 1 (launchd, always running) to a file WITHOUT holding flock
        try "1\n".write(to: staleURL, atomically: true, encoding: .utf8)

        let staleLock = SingleInstanceLock(name: "test-stale", bringToFrontOnConflict: false, customLockFileURL: staleURL)

        // lockOwnerPID must return nil because flock is not held, despite PID 1 being alive
        XCTAssertNil(staleLock.lockOwnerPID)

        // acquire() must succeed and take over the stale lock file
        XCTAssertTrue(staleLock.acquire())
        XCTAssertEqual(staleLock.lockOwnerPID, getpid())
        staleLock.release()
    }


    func testSSHAgentServerIsSocketListeningAndCollisionPrevention() throws {
        let testSockPath = testRootURL.appendingPathComponent("t-listen.sock").path

        // 1. Initial state: socket does not exist, isSocketListening must be false
        XCTAssertFalse(SSHAgentServer.isSocketListening(atPath: testSockPath))

        // 2. Start primary server
        let primaryServer = SSHAgentServer(socketPath: testSockPath)
        try primaryServer.start()
        defer { primaryServer.stop() }

        // Wait up to 1 second for socket to be active
        let deadline = Date().addingTimeInterval(1.0)
        var listening = false
        while Date() < deadline {
            if SSHAgentServer.isSocketListening(atPath: testSockPath) {
                listening = true
                break
            }
            usleep(10_000)
        }
        XCTAssertTrue(listening, "Server should be actively listening on socket")

        // 3. Attempting to start a second server on the same socket must fail with socketAlreadyInUse
        let secondaryServer = SSHAgentServer(socketPath: testSockPath)
        XCTAssertThrowsError(try secondaryServer.start()) { error in
            guard let serverError = error as? SSHAgentServerError else {
                XCTFail("Expected SSHAgentServerError, got \(error)")
                return
            }
            XCTAssertEqual(serverError, .socketAlreadyInUse(testSockPath))
        }

        // 4. Primary server must remain active and listening despite the collision attempt
        XCTAssertTrue(SSHAgentServer.isSocketListening(atPath: testSockPath))

        // 5. Stopping primary server makes socket not listening
        primaryServer.stop()
        XCTAssertFalse(SSHAgentServer.isSocketListening(atPath: testSockPath))
    }


    func testAgentLifecycleManagerSocketDetection() throws {
        let testSockPath = testRootURL.appendingPathComponent("t-life.sock").path
        let manager = AgentLifecycleManager(socketPath: testSockPath)

        XCTAssertFalse(manager.isAgentRunning)

        let server = SSHAgentServer(socketPath: testSockPath)
        try server.start()
        defer { server.stop() }

        let deadline = Date().addingTimeInterval(1.0)
        var isRunning = false
        while Date() < deadline {
            if manager.isAgentRunning {
                isRunning = true
                break
            }
            usleep(10_000)
        }
        XCTAssertTrue(isRunning)

        server.stop()
        XCTAssertFalse(manager.isAgentRunning)
    }


    @MainActor
    func testAppStateInitializationAndDaemonFlag() {
        let sessionCache = makeSessionCache()
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: sessionCache),
            sessionCache: sessionCache,
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-state.sock").path)
        )
        XCTAssertNotNil(appState)

        // Test setTimeout method syncs with SessionCacheManager
        appState.setTimeout(.fiveMinutes)
        XCTAssertEqual(sessionCache.currentTimeout, .fiveMinutes)
        XCTAssertEqual(appState.selectedTimeout, .fiveMinutes)

        appState.setTimeout(.never)
        XCTAssertEqual(sessionCache.currentTimeout, .never)
        XCTAssertEqual(appState.selectedTimeout, .never)

        // Test lockNow clears cache and refreshes state
        sessionCache.currentTimeout = .fiveMinutes
        sessionCache.set(label: "test-lock", key: Curve25519.Signing.PrivateKey())
        appState.lockNow()
        XCTAssertEqual(sessionCache.cachedCount, 0)
        XCTAssertEqual(appState.cachedKeysCount, 0)

        // Test clearError
        appState.clearError()
        XCTAssertNil(appState.errorMessage)
    }


    @MainActor
    func testDaemonModeFlagParsing() {
        let isDaemonMode = CommandLine.arguments.contains("--daemon")
        XCTAssertEqual(AppState.shared.isDaemonMode, isDaemonMode)
    }

    @MainActor
    func testApplicationDelegateRunsShutdownExactlyOnceForAllTerminationCallbacks() {
        var shutdownCount = 0
        let delegate = ClavisApplicationDelegate {
            shutdownCount += 1
        }

        let reply = delegate.applicationShouldTerminate(NSApplication.shared)
        delegate.applicationWillTerminate(
            Notification(name: NSApplication.willTerminateNotification)
        )

        XCTAssertEqual(reply, .terminateNow)
        XCTAssertEqual(shutdownCount, 1)
    }

    @MainActor
    func testAppTerminationClearsCachesStopsServerAndStopsAgent() throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .fiveMinutes
        cache.set(label: "termination-key", key: Curve25519.Signing.PrivateKey())

        let socketPath = testRootURL.appendingPathComponent("termination.sock").path
        let server = SSHAgentServer(socketPath: socketPath)
        try server.start()

        var agentStopCount = 0
        let lifecycle = AgentLifecycleManager(socketPath: socketPath)
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: cache),
            sessionCache: cache,
            sshAgentServer: server,
            agentLifecycle: lifecycle,
            terminationAgentStop: {
                agentStopCount += 1
                return true
            }
        )

        appState.shutdownForTermination()

        XCTAssertEqual(cache.cachedCount, 0)
        XCTAssertFalse(server.isSocketActive)
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath))
        XCTAssertEqual(agentStopCount, 1)
        XCTAssertFalse(appState.isSocketActive)
        XCTAssertNil(appState.agentPID)
    }


    func testLaunchAtLoginManager() {
        let tempPlistURL = FileManager.default.temporaryDirectory.appendingPathComponent("clavis_launch_\(UUID().uuidString).plist")
        LaunchAtLoginManager.customLaunchAgentURL = tempPlistURL
        defer {
            LaunchAtLoginManager.customLaunchAgentURL = nil
            try? FileManager.default.removeItem(at: tempPlistURL)
        }

        let mgr = LaunchAtLoginManager.shared
        XCTAssertFalse(mgr.isEnabled)

        mgr.setLaunchAtLogin(enabled: true)
        XCTAssertTrue(mgr.isEnabled)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempPlistURL.path))

        mgr.setLaunchAtLogin(enabled: false)
        XCTAssertFalse(mgr.isEnabled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempPlistURL.path))
    }


}
