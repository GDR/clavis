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


    func testHighFrequencyCategoriesAreDroppedUnlessVerbose() throws {
        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)

        ClavisLogger.customVerbose = false
        ClavisLogger.log("SSH_AGENT_REQ", "noise-quiet")
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "noise-quiet")
        ClavisLogger.log("KEY_LIST", "noise-quiet")
        ClavisLogger.log("SSH_AGENT", "kept-quiet")

        ClavisLogger.customVerbose = true
        ClavisLogger.log("SSH_AGENT_REQ", "noise-verbose")

        let contents = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertFalse(contents.contains("noise-quiet"))
        XCTAssertTrue(contents.contains("kept-quiet"))
        XCTAssertTrue(contents.contains("noise-verbose"))
    }


    func testSecurityEventsSurviveGeneralLogRotation() throws {
        ClavisLogger.customMaximumLogFileSize = 256
        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let securityURL = ClavisLogger.securityLogFileURL
        XCTAssertNotEqual(securityURL, logURL)

        ClavisLogger.log("SECURITY_ALERT", "evidence-\(UUID().uuidString)")
        let evidence = try String(contentsOf: securityURL, encoding: .utf8)
        XCTAssertTrue(evidence.contains("SECURITY_ALERT"))

        // Enough routine traffic to rotate the general log well past its 3 retained files.
        for index in 0..<60 {
            ClavisLogger.log("TEST", "routine-\(index)-\(String(repeating: "y", count: 80))")
        }

        let general = ClavisLogger.rotatedLogFiles()
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }
            .joined()
        XCTAssertFalse(general.contains("evidence-"), "Alert should have rotated out of the general log")
        XCTAssertTrue(try String(contentsOf: securityURL, encoding: .utf8).contains("evidence-"))

        let attributes = try FileManager.default.attributesOfItem(atPath: securityURL.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }


    func testLoggerEscapesEmbeddedNewlines() throws {
        ClavisLogger.log("TEST\nFORGED", "message\r\n[AUTH] forged")

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let contents = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertEqual(contents.split(separator: "\n").count, 1)
        XCTAssertTrue(contents.contains("TEST\\nFORGED"))
        XCTAssertTrue(contents.contains("message\\r\\n[AUTH] forged"))
    }

    func testLoggerMultiGenerationRotationAndPermissions() throws {
        ClavisLogger.customMaximumLogFileSize = 128
        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)

        for index in 0..<20 {
            ClavisLogger.log("TEST", "payload-\(index)-\(String(repeating: "a", count: 64))")
        }

        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: logURL.path))
        XCTAssertTrue(fm.fileExists(atPath: "\(logURL.path).1"))
        XCTAssertTrue(fm.fileExists(atPath: "\(logURL.path).2"))
        XCTAssertTrue(fm.fileExists(atPath: "\(logURL.path).3"))
        XCTAssertFalse(fm.fileExists(atPath: "\(logURL.path).4"))

        for index in 1...3 {
            let path = "\(logURL.path).\(index)"
            let attrs = try fm.attributesOfItem(atPath: path)
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }

        let rotatedList = ClavisLogger.rotatedLogFiles()
        XCTAssertEqual(rotatedList.count, 4)
    }

    func testLoggerRejectsSymlinkLogFiles() throws {
        let fakeTarget = testRootURL.appendingPathComponent("target-file.txt")
        try "initial target content\n".write(to: fakeTarget, atomically: true, encoding: .utf8)

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        try FileManager.default.createSymbolicLink(at: logURL, withDestinationURL: fakeTarget)

        ClavisLogger.log("MALICIOUS", "malicious payload trying to overwrite target")

        let targetContent = try String(contentsOf: fakeTarget, encoding: .utf8)
        XCTAssertEqual(targetContent, "initial target content\n")

        try? FileManager.default.removeItem(at: logURL)
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

    func testAgentLifecycleCodeSignatureVerificationRejectsUnsignedOrMismatchedBinary() throws {
        let fakeBinary = testRootURL.appendingPathComponent("fake-agent")
        try "#!/bin/sh\necho fake\n".write(to: fakeBinary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeBinary.path)

        // Without disabling signature check, unsigned file must fail verification
        AgentLifecycleManager.disableCodeSignatureCheckForTesting = false
        XCTAssertFalse(AgentLifecycleManager.verifyCodeSignature(of: fakeBinary))

        let lifecycle = AgentLifecycleManager()
        // Setting environment to unsigned binary should be rejected by locateAgentExecutable
        setenv("CLAVIS_AGENT_EXECUTABLE", fakeBinary.path, 1)
        defer { unsetenv("CLAVIS_AGENT_EXECUTABLE") }

        XCTAssertNil(lifecycle.locateAgentExecutable())
    }

    /// Copies a system binary and re-signs it ad-hoc with an attacker-chosen identifier.
    private func makeAdHocSignedBinary(identifier: String) throws -> URL {
        let url = testRootURL.appendingPathComponent("adhoc-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: url)
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--force", "--sign", "-", "--identifier", identifier, url.path]
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        try XCTSkipUnless(codesign.terminationStatus == 0, "codesign unavailable in this environment")
        return url
    }

    func testCodeSignatureRejectsAdHocBinaryClaimingSharedIdentifierWhenRequirementExists() throws {
        let impostor = try makeAdHocSignedBinary(identifier: ClavisCodeTrust.sharedIdentifier)
        let requirement = try XCTUnwrap(ClavisCodeTrust.makeRequirement(teamIdentifier: "ABCDE12345"))

        // The identifier matches, but a team-pinned requirement exists: no downgrade is allowed,
        // even if the development fallback is enabled.
        XCTAssertFalse(AgentLifecycleManager.verifyCodeSignature(
            of: impostor,
            requirement: requirement,
            allowIdentifierOnlyDevelopmentFallback: true
        ))
    }

    func testCodeSignatureIdentifierOnlyFallbackIsDevelopmentOnly() throws {
        let impostor = try makeAdHocSignedBinary(identifier: ClavisCodeTrust.sharedIdentifier)
        let unrelated = try makeAdHocSignedBinary(identifier: "com.clavis.not-really")

        // Release semantics: unsigned/ad-hoc parent without a team identifier fails closed.
        XCTAssertFalse(AgentLifecycleManager.verifyCodeSignature(
            of: impostor, requirement: nil, allowIdentifierOnlyDevelopmentFallback: false))

        // Development semantics: only the exact shared identifier is accepted (no prefix wildcards).
        XCTAssertTrue(AgentLifecycleManager.verifyCodeSignature(
            of: impostor, requirement: nil, allowIdentifierOnlyDevelopmentFallback: true))
        XCTAssertFalse(AgentLifecycleManager.verifyCodeSignature(
            of: unrelated, requirement: nil, allowIdentifierOnlyDevelopmentFallback: true))
    }

    func testCodeTrustRequirementRejectsMalformedTeamIdentifiers() {
        XCTAssertNotNil(ClavisCodeTrust.makeRequirement(teamIdentifier: "ABCDE12345"))
        for malformed in ["", "abcde12345", "ABCDE1234", "ABCDE123456", "ABCDE\" or true", "ABCDE1234\n"] {
            XCTAssertNil(ClavisCodeTrust.makeRequirement(teamIdentifier: malformed), malformed)
        }
    }

    @MainActor
    func testAppStateIgnoresSpoofedGitGraceNotificationUserInfo() throws {
        let cache = makeSessionCache()
        let socketPath = testRootURL.appendingPathComponent("spoof.sock").path
        let server = SSHAgentServer(socketPath: socketPath)
        let lifecycle = AgentLifecycleManager(socketPath: socketPath)
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: cache),
            sessionCache: cache,
            sshAgentServer: server,
            agentLifecycle: lifecycle
        )

        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        XCTAssertNil(appState.activeGitGrace)

        // Send forged notification with fake active grant
        DistributedNotificationCenter.default().postNotificationName(
            GitSigningGraceManager.gitGraceUpdatedNotification,
            object: nil,
            userInfo: [
                "active": true,
                "keyLabel": "forged-stolen-key",
                "remainingSeconds": 9999,
                "remainingOperations": 500
            ],
            deliverImmediately: true
        )

        // Wait for main actor runloop tick
        let deadline = Date().addingTimeInterval(0.2)
        while Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }

        // AppState must verify against authoritative state and reject the forged notification
        XCTAssertNil(appState.activeGitGrace, "AppState must not adopt spoofed userInfo from unauthenticated distributed notifications")
    }
}
