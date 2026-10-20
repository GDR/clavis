@testable import ClavisTestSupport
import Foundation
import Testing
import CryptoKit
import LocalAuthentication
import AppKit
@testable import ClavisCore
@testable import Clavis

@Suite(.serialized)
final class DaemonLifecycleTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    private func makeKeyManager(
        authenticator: UserAuthenticating = AllowingAuthenticator(),
        privateKeyStore: PrivateKeyStoring = InMemoryPrivateKeyStore(),
        vaultStore: EncryptedVaultStore? = nil,
        auditRecorder: AuditRecording = InMemoryAuditRecorder(),
        signingProvider: SecureEnclaveSigningProviding? = nil,
        gitSigningGraceManager: GitSigningGraceManager = .shared
    ) -> KeychainManager {
        fixture.makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: privateKeyStore,
            vaultStore: vaultStore,
            auditRecorder: auditRecorder,
            signingProvider: signingProvider,
            gitSigningGraceManager: gitSigningGraceManager
        )
    }

    @Test func testLoggerUsesPrivatePermissionsAndRotates() throws {
        try fixture.runSync {
            let logURL = testRootURL.appendingPathComponent("clavis.log")
            ClavisLogger.customLogFileURL = logURL
            defer {
                ClavisLogger.customLogFileURL = nil
                ClavisLogger.customMaximumLogFileSize = nil
            }
            ClavisLogger.customMaximumLogFileSize = 256
            for index in 0..<8 {
                ClavisLogger.log("TEST", "entry-\(index)-\(String(repeating: "x", count: 80))")
            }

            let logAttributes = try FileManager.default.attributesOfItem(atPath: logURL.path)
            #expect((logAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

            let directoryAttributes = try FileManager.default.attributesOfItem(atPath: logURL.deletingLastPathComponent().path)
            #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
            #expect(FileManager.default.fileExists(atPath: "\(logURL.path).1"))
        }
    }

    @Test func testHighFrequencyCategoriesAreDroppedUnlessVerbose() throws {
        try fixture.runSync {
            let logURL = testRootURL.appendingPathComponent("clavis.log")
            ClavisLogger.customLogFileURL = logURL
            defer {
                ClavisLogger.customLogFileURL = nil
                ClavisLogger.customVerbose = nil
            }

            ClavisLogger.customVerbose = false
            ClavisLogger.log("SSH_AGENT_REQ", "noise-quiet")
            ClavisLogger.log("SSH_AGENT_IDENTITIES", "noise-quiet")
            ClavisLogger.log("KEY_LIST", "noise-quiet")
            ClavisLogger.log("SSH_AGENT", "kept-quiet")

            ClavisLogger.customVerbose = true
            ClavisLogger.log("SSH_AGENT_REQ", "noise-verbose")

            let contents = try String(contentsOf: logURL, encoding: .utf8)
            #expect(!contents.contains("noise-quiet"))
            #expect(contents.contains("kept-quiet"))
            #expect(contents.contains("noise-verbose"))
        }
    }

    @Test func testLoggerEscapesEmbeddedNewlines() throws {
        try fixture.runSync {
            let logURL = testRootURL.appendingPathComponent("clavis.log")
            ClavisLogger.customLogFileURL = logURL
            defer { ClavisLogger.customLogFileURL = nil }
            ClavisLogger.log("TEST\nFORGED", "message\r\n[AUTH] forged")

            let contents = try String(contentsOf: logURL, encoding: .utf8)
            #expect(contents.split(separator: "\n").count == 1)
            #expect(contents.contains("TEST\\nFORGED"))
            #expect(contents.contains("message\\r\\n[AUTH] forged"))
        }
    }

    @Test func testLoggerMultiGenerationRotationAndPermissions() throws {
        try fixture.runSync {
            let logURL = testRootURL.appendingPathComponent("clavis.log")
            ClavisLogger.customLogFileURL = logURL
            defer {
                ClavisLogger.customLogFileURL = nil
                ClavisLogger.customMaximumLogFileSize = nil
            }
            ClavisLogger.customMaximumLogFileSize = 128

            for index in 0..<20 {
                ClavisLogger.log("TEST", "payload-\(index)-\(String(repeating: "a", count: 64))")
            }

            let fm = FileManager.default
            #expect(fm.fileExists(atPath: logURL.path))
            #expect(fm.fileExists(atPath: "\(logURL.path).1"))
            #expect(fm.fileExists(atPath: "\(logURL.path).2"))
            #expect(fm.fileExists(atPath: "\(logURL.path).3"))
            #expect(!fm.fileExists(atPath: "\(logURL.path).4"))

            for index in 1...3 {
                let path = "\(logURL.path).\(index)"
                let attrs = try fm.attributesOfItem(atPath: path)
                #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            }

            let rotatedList = ClavisLogger.rotatedLogFiles()
            #expect(rotatedList.count == 4)
        }
    }

    @Test func testLoggerRejectsSymlinkLogFiles() throws {
        try fixture.runSync {
            let logURL = testRootURL.appendingPathComponent("clavis.log")
            ClavisLogger.customLogFileURL = logURL
            defer { ClavisLogger.customLogFileURL = nil }

            let fakeTarget = testRootURL.appendingPathComponent("target-file.txt")
            try "initial target content\n".write(to: fakeTarget, atomically: true, encoding: .utf8)

            try FileManager.default.createSymbolicLink(at: logURL, withDestinationURL: fakeTarget)

            ClavisLogger.log("MALICIOUS", "malicious payload trying to overwrite target")

            let targetContent = try String(contentsOf: fakeTarget, encoding: .utf8)
            #expect(targetContent == "initial target content\n")

            try? FileManager.default.removeItem(at: logURL)
        }
    }

    @Test func testSingleInstanceLockAcquireAndRelease() {
        let tempURL = testRootURL.appendingPathComponent("clavis_test_\(UUID().uuidString).lock")
        SingleInstanceLock.customLockFileURL = tempURL
        defer {
            SingleInstanceLock.shared.release()
            SingleInstanceLock.customLockFileURL = nil
            try? FileManager.default.removeItem(at: tempURL)
        }

        let lock = SingleInstanceLock.shared
        lock.release()

        #expect(lock.acquire())
        #expect(lock.acquire())

        let fd = open(tempURL.path, O_RDWR)
        if fd >= 0 {
            let flockRes = flock(fd, LOCK_EX | LOCK_NB)
            #expect(flockRes == -1)
            #expect(errno == EWOULDBLOCK)
            close(fd)
        }

        lock.release()
        let fd2 = open(tempURL.path, O_RDWR)
        if fd2 >= 0 {
            let flockRes2 = flock(fd2, LOCK_EX | LOCK_NB)
            #expect(flockRes2 == 0)
            flock(fd2, LOCK_UN)
            close(fd2)
        }
    }

    @Test func testSingleInstanceLockGuiAndAgentConcurrency() throws {
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
        #expect(guiLock.acquire())
        #expect(agentLock.acquire())

        // lockOwnerPID should identify this process
        #expect(guiLock.lockOwnerPID == getpid())
        #expect(agentLock.lockOwnerPID == getpid())

        // A second instance trying to acquire the same file must fail
        let duplicateGuiLock = SingleInstanceLock(name: "test-gui-dup", bringToFrontOnConflict: false, customLockFileURL: guiURL)
        #expect(!duplicateGuiLock.acquire())

        // Release GUI lock; duplicate can now acquire
        guiLock.release()
        #expect(duplicateGuiLock.acquire())
        duplicateGuiLock.release()
    }

    @Test func testSingleInstanceLockStaleLockIgnored() throws {
        let staleURL = testRootURL.appendingPathComponent("test_stale_\(UUID().uuidString).lock")
        defer { try? FileManager.default.removeItem(at: staleURL) }

        // Write PID 1 (launchd, always running) to a file WITHOUT holding flock
        try "1\n".write(to: staleURL, atomically: true, encoding: .utf8)

        let staleLock = SingleInstanceLock(name: "test-stale", bringToFrontOnConflict: false, customLockFileURL: staleURL)

        // lockOwnerPID must return nil because flock is not held, despite PID 1 being alive
        #expect(staleLock.lockOwnerPID == nil)

        // acquire() must succeed and take over the stale lock file
        #expect(staleLock.acquire())
        #expect(staleLock.lockOwnerPID == getpid())
        staleLock.release()
    }

    @Test func testSSHAgentServerIsSocketListeningAndCollisionPrevention() throws {
        let testSockPath = testRootURL.appendingPathComponent("t-listen.sock").path

        // 1. Initial state: socket does not exist, isSocketListening must be false
        #expect(!SSHAgentServer.isSocketListening(atPath: testSockPath))

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
        #expect(listening, "Server should be actively listening on socket")

        // 3. Attempting to start a second server on the same socket must fail with socketAlreadyInUse
        let secondaryServer = SSHAgentServer(socketPath: testSockPath)
        #expect(throws: SSHAgentServerError.socketAlreadyInUse(testSockPath)) {
            try secondaryServer.start()
        }

        // 4. Primary server must remain active and listening despite the collision attempt
        #expect(SSHAgentServer.isSocketListening(atPath: testSockPath))

        // 5. Stopping primary server makes socket not listening
        primaryServer.stop()
        #expect(!SSHAgentServer.isSocketListening(atPath: testSockPath))
    }

    @Test func testAgentLifecycleManagerSocketDetection() throws {
        let testSockPath = testRootURL.appendingPathComponent("t-life.sock").path
        let manager = AgentLifecycleManager(socketPath: testSockPath)

        #expect(!manager.isAgentRunning)

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
        #expect(isRunning)

        server.stop()
        #expect(!manager.isAgentRunning)
    }

    @MainActor
    @Test func testAppStateInitializationAndDaemonFlag() {
        fixture.runSync {
            let appState = AppState(
                keyManager: makeKeyManager(),
                sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-state.sock").path)
            )
            #expect(appState.errorMessage == nil)

            // Test lockNow refreshes state
            appState.lockNow()

            // Test clearError
            appState.clearError()
            #expect(appState.errorMessage == nil)
        }
    }

    @MainActor
    @Test func testApplicationDelegateRunsShutdownExactlyOnceForAllTerminationCallbacks() {
        var shutdownCount = 0
        let delegate = ClavisApplicationDelegate {
            shutdownCount += 1
        }

        let reply = delegate.applicationShouldTerminate(NSApplication.shared)
        delegate.applicationWillTerminate(
            Notification(name: NSApplication.willTerminateNotification)
        )

        #expect(reply == .terminateNow)
        #expect(shutdownCount == 1)
    }

    @MainActor
    @Test func testAppTerminationClearsCachesStopsServerAndStopsAgent() throws {
        let socketPath = testRootURL.appendingPathComponent("termination.sock").path
        let server = SSHAgentServer(socketPath: socketPath)
        try server.start()

        var agentStopCount = 0
        let lifecycle = AgentLifecycleManager(socketPath: socketPath)
        let appState = AppState(
            keyManager: makeKeyManager(),
            sshAgentServer: server,
            agentLifecycle: lifecycle,
            terminationAgentStop: {
                agentStopCount += 1
                return true
            }
        )

        appState.shutdownForTermination()

        #expect(!server.isSocketActive)
        #expect(!FileManager.default.fileExists(atPath: socketPath))
        #expect(agentStopCount == 1)
        #expect(!appState.isSocketActive)
        #expect(appState.agentPID == nil)
    }

    @Test func testLaunchAgentPlistIsStructurallySafeForHostilePaths() throws {
        let hostile = "/tmp/a&b</string><key>RunAtLoad</key><false/>\"'\n<string>x/agent"
        let data = try LaunchAtLoginManager.launchAgentPlistData(executable: hostile)

        let parsed = try #require(
            PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        )
        #expect(parsed["Label"] as? String == LaunchAtLoginManager.launchAgentLabel)
        #expect(parsed["ProgramArguments"] as? [String] == [hostile, "--daemon"])
        #expect(parsed["RunAtLoad"] as? Bool == true, "Path content must not inject keys")
        #expect(Set(parsed.keys) == ["Label", "ProgramArguments", "RunAtLoad", "KeepAlive", "ProcessType"])
    }

    @Test func testLaunchAtLoginManager() throws {
        let tempPlistURL = FileManager.default.temporaryDirectory.appendingPathComponent("clavis_launch_\(UUID().uuidString).plist")
        LaunchAtLoginManager.customLaunchAgentURL = tempPlistURL
        defer {
            LaunchAtLoginManager.customLaunchAgentURL = nil
            try? FileManager.default.removeItem(at: tempPlistURL)
        }

        let testAgent = testRootURL.appendingPathComponent("clavis-agent")
        try "#!/bin/sh\nexit 0\n".write(to: testAgent, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: testAgent.path)
        setenv("CLAVIS_AGENT_EXECUTABLE", testAgent.path, 1)
        #if DEBUG
        AgentLifecycleManager.disableCodeSignatureCheckForTesting = true
        defer {
            AgentLifecycleManager.disableCodeSignatureCheckForTesting = false
            unsetenv("CLAVIS_AGENT_EXECUTABLE")
        }
        #endif

        let mgr = LaunchAtLoginManager.shared
        #expect(!mgr.isEnabled)

        mgr.setLaunchAtLogin(enabled: true)
        #expect(mgr.isEnabled)
        #expect(FileManager.default.fileExists(atPath: tempPlistURL.path))

        mgr.setLaunchAtLogin(enabled: false)
        #expect(!mgr.isEnabled)
        #expect(!FileManager.default.fileExists(atPath: tempPlistURL.path))
    }

    @Test func testAgentLifecycleCodeSignatureVerificationRejectsUnsignedOrMismatchedBinary() throws {
        let fakeBinary = testRootURL.appendingPathComponent("fake-agent")
        try "#!/bin/sh\necho fake\n".write(to: fakeBinary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeBinary.path)

        // Without disabling signature check, unsigned file must fail verification
        #if DEBUG
        AgentLifecycleManager.disableCodeSignatureCheckForTesting = false
        #endif
        #expect(!AgentLifecycleManager.verifyCodeSignature(of: fakeBinary))

        let lifecycle = AgentLifecycleManager()
        // Setting environment to unsigned binary should be rejected by locateAgentExecutable
        setenv("CLAVIS_AGENT_EXECUTABLE", fakeBinary.path, 1)
        defer { unsetenv("CLAVIS_AGENT_EXECUTABLE") }

        #expect(lifecycle.locateAgentExecutable() == nil)
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
        try #require(codesign.terminationStatus == 0, "codesign unavailable in this environment")
        return url
    }

    @Test func testCodeSignatureRejectsAdHocBinaryClaimingSharedIdentifierWhenRequirementExists() throws {
        let impostor = try makeAdHocSignedBinary(identifier: ClavisCodeTrust.sharedIdentifier)
        let requirement = try #require(ClavisCodeTrust.makeRequirement(teamIdentifier: "ABCDE12345"))

        // The identifier matches, but a team-pinned requirement exists: no downgrade is allowed,
        // even if the development fallback is enabled.
        #expect(!AgentLifecycleManager.verifyCodeSignature(
            of: impostor,
            requirement: requirement,
            allowIdentifierOnlyDevelopmentFallback: true
        ))
    }

    @Test func testCodeSignatureIdentifierOnlyFallbackIsDevelopmentOnly() throws {
        let impostor = try makeAdHocSignedBinary(identifier: ClavisCodeTrust.sharedIdentifier)
        let unrelated = try makeAdHocSignedBinary(identifier: "com.clavis.not-really")

        // Release semantics: unsigned/ad-hoc parent without a team identifier fails closed.
        #expect(!AgentLifecycleManager.verifyCodeSignature(
            of: impostor, requirement: nil, allowIdentifierOnlyDevelopmentFallback: false))

        // Development semantics: only the exact shared identifier is accepted (no prefix wildcards).
        #expect(AgentLifecycleManager.verifyCodeSignature(
            of: impostor, requirement: nil, allowIdentifierOnlyDevelopmentFallback: true))
        #expect(!AgentLifecycleManager.verifyCodeSignature(
            of: unrelated, requirement: nil, allowIdentifierOnlyDevelopmentFallback: true))
    }

    @Test func testCodeTrustRequirementRejectsMalformedTeamIdentifiers() {
        #expect(ClavisCodeTrust.makeRequirement(teamIdentifier: "ABCDE12345") != nil)
        for malformed in ["", "abcde12345", "ABCDE1234", "ABCDE123456", "ABCDE\" or true", "ABCDE1234\n"] {
            #expect(ClavisCodeTrust.makeRequirement(teamIdentifier: malformed) == nil, Comment(rawValue: malformed))
        }
    }

    @MainActor
    @Test func testAppStateIgnoresSpoofedGitGraceNotificationUserInfo() throws {
        let socketPath = testRootURL.appendingPathComponent("spoof.sock").path
        let server = SSHAgentServer(socketPath: socketPath)
        let lifecycle = AgentLifecycleManager(socketPath: socketPath)
        let appState = AppState(
            keyManager: makeKeyManager(),
            sshAgentServer: server,
            agentLifecycle: lifecycle
        )

        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        #expect(appState.activeGitGrace == nil)

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
        let deadline = Date().addingTimeInterval(0.05)
        while Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.005))
        }

        // AppState must verify against authoritative state and reject the forged notification
        #expect(appState.activeGitGrace == nil, "AppState must not adopt spoofed userInfo from unauthenticated distributed notifications")
    }

    @Test @MainActor
    func testAppTerminationPromptCancelsShutdownWhenActiveWindowsPresent() {
        var shutdownCalled = false
        let delegate = ClavisApplicationDelegate(
            activeWindowsCheck: { true },
            confirmationPrompt: { false }, // user pressed Cancel
            shutdownHandler: { shutdownCalled = true }
        )

        let reply = delegate.applicationShouldTerminate(NSApplication.shared)
        #expect(reply == .terminateCancel)
        #expect(!shutdownCalled)
    }

    @Test @MainActor
    func testAppTerminationProceedsWhenConfirmedWithActiveWindows() {
        var shutdownCalled = false
        let delegate = ClavisApplicationDelegate(
            activeWindowsCheck: { true },
            confirmationPrompt: { true }, // user pressed Quit
            shutdownHandler: { shutdownCalled = true }
        )

        let reply = delegate.applicationShouldTerminate(NSApplication.shared)
        #expect(reply == .terminateNow)
        #expect(shutdownCalled)
    }

    @Test @MainActor
    func testAppTerminationProceedsImmediatelyWithoutPromptWhenNoActiveWindows() {
        var shutdownCalled = false
        var promptCalled = false
        let delegate = ClavisApplicationDelegate(
            activeWindowsCheck: { false },
            confirmationPrompt: { promptCalled = true; return false },
            shutdownHandler: { shutdownCalled = true }
        )

        let reply = delegate.applicationShouldTerminate(NSApplication.shared)
        #expect(reply == .terminateNow)
        #expect(!promptCalled)
        #expect(shutdownCalled)
    }

    @Test @MainActor
    func testWindowManagerHasActiveWindowsTracking() {
        let wm = WindowManager()
        #expect(!wm.hasActiveWindows)

        let testWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 200),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        testWindow.isReleasedWhenClosed = false
        testWindow.makeKeyAndOrderFront(nil)
        defer { testWindow.orderOut(nil) }

        wm.keyManagerWindow = testWindow
        #expect(wm.hasActiveWindows)

        wm.keyManagerWindow = nil
        #expect(!wm.hasActiveWindows)

        wm.settingsWindow = testWindow
        #expect(wm.hasActiveWindows)

        wm.settingsWindow = nil
        #expect(!wm.hasActiveWindows)

        wm.historyWindow = testWindow
        #expect(wm.hasActiveWindows)

        wm.historyWindow = nil
        #expect(!wm.hasActiveWindows)
    }

    @Test @MainActor
    func testWindowManagerCloseActiveWindow() {
        let wm = WindowManager()
        let testWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 200),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        testWindow.isReleasedWhenClosed = false
        wm.keyManagerWindow = testWindow
        testWindow.makeKeyAndOrderFront(nil)
        defer { testWindow.orderOut(nil) }
        #expect(testWindow.isVisible)

        wm.closeActiveWindow()
        #expect(!testWindow.isVisible)
    }
}
