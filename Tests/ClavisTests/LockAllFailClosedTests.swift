import XCTest
import Darwin
@testable import ClavisCore
@testable import Clavis

final class LockAllFailClosedTests: ClavisBaseTestCase {

    enum StubBehavior {
        case replyFailure
        case neverReply
        case closeImmediately
        case replySuccess
    }

    override func setUpWithError() throws {
        try super.setUpWithError()
        signal(SIGPIPE, SIG_IGN)
    }

    final class StubAgentServer {
        let socketPath: String
        private var listeningFd: Int32 = -1
        private let behavior: StubBehavior
        private var workerThread: Thread?
        private var isRunning = true

        init(socketPath: String, behavior: StubBehavior) throws {
            self.socketPath = socketPath
            self.behavior = behavior

            unlink(socketPath)
            listeningFd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard listeningFd >= 0 else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            var nosigpipe: Int32 = 1
            setsockopt(listeningFd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout<Int32>.size))

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = socketPath.utf8CString
            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                for (i, b) in pathBytes.enumerated() { raw[i] = b }
            }
            let len = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
            guard Darwin.bind(listeningFd, withUnsafePointer(to: &addr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1, { $0 }) }), len) == 0 else {
                let err = errno
                close(listeningFd)
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
            }
            guard Darwin.listen(listeningFd, 5) == 0 else {
                let err = errno
                close(listeningFd)
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(err))
            }

            let thread = Thread { [weak self] in
                self?.runLoop()
            }
            self.workerThread = thread
            thread.start()
        }

        private func runLoop() {
            while isRunning {
                let clientFd = accept(listeningFd, nil, nil)
                guard clientFd >= 0 else { break }
                var nosigpipe: Int32 = 1
                setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout<Int32>.size))

                switch behavior {
                case .replyFailure:
                    var buf = [UInt8](repeating: 0, count: 5)
                    _ = read(clientFd, &buf, buf.count)
                    var response: [UInt8] = [0, 0, 0, 1, 5] // SSH_AGENT_FAILURE
                    _ = write(clientFd, &response, response.count)
                    close(clientFd)

                case .neverReply:
                    var buf = [UInt8](repeating: 0, count: 5)
                    _ = read(clientFd, &buf, buf.count)
                    while isRunning {
                        Thread.sleep(forTimeInterval: 0.05)
                    }
                    close(clientFd)

                case .closeImmediately:
                    close(clientFd)

                case .replySuccess:
                    var buf = [UInt8](repeating: 0, count: 5)
                    _ = read(clientFd, &buf, buf.count)
                    var response: [UInt8] = [0, 0, 0, 1, 6] // SSH_AGENT_SUCCESS
                    _ = write(clientFd, &response, response.count)
                    close(clientFd)
                }
            }
        }

        func stop() {
            isRunning = false
            if listeningFd >= 0 {
                close(listeningFd)
                listeningFd = -1
            }
            unlink(socketPath)
        }

        deinit {
            stop()
        }
    }

    func testSendLockAllThrowsOnFailureReply() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        XCTAssertThrowsError(try manager.sendLockAllToAgent()) { error in
            guard let lifecycleError = error as? AgentLifecycleError else {
                XCTFail("Expected AgentLifecycleError, got \(error)")
                return
            }
            if case .agentControlFailed = lifecycleError {} else {
                XCTFail("Expected agentControlFailed, got \(lifecycleError)")
            }
        }
    }

    func testSendLockAllThrowsOnImmediateClose() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-close.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .closeImmediately)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        XCTAssertThrowsError(try manager.sendLockAllToAgent())
    }

    func testSendLockAllSucceedsOnSuccessReply() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-success.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        XCTAssertNoThrow(try manager.sendLockAllToAgent())
    }

    func testSendLockAllThrowsOnNeverReplyWithinTimeout() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-never.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .neverReply)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        let start = Date()
        XCTAssertThrowsError(try manager.sendLockAllToAgent())
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertGreaterThanOrEqual(elapsed, 2.8, "Should respect socket receive timeout")
        XCTAssertLessThan(elapsed, 5.0, "Should timeout without hanging indefinitely")
    }

    func testCLIServiceLockFailsClosedWhenAgentRejects() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-cli-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        let result = CLIService.handle(args: ["clavis", "lock"], agentLifecycle: manager)
        XCTAssertEqual(result?.exitCode, 1)
        XCTAssertNotNil(result?.error)
        XCTAssertTrue(result?.error?.contains("Lock failed:") == true)
    }

    func testCLIServiceLockSucceedsWhenAgentConfirms() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-cli-ok.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath)
        let result = CLIService.handle(args: ["clavis", "lock"], agentLifecycle: manager)
        XCTAssertEqual(result?.exitCode, 0)
        XCTAssertEqual(result?.output, CLIMessages.lockedAll)
    }

    @MainActor
    func testAppStateEndGitSigningSessionFailsClosedWhenAgentRejects() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let cache = makeSessionCache()
        let manager = AgentLifecycleManager(socketPath: sockPath)
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: cache),
            sessionCache: cache,
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-fail.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.endGitSigningSession()

        XCTAssertNotNil(appState.errorMessage, "Error message must be set when agent rejects lock-all")
        XCTAssertNotNil(appState.activeGitGrace, "activeGitGrace must NOT be cleared when lock-all fails")
    }

    func testSendLockAllThrowsOnMissingSocketWithOrphanProcess() throws {
        let sockPath = testRootURL.appendingPathComponent("nonexistent.sock").path
        unlink(sockPath)

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" }
        )
        XCTAssertThrowsError(try manager.sendLockAllToAgent()) { error in
            guard let lifecycleError = error as? AgentLifecycleError else {
                XCTFail("Expected AgentLifecycleError, got \(error)")
                return
            }
            if case .agentControlFailed = lifecycleError {} else {
                XCTFail("Expected agentControlFailed, got \(lifecycleError)")
            }
        }
    }

    @MainActor
    func testAppStateEndGitSigningSessionSucceedsWhenAgentConfirms() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-ok.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let cache = makeSessionCache()
        let manager = AgentLifecycleManager(socketPath: sockPath)
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: cache),
            sessionCache: cache,
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-ok.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.endGitSigningSession()

        XCTAssertNil(appState.errorMessage)
        XCTAssertNil(appState.activeGitGrace, "activeGitGrace must be cleared on success")
    }

    @MainActor
    func testAppStateLockNowPreservesErrorMessageOnFailure() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-locknow-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let cache = makeSessionCache()
        let manager = AgentLifecycleManager(socketPath: sockPath)
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: cache),
            sessionCache: cache,
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-locknow-fail.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.lockNow()

        XCTAssertNotNil(appState.errorMessage, "Error message must be preserved when lockNow fails")
    }
}

