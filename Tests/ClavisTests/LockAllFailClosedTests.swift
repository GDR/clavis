import Foundation
import Testing
import Darwin
@testable import ClavisCore
@testable import Clavis

@Suite
final class LockAllFailClosedTests {

    enum StubBehavior {
        case replyFailure
        case neverReply
        case closeImmediately
        case replySuccess
    }

    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }

    init() throws {
        signal(SIGPIPE, SIG_IGN)
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

    final class StubAgentServer: @unchecked Sendable {
        let socketPath: String
        private let lock = NSLock()
        private var _listeningFd: Int32 = -1
        private let behavior: StubBehavior
        private var workerThread: Thread?
        private var _isRunning = true

        private var isRunning: Bool {
            get {
                lock.lock()
                defer { lock.unlock() }
                return _isRunning
            }
            set {
                lock.lock()
                defer { lock.unlock() }
                _isRunning = newValue
            }
        }

        init(socketPath: String, behavior: StubBehavior) throws {
            self.socketPath = socketPath
            self.behavior = behavior

            unlink(socketPath)
            let listeningFd = socket(AF_UNIX, SOCK_STREAM, 0)
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

            lock.lock()
            self._listeningFd = listeningFd
            lock.unlock()

            let thread = Thread { [weak self] in
                self?.runLoop()
            }
            self.workerThread = thread
            thread.start()
        }

        private func runLoop() {
            while isRunning {
                lock.lock()
                let fd = _listeningFd
                lock.unlock()
                guard fd >= 0 else { break }

                let clientFd = accept(fd, nil, nil)
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
            lock.lock()
            let fd = _listeningFd
            _listeningFd = -1
            lock.unlock()
            if fd >= 0 {
                close(fd)
            }
            unlink(socketPath)
        }

        deinit {
            stop()
        }
    }

    @Test func testSendLockAllThrowsOnFailureReply() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        #expect {
            try manager.sendLockAllToAgent()
        } throws: { error in
            guard let lifecycleError = error as? AgentLifecycleError,
                  case .agentControlFailed = lifecycleError else {
                return false
            }
            return true
        }
    }

    @Test func testSendLockAllThrowsOnImmediateClose() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-close.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .closeImmediately)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        #expect(throws: (any Error).self) {
            try manager.sendLockAllToAgent()
        }
    }

    @Test func testSendLockAllSucceedsOnSuccessReply() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-success.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        #expect(throws: Never.self) {
            try manager.sendLockAllToAgent()
        }
    }

    @Test func testSendLockAllThrowsOnNeverReplyWithinTimeout() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-never.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .neverReply)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            isTrustedServerPeer: { _ in true },
            controlTimeout: 0.15
        )
        let start = Date()
        #expect(throws: (any Error).self) {
            try manager.sendLockAllToAgent()
        }
        let elapsed = Date().timeIntervalSince(start)
        #expect(elapsed >= 0.12, "Should respect socket receive timeout")
        #expect(elapsed < 1.5, "Should timeout without hanging indefinitely")
    }

    @Test func testCLIServiceLockFailsClosedWhenAgentRejects() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-cli-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        let result = CLIService.handle(args: ["clavis", "lock"], agentLifecycle: manager)
        #expect(result?.exitCode == 1)
        #expect(result?.error != nil)
        #expect(result?.error?.contains("Lock failed:") == true)
        #expect(result?.error?.contains("Failed to revoke the SSH agent grant") == false)
        #expect(result?.error?.contains("Failed to control SSH agent: agent rejected lock-all") == true)
    }

    @Test func testCLIServiceLockSucceedsWhenAgentConfirms() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-cli-ok.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        let result = CLIService.handle(args: ["clavis", "lock"], agentLifecycle: manager)
        #expect(result?.exitCode == 0)
        #expect(result?.output == CLIMessages.lockedAll)
    }

    @MainActor
    @Test func testAppStateEndGitSigningSessionFailsClosedWhenAgentRejects() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        let appState = AppState(
            keyManager: makeKeyManager(),
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-fail.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.endGitSigningSession()

        #expect(appState.errorMessage != nil, "Error message must be set when agent rejects lock-all")
        #expect(appState.activeGitGrace != nil, "activeGitGrace must NOT be cleared when lock-all fails")
    }

    @Test func testSendLockAllThrowsOnMissingSocketWithOrphanProcess() throws {
        let sockPath = testRootURL.appendingPathComponent("nonexistent.sock").path
        unlink(sockPath)

        let manager = AgentLifecycleManager(
            socketPath: sockPath,
            agentPIDProvider: { 99999 },
            processNameProvider: { _ in "clavis-agent" }
        )
        #expect {
            try manager.sendLockAllToAgent()
        } throws: { error in
            guard let lifecycleError = error as? AgentLifecycleError,
                  case .agentControlFailed = lifecycleError else {
                return false
            }
            return true
        }
    }

    @MainActor
    @Test func testAppStateEndGitSigningSessionSucceedsWhenAgentConfirms() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-ok.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replySuccess)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        let appState = AppState(
            keyManager: makeKeyManager(),
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-ok.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.endGitSigningSession()

        #expect(appState.errorMessage == nil)
        #expect(appState.activeGitGrace == nil, "activeGitGrace must be cleared on success")
    }

    @MainActor
    @Test func testAppStateLockNowPreservesErrorMessageOnFailure() throws {
        let sockPath = testRootURL.appendingPathComponent("stub-appstate-locknow-fail.sock").path
        let stub = try StubAgentServer(socketPath: sockPath, behavior: .replyFailure)
        defer { stub.stop() }

        let manager = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })
        let appState = AppState(
            keyManager: makeKeyManager(),
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-srv-locknow-fail.sock").path),
            agentLifecycle: manager
        )

        appState.activeGitGrace = ActiveGitGraceInfo(keyLabel: "test-key", remainingSeconds: 300, remainingOperations: 10)
        appState.lockNow()

        #expect(appState.errorMessage != nil, "Error message must be preserved when lockNow fails")
    }

    @Test func testAgentControlFailedErrorDescriptionDoesNotMentionRevoke() {
        let err = AgentLifecycleError.agentControlFailed("agent rejected lock-all")
        #expect(err.errorDescription == "Failed to control SSH agent: agent rejected lock-all")
        #expect(err.errorDescription?.contains("revoke") == false)
    }
}
