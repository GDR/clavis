import Testing
import CryptoKit
import Foundation
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("SigningPolicyEvaluatorTests")
final class SigningPolicyEvaluatorTests {

    private let fixture: ClavisTestFixture
    private let recorder: InMemoryAuditRecorder
    private let keyManager: KeychainManager
    private let evaluator: SigningPolicyEvaluator
    private let graceManager: GitSigningGraceManager

    init() throws {
        let fixture = try ClavisTestFixture()
        let recorder = InMemoryAuditRecorder()
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)
        let keyManager = fixture.makeKeyManager(
            authenticator: AllowingAuthenticator(),
            gitSigningGraceManager: graceManager
        )
        let evaluator = SigningPolicyEvaluator(applicationAccess: TestApplicationAccess(),
            keyManager: keyManager,
            gitSigningGraceManager: graceManager,
            auditRecorder: recorder,
            peerProcessValidator: { _, _, _ in true }
        )
        self.fixture = fixture
        self.recorder = recorder
        self.graceManager = graceManager
        self.keyManager = keyManager
        self.evaluator = evaluator
    }

    deinit {
        fixture.cleanup()
    }


    @Test
    func test_evaluateSigningRequest_malformedFlags() async throws {
        try await fixture.run {
            let keyInfo = try keyManager.generateKey(label: "flags-key")
            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: Data("test-data".utf8),
                flags: 1, // Non-zero flags are invalid in SSH agent wire protocol
                role: .personal,
                clientPid: getpid()
            )

            #expect(decision == .denied)
            #expect(recorder.events.count == 1)
            #expect(recorder.events.last?.result == .denied)
            #expect(recorder.events.last?.reason == .malformedRequest)
        }
    }

    @Test
    func test_evaluateSigningRequest_unknownKey() async throws {
        try await fixture.run {
            let unknownKeyBlob = Data([0xDE, 0xAD, 0xBE, 0xEF])
            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: unknownKeyBlob,
                dataToSign: Data("test-data".utf8),
                flags: 0,
                role: .personal,
                clientPid: getpid()
            )

            #expect(decision == .denied)
            #expect(recorder.events.count == 1)
            #expect(recorder.events.last?.result == .denied)
            #expect(recorder.events.last?.reason == .unknownKey)
        }
    }

    @Test
    func test_evaluateSigningRequest_agentSocket_refusesForwarding() async throws {
        try await fixture.run {
            let keyInfo = try keyManager.generateKey(label: "agent-key", keyPurpose: .agent)
            let connection = AgentConnectionState()

            let priv = Curve25519.Signing.PrivateKey()
            let sessionID = Data("test-session".utf8)
            var hostKeyBlob = Data()
            hostKeyBlob.appendWireString("ssh-ed25519")
            hostKeyBlob.appendWireData(priv.publicKey.rawRepresentation)

            let sigRaw = try priv.signature(for: sessionID)
            var sigBlob = Data()
            sigBlob.appendWireString("ssh-ed25519")
            sigBlob.appendWireData(sigRaw)

            let binding = SessionBinding(hostKeyBlob: hostKeyBlob, sessionID: sessionID, isForwarding: true)
            #expect(connection.bind(binding, signature: sigBlob))
            #expect(connection.hasForwarding)

            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: Data("test-data".utf8),
                flags: 0,
                role: .agent,
                clientPid: getpid(),
                connection: connection
            )

            #expect(decision == .denied)
            #expect(recorder.events.last?.reason == .forwardingRefused)
        }
    }

    @Test
    func test_evaluateSigningRequest_agentKey_refusesSSHSIG() async throws {
        try await fixture.run {
            let keyInfo = try keyManager.generateKey(label: "agent-sshsig-key", keyPurpose: .agent)
            let validGitPayload = SSHSIGPayload(
                namespace: "git",
                hashAlgorithm: "sha256",
                messageHash: Data(repeating: 0x42, count: 32)
            ).serialize()

            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: validGitPayload,
                flags: 0,
                role: .agent,
                clientPid: getpid()
            )

            #expect(decision == .denied)
            #expect(recorder.events.last?.reason == .wrongKeyKind)
        }
    }

    @Test
    func test_evaluateSigningRequest_gitSigningOnlyKey_refusesNonGitPayload() async throws {
        try await fixture.run {
            let keyInfo = try keyManager.generateKey(label: "git-only-key", keyPurpose: .gitSigningOnly)
            let nonGitPayload = Data("plain ssh login challenge".utf8)

            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: nonGitPayload,
                flags: 0,
                role: .personal,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/git"
            )

            #expect(decision == .denied)
            #expect(recorder.events.last?.reason == .gitOnlyKeyNonGitPayload)
        }
    }

    @Test
    func test_evaluateSigningRequest_personalSocket_gitGraceFastPath() async throws {
        try await fixture.run {
            let keyInfo = try keyManager.generateKey(label: "grace-fastpath-key", keyPurpose: .general)
            let validGitPayload = SSHSIGPayload(
                namespace: "git",
                hashAlgorithm: "sha256",
                messageHash: Data(repeating: 0x77, count: 32)
            ).serialize()

            let pid = getpid()
            let realStart = ProcessInspector.processStartTime(pid: pid) ?? 0
            let realPath = ProcessInspector.getProcessPath(pid: pid)
            let clientIdentity = ProcessInspector.resolveClientIdentity(pid: pid, processPath: realPath ?? "/usr/bin/git")
            let anchor = GitApprovedProcess(pid: pid, startTime: realStart, path: realPath)

            // Pre-authorize a 5-minute Git grant
            _ = try keyManager.authorizeGitSigningGrant(
                key: keyInfo,
                prompt: "Authorize",
                clientIdentity: clientIdentity,
                duration: 300.0,
                maxOperations: 200,
                approvedProcess: anchor
            )

            let decision = try evaluator.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: validGitPayload,
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: realPath,
                clientStartTime: realStart
            )

            if case .approved(let sig) = decision {
                #expect(!sig.isEmpty)
            } else {
                Issue.record("Expected approved signature from active Git grant")
            }
            #expect(recorder.events.last?.result == .allowed)
            #expect(recorder.events.last?.reason == .viaGitGrant)
        }
    }

    @Test
    func test_staticReasonStringGenerators() {
        let authReason = SigningPolicyEvaluator.sshAuthenticationReason(keyLabel: "MyKey", requester: "/usr/bin/ssh (PID 123)")
        #expect(authReason.contains("MyKey"))
        #expect(authReason.contains("PID 123"))

        let gitReason = SigningPolicyEvaluator.gitCommitSigningReason(keyLabel: "GitKey", requester: "/usr/bin/git (PID 456)")
        #expect(gitReason.contains("GitKey"))
        #expect(gitReason.contains("PID 456"))

        let sessionReason = SigningPolicyEvaluator.gitSigningSessionReason(keyLabel: "GitKey")
        #expect(sessionReason.contains("GitKey"))

        let desc = SigningPolicyEvaluator.requesterDescription(processPath: "/usr/bin/ssh", pid: 789)
        #expect(desc == "/usr/bin/ssh (PID 789)")

        let safePath = SigningPolicyEvaluator.safeProcessPath("hello\u{0000}world")
        #expect(safePath == "hello?world")
    }

    @Test
    func test_F6_requesterDescriptionMiddleTruncatesAndCollapsesWhitespace() {
        let spoofAttempt = "/Users/attacker/payload" + String(repeating: " ", count: 75) + "/usr/bin/ssh"
        let collapsedDesc = SigningPolicyEvaluator.requesterDescription(processPath: spoofAttempt, pid: 321)
        #expect(collapsedDesc == "/Users/attacker/payload /usr/bin/ssh (PID 321)")

        let longSpoofAttempt = "/Users/attacker/deeply/nested/directory/structure/that/exceeds/eighty/characters/easily/usr/bin/ssh"
        let truncatedDesc = SigningPolicyEvaluator.requesterDescription(processPath: longSpoofAttempt, pid: 654)
        #expect(truncatedDesc.hasPrefix("/Users/attacker/deeply/nested/di"), "Must preserve leading /Users/... prefix")
        #expect(truncatedDesc.contains("…"), "Must middle-truncate with ellipsis")
        #expect(truncatedDesc.hasSuffix("/usr/bin/ssh (PID 654)"), "Must preserve trailing binary path and PID")
        #expect(truncatedDesc.count == 80 + " (PID 654)".count)
    }

    @Test
    func test_F6_processInspectorValidatesNixStorePathsAndPermissions() throws {
        defer { fixture.cleanup() }
        // Malformed /nix/store paths must be rejected
        #expect(!ProcessInspector.isTrustedSshBinary(path: "/nix/store/evil/sub/bin/ssh"))
        #expect(!ProcessInspector.isTrustedSshBinary(path: "/nix/store/evil/bin/ssh"))
        #expect(!ProcessInspector.isTrustedSshBinary(path: "/nix/store/../../tmp/bin/ssh"))
        #expect(!ProcessInspector.isTrustedGitExecutable(path: "/nix/store/evil/sub/bin/git"))
        #expect(!ProcessInspector.isTrustedGitExecutable(path: "/nix/store/0123456789abcdef0123456789abcdef-git/sub/bin/git"))
        #expect(!ProcessInspector.isTrustedSshKeygen(path: "/nix/store/evil/sub/bin/ssh-keygen"))

        // Valid /nix/store/<32-char-hash>-<name>/bin/<binary> paths must be accepted
        let validHash = "0123456789abcdef0123456789abcdef"
        #expect(ProcessInspector.isTrustedSshBinary(path: "/nix/store/\(validHash)-openssh-9.8p1/bin/ssh"))
        #expect(ProcessInspector.isTrustedGitExecutable(path: "/nix/store/\(validHash)-git-2.44.0/bin/git"))
        #expect(ProcessInspector.isTrustedSshKeygen(path: "/nix/store/\(validHash)-openssh-9.8p1/bin/ssh-keygen"))

        // On-disk permission checks (reject group/world-writable binaries)
        let fakeStoreRoot = fixture.testRootURL.appendingPathComponent("nix-store")
        let entryDir = fakeStoreRoot.appendingPathComponent("\(validHash)-openssh-9.8p1/bin")
        try FileManager.default.createDirectory(at: entryDir, withIntermediateDirectories: true)
        let binURL = entryDir.appendingPathComponent("ssh")
        try Data("#!/bin/sh\n".utf8).write(to: binURL)

        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binURL.path)
        #expect(
            ProcessInspector.isValidNixStoreBinary(
                standardizedPath: binURL.path,
                binaryName: "ssh",
                storeRoot: fakeStoreRoot.path
            )
        )

        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: binURL.path)
        #expect(
            !ProcessInspector.isValidNixStoreBinary(
                standardizedPath: binURL.path,
                binaryName: "ssh",
                storeRoot: fakeStoreRoot.path
            ),
            "World-writable binary in Nix store must be rejected"
        )
    }

    // MARK: - SigningPromptAuthenticating Seam Tests

    private final class MockSigningPromptPresenter: SigningPromptAuthenticating, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var requests: [SigningAuthenticationRequest] = []
        private(set) var issuedContexts: [TrackableLAContext] = []
        var nextScope: KeyGracePeriod = .always
        var errorToThrow: Error?

        func authenticateSigningRequest(_ request: SigningAuthenticationRequest) throws -> SigningAuthenticationOutcome {
            lock.lock()
            requests.append(request)
            let err = errorToThrow
            let scope = nextScope
            lock.unlock()
            if let err {
                throw err
            }
            let ctx = TrackableLAContext()
            lock.lock()
            issuedContexts.append(ctx)
            lock.unlock()
            return SigningAuthenticationOutcome(context: ctx, selectedScope: scope)
        }
    }

    private struct UncertainApplicationAccess: ApplicationRequestAuthorizing {
        private let revision = UUID()
        func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease {
            .init(eligibility: .authenticatedOnceOnly, revision: revision, caller: nil)
        }
        func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool { true }
    }

    @Test
    func test_signingPromptPresenter_authenticatedOnceOnly_usesPresenterAndSkipsFallback() async throws {
        try await fixture.run {
            let fallbackAuth = CountingAuthenticator()
            let keyMgr = fixture.makeKeyManager(authenticator: fallbackAuth, gitSigningGraceManager: graceManager)
            let presenter = MockSigningPromptPresenter()
            let uncertainEval = SigningPolicyEvaluator(
                applicationAccess: UncertainApplicationAccess(),
                keyManager: keyMgr,
                gitSigningGraceManager: graceManager,
                auditRecorder: recorder,
                authenticator: fallbackAuth,
                signingPromptPresenter: presenter,
                peerProcessValidator: { _, _, _ in true }
            )
            let keyInfo = try keyMgr.generateKey(label: "github-ssh-key")
            let pid = getpid()
            let start = ProcessInspector.processStartTime(pid: pid) ?? 0
            let decision = try uncertainEval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: Data("ssh-userauth-challenge".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )

            guard case .approved(let sig) = decision else {
                Issue.record("Expected approved SSH signature via SigningPromptAuthenticating")
                return
            }
            #expect(!sig.isEmpty)
            #expect(fallbackAuth.authenticationCount == 0, "Fallback system modal must not run when presenter is wired")
            #expect(presenter.requests.count == 1)
            #expect(presenter.requests.first?.isUncertainCaller == true)
            #expect(presenter.requests.first?.allowsSessionScope == true)
            #expect(presenter.requests.first?.defaultScope == .fifteenMinutes)
            #expect(presenter.requests.first?.operation == .ssh)
            #expect(presenter.requests.first?.operationLabel == "Authenticate with SSH")
            #expect(presenter.requests.first?.peerPath == "/usr/bin/ssh")
            #expect(presenter.issuedContexts.first?.isInvalidated == true)
            #expect(graceManager.allActivePersonalGrants().isEmpty)
        }
    }

    @Test
    func test_signingPromptPresenter_eligibleSSHAndGitBurst_singlePromptAndCancelHandling() async throws {
        try await fixture.run {
            let fallbackAuth = CountingAuthenticator()
            let keyMgr = fixture.makeKeyManager(authenticator: fallbackAuth, gitSigningGraceManager: graceManager)
            let presenter = MockSigningPromptPresenter()
            let eval = SigningPolicyEvaluator(
                applicationAccess: TestApplicationAccess(),
                keyManager: keyMgr,
                gitSigningGraceManager: graceManager,
                auditRecorder: recorder,
                authenticator: fallbackAuth,
                signingPromptPresenter: presenter,
                peerProcessValidator: { _, _, _ in true }
            )
            let keyInfo = try keyMgr.generateKey(label: "eligible-presenter-key")
            let pid = getpid()
            let realPath = ProcessInspector.getProcessPath(pid: pid) ?? "/usr/bin/git"
            let start = ProcessInspector.processStartTime(pid: pid) ?? 0

            // 1. Eligible SSH request
            let sshDecision = try eval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: Data("ssh-auth".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            guard case .approved = sshDecision else {
                Issue.record("Expected approved eligible SSH request")
                return
            }
            #expect(presenter.requests.count == 1)
            #expect(presenter.requests.last?.allowsSessionScope == false)
            #expect(presenter.requests.last?.operation == .ssh)

            // 2. Git commit #1 -> single-shot prompt
            let gitPayload = SSHSIGPayload(
                namespace: "git",
                hashAlgorithm: "sha256",
                messageHash: Data(repeating: 0x22, count: 32)
            ).serialize()
            let commit1 = try eval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: gitPayload,
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: realPath,
                clientStartTime: start
            )
            guard case .approved = commit1 else {
                Issue.record("Expected approved Git commit #1")
                return
            }
            #expect(presenter.requests.count == 2)
            #expect(presenter.requests.last?.allowsSessionScope == false)
            #expect(presenter.requests.last?.operationLabel == "Sign a Git commit")

            // 3. Git commit #2 within 30s -> unified 1-step session prompt creates grant without second auth
            presenter.nextScope = .fifteenMinutes
            let commit2 = try eval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: gitPayload,
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: realPath,
                clientStartTime: start
            )
            guard case .approved = commit2 else {
                Issue.record("Expected approved Git commit #2 with 15-min grant")
                return
            }
            #expect(presenter.requests.count == 3)
            #expect(presenter.requests.last?.allowsSessionScope == true)
            #expect(fallbackAuth.authenticationCount == 0)

            // 4. Git commit #3 uses active grant with 0 extra prompts
            let commit3 = try eval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: gitPayload,
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: realPath,
                clientStartTime: start
            )
            guard case .approved = commit3 else {
                Issue.record("Expected approved Git commit #3 via active grant")
                return
            }
            #expect(presenter.requests.count == 3, "Commit #3 must reuse the active Git grant without prompting")
            #expect(recorder.events.last?.reason == .viaGitGrant)

            // 5. User cancellation maps to .denied and .cancelled audit result
            presenter.errorToThrow = UserAuthenticationError.rejected(LAError(.userCancel))
            let cancelled = try eval.evaluateSigningRequest(
                keyBlob: keyInfo.publicKeyBlob,
                dataToSign: Data("ssh-cancel".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            #expect(cancelled == .denied)
            #expect(recorder.events.last?.result == .cancelled)
            #expect(recorder.events.last?.reason == .userCancelled)
            #expect(fallbackAuth.authenticationCount == 0)
        }
    }

    private final class VerifiedCallerAccess: ApplicationRequestAuthorizing, @unchecked Sendable {
        private let revision = UUID()
        func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease {
            guard key.effectiveAccessProfile.capabilities.permits(operation),
                  role == .personal || key.effectiveAccessProfile.type == .bot else {
                return .init(eligibility: .denied, revision: revision, caller: nil)
            }
            let identity = try ApplicationIdentity(kind: .designatedRequirement, value: "identifier \"\(path)\"")
            let app = RegisteredApplication(identity: identity, name: path, path: path, classification: .personal)
            let caller = VerifiedApplicationCaller(identity: identity, application: app, pid: pid, startTime: start, path: path)
            return .init(eligibility: .eligible(.personal), revision: revision, caller: caller)
        }
        func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool { true }
    }

    @Test
    func test_unlockedTimeoutOnceNeverEscalatesGitOrCachesSSH() async throws {
        try await fixture.run {
            let fallbackAuth = CountingAuthenticator()
            let keyMgr = fixture.makeKeyManager(authenticator: fallbackAuth, gitSigningGraceManager: graceManager)
            let presenter = MockSigningPromptPresenter()
            presenter.nextScope = .fifteenMinutes
            let eval = SigningPolicyEvaluator(
                applicationAccess: VerifiedCallerAccess(),
                keyManager: keyMgr,
                gitSigningGraceManager: graceManager,
                auditRecorder: recorder,
                authenticator: fallbackAuth,
                signingPromptPresenter: presenter,
                peerProcessValidator: { _, _, _ in true }
            )
            let key = try keyMgr.generateKey(label: "once-key", unlockedTimeout: .always)
            let pid = getpid()
            let realPath = ProcessInspector.getProcessPath(pid: pid) ?? "/usr/bin/git"
            let start = ProcessInspector.processStartTime(pid: pid) ?? 0
            let gitPayload = SSHSIGPayload(
                namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x33, count: 32)
            ).serialize()

            for _ in 0..<2 {
                let gitDecision = try eval.evaluateSigningRequest(
                    keyBlob: key.publicKeyBlob, dataToSign: gitPayload, flags: 0,
                    role: .personal, clientPid: pid, clientExecutablePath: realPath, clientStartTime: start
                )
                guard case .approved = gitDecision else { Issue.record("Expected Git approval"); return }
            }
            #expect(presenter.requests.count == 2)
            #expect(presenter.requests.allSatisfy { $0.allowsSessionScope == false && $0.defaultScope == .always })
            #expect(graceManager.getValidGrant(for: key.label) == nil)

            for _ in 0..<2 {
                let sshDecision = try eval.evaluateSigningRequest(
                    keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                    role: .personal, clientPid: pid, clientExecutablePath: "/Applications/TermA.app/ssh", clientStartTime: start
                )
                guard case .approved = sshDecision else { Issue.record("Expected SSH approval"); return }
            }
            #expect(presenter.requests.count == 4)
            #expect(graceManager.allActivePersonalGrants().isEmpty)
        }
    }

    @Test
    func test_unlockedTimeoutCachesPerAppSSHAndPropagatesGitDefaultScopeAndRevokesOnLock() async throws {
        try await fixture.run {
            let fallbackAuth = CountingAuthenticator()
            let keyMgr = fixture.makeKeyManager(authenticator: fallbackAuth, gitSigningGraceManager: graceManager)
            let presenter = MockSigningPromptPresenter()
            presenter.nextScope = .untilLock
            let eval = SigningPolicyEvaluator(
                applicationAccess: VerifiedCallerAccess(),
                keyManager: keyMgr,
                gitSigningGraceManager: graceManager,
                auditRecorder: recorder,
                authenticator: fallbackAuth,
                signingPromptPresenter: presenter,
                peerProcessValidator: { _, _, _ in true }
            )
            let key = try keyMgr.generateKey(label: "scoped-key", unlockedTimeout: .untilLock)
            let pid = getpid()
            let realPath = ProcessInspector.getProcessPath(pid: pid) ?? "/usr/bin/git"
            let start = ProcessInspector.processStartTime(pid: pid) ?? 0

            // 1. Git Commit #1 (single-shot) -> Commit #2 receives defaultScope == .untilLock and creates ~24h grant
            let gitPayload = SSHSIGPayload(
                namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x44, count: 32)
            ).serialize()
            _ = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: gitPayload, flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: realPath, clientStartTime: start
            )
            _ = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: gitPayload, flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: realPath, clientStartTime: start
            )
            #expect(presenter.requests.last?.allowsSessionScope == true)
            #expect(presenter.requests.last?.defaultScope == .untilLock)
            let gitGrant = try #require(graceManager.getValidGrant(for: key.label))
            #expect(gitGrant.remainingSeconds > 23 * 3600)

            // 2. Verified app A SSH request #1 -> prompts with defaultScope == .untilLock and caches grant
            presenter.nextScope = .session
            let promptsBeforeSSH = presenter.requests.count
            let sshA1 = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: Data("ssh-a1".utf8), flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: "/Applications/TermA.app/ssh", clientStartTime: start
            )
            guard case .approved = sshA1 else { Issue.record("Expected SSH A1 approval"); return }
            #expect(presenter.requests.count == promptsBeforeSSH + 1)
            #expect(presenter.requests.last?.allowsSessionScope == true)
            #expect(presenter.requests.last?.defaultScope == .untilLock)

            // 3. Verified app A SSH request #2 -> reuses active grant with 0 extra prompts
            let sshA2 = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: Data("ssh-a2".utf8), flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: "/Applications/TermA.app/ssh", clientStartTime: start
            )
            guard case .approved = sshA2 else { Issue.record("Expected SSH A2 cached approval"); return }
            #expect(presenter.requests.count == promptsBeforeSSH + 1)
            #expect(recorder.events.last?.reason == .viaGitGrant)

            // 4. Different verified app B cannot reuse app A's session (D-28)
            let sshB1 = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: Data("ssh-b1".utf8), flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: "/Applications/TermB.app/ssh", clientStartTime: start
            )
            guard case .approved = sshB1 else { Issue.record("Expected SSH B1 approval"); return }
            #expect(presenter.requests.count == promptsBeforeSSH + 2)

            // 5. Locking the key / changing timeout revokes grants immediately so app A prompts again
            try keyMgr.lockKey(label: key.label)
            #expect(graceManager.allActivePersonalGrants().isEmpty)
            let sshA3 = try eval.evaluateSigningRequest(
                keyBlob: key.publicKeyBlob, dataToSign: Data("ssh-a3".utf8), flags: 0,
                role: .personal, clientPid: pid, clientExecutablePath: "/Applications/TermA.app/ssh", clientStartTime: start
            )
            guard case .approved = sshA3 else { Issue.record("Expected SSH A3 approval after lock"); return }
            #expect(presenter.requests.count == promptsBeforeSSH + 3)
        }
    }

    @Test
    func resolveSigningDestinationUsesVerifiedProtocolFirstAndFailsClosedOnForwarding() throws {
        let userPriv = Curve25519.Signing.PrivateKey()
        var userKeyBlob = Data()
        userKeyBlob.appendWireString("ssh-ed25519")
        userKeyBlob.appendWireData(userPriv.publicKey.rawRepresentation)

        let hostPriv = Curve25519.Signing.PrivateKey()
        var hostKeyBlob = Data()
        hostKeyBlob.appendWireString("ssh-ed25519")
        hostKeyBlob.appendWireData(hostPriv.publicKey.rawRepresentation)
        let sessionID = Data("dest-session".utf8)
        let hostSigRaw = try hostPriv.signature(for: sessionID)
        var hostSigBlob = Data()
        hostSigBlob.appendWireString("ssh-ed25519")
        hostSigBlob.appendWireData(hostSigRaw)

        let connection = AgentConnectionState()
        #expect(connection.bind(SessionBinding(hostKeyBlob: hostKeyBlob, sessionID: sessionID, isForwarding: false), signature: hostSigBlob))

        func makeUserAuth(user: String, method: String, includeHostKey: Bool) -> Data {
            var d = Data()
            d.appendWireData(sessionID)
            d.append(50) // SSH2_MSG_USERAUTH_REQUEST
            d.appendWireString(user)
            d.appendWireString("ssh-connection")
            d.appendWireString(method)
            d.append(1) // TRUE
            d.appendWireString("ssh-ed25519")
            d.appendWireData(userKeyBlob)
            if includeHostKey {
                d.appendWireData(hostKeyBlob)
            }
            return d
        }

        let plainUserAuth = makeUserAuth(user: "git", method: "publickey", includeHostKey: false)
        let hostboundUserAuth = makeUserAuth(user: "git", method: "publickey-hostbound-v00@openssh.com", includeHostKey: true)

        // 1. Verified hostKey + userauth username -> git@github.com
        let verified = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .ssh,
            dataToSign: plainUserAuth,
            keyBlob: userKeyBlob,
            connection: connection,
            isForwardedAgent: false,
            peerPid: 123,
            peerPath: "/usr/bin/ssh",
            knownHostsReverseLookup: { $0 == hostKeyBlob ? "github.com" : nil },
            processArgumentsLookup: { _ in Issue.record("Should not fall back to argv when known_hosts matched"); return nil },
            processWorkingDirectoryLookup: { _ in nil }
        )
        #expect(verified == "git@github.com")

        // 2. Hashed known_hosts (reverse lookup nil) falls back to ssh argv
        let fallback = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .ssh,
            dataToSign: plainUserAuth,
            keyBlob: userKeyBlob,
            connection: connection,
            isForwardedAgent: false,
            peerPid: 123,
            peerPath: "/usr/bin/ssh",
            knownHostsReverseLookup: { _ in nil },
            processArgumentsLookup: { _ in ["/usr/bin/ssh", "deploy@prod.example.com"] },
            processWorkingDirectoryLookup: { _ in nil }
        )
        #expect(fallback == "git@prod.example.com")

        // 3. Forwarded agent MUST ignore connection.authBinding and local ssh argv
        let forwardedNoUserAuthHostKey = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .ssh,
            dataToSign: plainUserAuth,
            keyBlob: userKeyBlob,
            connection: connection,
            isForwardedAgent: true,
            peerPid: 123,
            peerPath: "/usr/bin/ssh",
            knownHostsReverseLookup: { $0 == hostKeyBlob ? "github.com" : nil },
            processArgumentsLookup: { _ in Issue.record("Forwarded agent must never inspect local ssh argv"); return ["/usr/bin/ssh", "local.example"] },
            processWorkingDirectoryLookup: { _ in nil }
        )
        #expect(forwardedNoUserAuthHostKey == nil)

        let forwardedWithHostbound = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .ssh,
            dataToSign: hostboundUserAuth,
            keyBlob: userKeyBlob,
            connection: connection,
            isForwardedAgent: true,
            peerPid: 123,
            peerPath: "/usr/bin/ssh",
            knownHostsReverseLookup: { $0 == hostKeyBlob ? "remote.example.com" : nil },
            processArgumentsLookup: { _ in Issue.record("Forwarded agent must never inspect local ssh argv"); return nil },
            processWorkingDirectoryLookup: { _ in nil }
        )
        #expect(forwardedWithHostbound == "git@remote.example.com")

        // 4. Git SSHSIG resolves repo name (with fallbackPid)
        let repoRoot = fixture.testRootURL.appendingPathComponent("clavis-repo")
        try FileManager.default.createDirectory(at: repoRoot.appendingPathComponent(".git"), withIntermediateDirectories: true)
        let gitPayload = SSHSIGPayload(
            namespace: "git",
            hashAlgorithm: "sha256",
            messageHash: Data(repeating: 0x55, count: 32)
        ).serialize()

        let gitRepo = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .signature,
            dataToSign: gitPayload,
            keyBlob: userKeyBlob,
            connection: nil,
            isForwardedAgent: false,
            peerPid: 200,
            peerPath: "/usr/bin/ssh-keygen",
            fallbackPid: 199,
            knownHostsReverseLookup: { _ in nil },
            processArgumentsLookup: { _ in nil },
            processWorkingDirectoryLookup: { pid in pid == 199 ? repoRoot.path : nil }
        )
        #expect(gitRepo == "clavis-repo")

        // 5. Non-Git raw data on .signature returns nil
        let rawSign = SigningPolicyEvaluator.resolveSigningDestination(
            operation: .signature,
            dataToSign: Data("arbitrary-payload".utf8),
            keyBlob: userKeyBlob,
            connection: nil,
            isForwardedAgent: false,
            peerPid: 200,
            peerPath: "/usr/bin/ssh-keygen",
            knownHostsReverseLookup: { _ in nil },
            processArgumentsLookup: { _ in nil },
            processWorkingDirectoryLookup: { _ in repoRoot.path }
        )
        #expect(rawSign == nil)
    }

    @Test
    func test_personalUnlockTimeoutWorksAcrossTerminalAndAgentOnUncertainPath() async throws {
        try await fixture.run {
            let fallbackAuth = CountingAuthenticator()
            let keyMgr = fixture.makeKeyManager(authenticator: fallbackAuth, gitSigningGraceManager: graceManager)
            let presenter = MockSigningPromptPresenter()
            presenter.nextScope = .untilLock
            let eval = SigningPolicyEvaluator(
                applicationAccess: UncertainApplicationAccess(),
                keyManager: keyMgr,
                gitSigningGraceManager: graceManager,
                auditRecorder: recorder,
                authenticator: fallbackAuth,
                signingPromptPresenter: presenter,
                peerProcessValidator: { _, _, _ in true }
            )

            let pid = getpid()
            let start = ProcessInspector.processStartTime(pid: pid) ?? 0
            let realPath = ProcessInspector.getProcessPath(pid: pid) ?? "/usr/bin/git"
            let gitPayload = SSHSIGPayload(
                namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x66, count: 32)
            ).serialize()

            // 1. Personal key with unlockedTimeout: .untilLock shares cached grant across terminal SSH, agent path, and Git SSHSIG
            let untilLockKey = try keyMgr.generateKey(label: "github-until-lock", unlockedTimeout: .untilLock)
            let ssh1 = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: Data("ssh-1".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            guard case .approved = ssh1 else { Issue.record("Expected SSH #1 approval"); return }
            #expect(presenter.requests.count == 1)
            #expect(presenter.requests.last?.allowsSessionScope == true)
            #expect(presenter.requests.last?.defaultScope == .untilLock)
            #expect(graceManager.allActivePersonalGrants().count == 1)
            #expect(recorder.events.last?.reason == .viaPrompt)

            // Request #2 from another executable simulating an agent process reuses grant with 0 extra prompts
            let sshAgent = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: Data("ssh-agent-2".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/local/bin/claude",
                clientStartTime: start
            )
            guard case .approved = sshAgent else { Issue.record("Expected agent SSH reuse approval"); return }
            #expect(presenter.requests.count == 1)
            #expect(recorder.events.last?.reason == .viaGitGrant)

            // Request #3 Git SSHSIG commit reuses same Personal unlock grant with 0 extra prompts
            let gitCommit = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: gitPayload,
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: realPath,
                clientStartTime: start
            )
            guard case .approved = gitCommit else { Issue.record("Expected Git SSHSIG reuse approval"); return }
            #expect(presenter.requests.count == 1)
            #expect(recorder.events.last?.reason == .viaGitGrant)

            // Forwarded SSH must NEVER reuse the cached grant and must force single-shot prompt
            let hostPriv = Curve25519.Signing.PrivateKey()
            var hostKeyBlob = Data()
            hostKeyBlob.appendWireString("ssh-ed25519")
            hostKeyBlob.appendWireData(hostPriv.publicKey.rawRepresentation)
            let sessionID = Data("fwd-session".utf8)
            let hostSigRaw = try hostPriv.signature(for: sessionID)
            var hostSigBlob = Data()
            hostSigBlob.appendWireString("ssh-ed25519")
            hostSigBlob.appendWireData(hostSigRaw)
            let fwdConnection = AgentConnectionState()
            #expect(fwdConnection.bind(SessionBinding(hostKeyBlob: hostKeyBlob, sessionID: sessionID, isForwarding: true), signature: hostSigBlob))

            let forwardedSSH = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: Data("ssh-forwarded".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                connection: fwdConnection,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            guard case .approved = forwardedSSH else { Issue.record("Expected forwarded SSH one-shot approval"); return }
            #expect(presenter.requests.count == 2)
            #expect(presenter.requests.last?.allowsSessionScope == false)
            #expect(presenter.requests.last?.defaultScope == .always)
            #expect(presenter.requests.last?.isForwardedAgent == true)

            // Locking the key revokes the cached grant so the next request prompts again
            try keyMgr.lockKey(label: untilLockKey.label)
            #expect(graceManager.allActivePersonalGrants().isEmpty)

            let sshAfterLock = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: Data("ssh-after-lock".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            guard case .approved = sshAfterLock else { Issue.record("Expected SSH approval after lock"); return }
            #expect(presenter.requests.count == 3)
            #expect(presenter.requests.last?.allowsSessionScope == true)

            // 2. Personal key with unlockedTimeout: .always (Once) always prompts single-shot and creates no grant
            let countBeforeOnce = presenter.requests.count
            let onceKey = try keyMgr.generateKey(label: "github-once", unlockedTimeout: .always)
            for idx in 0..<2 {
                let res = try eval.evaluateSigningRequest(
                    keyBlob: onceKey.publicKeyBlob,
                    dataToSign: Data("ssh-once-\(idx)".utf8),
                    flags: 0,
                    role: .personal,
                    clientPid: pid,
                    clientExecutablePath: "/usr/bin/ssh",
                    clientStartTime: start
                )
                guard case .approved = res else { Issue.record("Expected Once SSH approval"); return }
            }
            #expect(presenter.requests.count == countBeforeOnce + 2)
            #expect(presenter.requests.suffix(2).allSatisfy { !$0.allowsSessionScope && $0.defaultScope == .always })

            // 3. Bot key with unlockedTimeout: .untilLock on uncertain path stays single-shot without PersonalUnlockGrant
            try keyMgr.lockKey(label: untilLockKey.label)
            let countBeforeBot = presenter.requests.count
            let botKey = try keyMgr.generateKey(
                label: "bot-until-lock",
                accessProfile: KeyAccessProfile(type: .bot, capabilities: KeyCapabilities(ssh: true, signature: true)),
                unlockedTimeout: .untilLock
            )
            for idx in 0..<2 {
                let res = try eval.evaluateSigningRequest(
                    keyBlob: botKey.publicKeyBlob,
                    dataToSign: Data("ssh-bot-\(idx)".utf8),
                    flags: 0,
                    role: .personal,
                    clientPid: pid,
                    clientExecutablePath: "/usr/bin/ssh",
                    clientStartTime: start
                )
                guard case .approved = res else { Issue.record("Expected Bot SSH approval"); return }
            }
            #expect(presenter.requests.count == countBeforeBot + 2)
            #expect(presenter.requests.suffix(2).allSatisfy { !$0.allowsSessionScope && $0.defaultScope == .always })
            #expect(graceManager.allActivePersonalGrants().isEmpty)

            // 4. Stale/failing cached PersonalUnlockGrant is invalidated and falls through to re-prompt
            let sharedIdentity = SigningPolicyEvaluator.sharedPersonalUnlockIdentity(for: untilLockKey)
            graceManager.recordPersonalSSHGrant(
                keyLabel: untilLockKey.label,
                approvalIdentity: sharedIdentity,
                duration: 300,
                allowedCapabilities: untilLockKey.effectiveAccessProfile.capabilities,
                context: TrackableLAContext(),
                hardwareSigner: { _ in throw AgentSessionGrantError.grantInvalidated }
            )
            let countBeforeStale = presenter.requests.count
            let recovered = try eval.evaluateSigningRequest(
                keyBlob: untilLockKey.publicKeyBlob,
                dataToSign: Data("ssh-stale-recovery".utf8),
                flags: 0,
                role: .personal,
                clientPid: pid,
                clientExecutablePath: "/usr/bin/ssh",
                clientStartTime: start
            )
            guard case .approved = recovered else { Issue.record("Expected stale grant recovery via re-prompt"); return }
            #expect(presenter.requests.count == countBeforeStale + 1)
            #expect(graceManager.allActivePersonalGrants().count == 1)
            #expect(fallbackAuth.authenticationCount == 0)
        }
    }
}
