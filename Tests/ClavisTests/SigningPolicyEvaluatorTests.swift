import XCTest
import CryptoKit
@testable import ClavisCore

final class SigningPolicyEvaluatorTests: ClavisBaseTestCase {
    private var recorder: InMemoryAuditRecorder!
    private var keyManager: KeychainManager!
    private var evaluator: SigningPolicyEvaluator!

    override func setUpWithError() throws {
        try super.setUpWithError()
        recorder = InMemoryAuditRecorder()
        keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore()
        )
        evaluator = SigningPolicyEvaluator(
            keyManager: keyManager,
            auditRecorder: recorder,
            peerProcessValidator: { _, _, _ in true }
        )
    }

    func test_evaluateSigningRequest_malformedFlags() throws {
        let keyInfo = try keyManager.generateKey(label: "flags-key")
        let decision = try evaluator.evaluateSigningRequest(
            keyBlob: keyInfo.publicKeyBlob,
            dataToSign: Data("test-data".utf8),
            flags: 1, // Non-zero flags are invalid in SSH agent wire protocol
            role: .personal,
            clientPid: getpid()
        )

        XCTAssertEqual(decision, .denied)
        XCTAssertEqual(recorder.events.count, 1)
        XCTAssertEqual(recorder.events.last?.result, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .malformedRequest)
    }

    func test_evaluateSigningRequest_unknownKey() throws {
        let unknownKeyBlob = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let decision = try evaluator.evaluateSigningRequest(
            keyBlob: unknownKeyBlob,
            dataToSign: Data("test-data".utf8),
            flags: 0,
            role: .personal,
            clientPid: getpid()
        )

        XCTAssertEqual(decision, .denied)
        XCTAssertEqual(recorder.events.count, 1)
        XCTAssertEqual(recorder.events.last?.result, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .unknownKey)
    }

    func test_evaluateSigningRequest_agentSocket_refusesForwarding() throws {
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
        XCTAssertTrue(connection.bind(binding, signature: sigBlob))
        XCTAssertTrue(connection.hasForwarding)

        let decision = try evaluator.evaluateSigningRequest(
            keyBlob: keyInfo.publicKeyBlob,
            dataToSign: Data("test-data".utf8),
            flags: 0,
            role: .agent,
            clientPid: getpid(),
            connection: connection
        )

        XCTAssertEqual(decision, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .forwardingRefused)
    }

    func test_evaluateSigningRequest_agentKey_refusesSSHSIG() throws {
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

        XCTAssertEqual(decision, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .wrongKeyKind)
    }

    func test_evaluateSigningRequest_gitSigningOnlyKey_refusesNonGitPayload() throws {
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

        XCTAssertEqual(decision, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .gitOnlyKeyNonGitPayload)
    }

    func test_evaluateSigningRequest_personalSocket_gitGraceFastPath() throws {
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
            XCTAssertFalse(sig.isEmpty)
        } else {
            XCTFail("Expected approved signature from active Git grant")
        }
        XCTAssertEqual(recorder.events.last?.result, .allowed)
        XCTAssertEqual(recorder.events.last?.reason, .viaGitGrant)
    }

    func test_staticReasonStringGenerators() {
        let authReason = SigningPolicyEvaluator.sshAuthenticationReason(keyLabel: "MyKey", requester: "/usr/bin/ssh (PID 123)")
        XCTAssertTrue(authReason.contains("MyKey"))
        XCTAssertTrue(authReason.contains("PID 123"))

        let gitReason = SigningPolicyEvaluator.gitCommitSigningReason(keyLabel: "GitKey", requester: "/usr/bin/git (PID 456)")
        XCTAssertTrue(gitReason.contains("GitKey"))
        XCTAssertTrue(gitReason.contains("PID 456"))

        let sessionReason = SigningPolicyEvaluator.gitSigningSessionReason(keyLabel: "GitKey")
        XCTAssertTrue(sessionReason.contains("GitKey"))

        let desc = SigningPolicyEvaluator.requesterDescription(processPath: "/usr/bin/ssh", pid: 789)
        XCTAssertEqual(desc, "/usr/bin/ssh (PID 789)")

        let safePath = SigningPolicyEvaluator.safeProcessPath("hello\u{0000}world")
        XCTAssertEqual(safePath, "hello?world")
    }

    func test_F6_requesterDescriptionMiddleTruncatesAndCollapsesWhitespace() {
        let spoofAttempt = "/Users/attacker/payload" + String(repeating: " ", count: 75) + "/usr/bin/ssh"
        let collapsedDesc = SigningPolicyEvaluator.requesterDescription(processPath: spoofAttempt, pid: 321)
        XCTAssertEqual(collapsedDesc, "/Users/attacker/payload /usr/bin/ssh (PID 321)")

        let longSpoofAttempt = "/Users/attacker/deeply/nested/directory/structure/that/exceeds/eighty/characters/easily/usr/bin/ssh"
        let truncatedDesc = SigningPolicyEvaluator.requesterDescription(processPath: longSpoofAttempt, pid: 654)
        XCTAssertTrue(truncatedDesc.hasPrefix("/Users/attacker/deeply/nested/di"), "Must preserve leading /Users/... prefix")
        XCTAssertTrue(truncatedDesc.contains("…"), "Must middle-truncate with ellipsis")
        XCTAssertTrue(truncatedDesc.hasSuffix("/usr/bin/ssh (PID 654)"), "Must preserve trailing binary path and PID")
        XCTAssertEqual(truncatedDesc.count, 80 + " (PID 654)".count)
    }

    func test_F6_processInspectorValidatesNixStorePathsAndPermissions() throws {
        // Malformed /nix/store paths must be rejected
        XCTAssertFalse(ProcessInspector.isTrustedSshBinary(path: "/nix/store/evil/sub/bin/ssh"))
        XCTAssertFalse(ProcessInspector.isTrustedSshBinary(path: "/nix/store/evil/bin/ssh"))
        XCTAssertFalse(ProcessInspector.isTrustedSshBinary(path: "/nix/store/../../tmp/bin/ssh"))
        XCTAssertFalse(ProcessInspector.isTrustedGitExecutable(path: "/nix/store/evil/sub/bin/git"))
        XCTAssertFalse(ProcessInspector.isTrustedGitExecutable(path: "/nix/store/0123456789abcdef0123456789abcdef-git/sub/bin/git"))
        XCTAssertFalse(ProcessInspector.isTrustedSshKeygen(path: "/nix/store/evil/sub/bin/ssh-keygen"))

        // Valid /nix/store/<32-char-hash>-<name>/bin/<binary> paths must be accepted
        let validHash = "0123456789abcdef0123456789abcdef"
        XCTAssertTrue(ProcessInspector.isTrustedSshBinary(path: "/nix/store/\(validHash)-openssh-9.8p1/bin/ssh"))
        XCTAssertTrue(ProcessInspector.isTrustedGitExecutable(path: "/nix/store/\(validHash)-git-2.44.0/bin/git"))
        XCTAssertTrue(ProcessInspector.isTrustedSshKeygen(path: "/nix/store/\(validHash)-openssh-9.8p1/bin/ssh-keygen"))

        // On-disk permission checks (reject group/world-writable binaries)
        let fakeStoreRoot = testRootURL.appendingPathComponent("nix-store")
        let entryDir = fakeStoreRoot.appendingPathComponent("\(validHash)-openssh-9.8p1/bin")
        try FileManager.default.createDirectory(at: entryDir, withIntermediateDirectories: true)
        let binURL = entryDir.appendingPathComponent("ssh")
        try Data("#!/bin/sh\n".utf8).write(to: binURL)

        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binURL.path)
        XCTAssertTrue(
            ProcessInspector.isValidNixStoreBinary(
                standardizedPath: binURL.path,
                binaryName: "ssh",
                storeRoot: fakeStoreRoot.path
            )
        )

        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: binURL.path)
        XCTAssertFalse(
            ProcessInspector.isValidNixStoreBinary(
                standardizedPath: binURL.path,
                binaryName: "ssh",
                storeRoot: fakeStoreRoot.path
            ),
            "World-writable binary in Nix store must be rejected"
        )
    }
}
