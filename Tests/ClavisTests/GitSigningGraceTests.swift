import Foundation
import Testing
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

@Suite(.serialized)
final class GitSigningGraceTests {
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

    @Test func testSSHSIGPayloadStrictParsing() throws {
        // Valid Git SSHSIG payload (sha256)
        let hash256 = Data(repeating: 0x42, count: 32)
        let payload256 = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: hash256)
        let wire256 = payload256.serialize()

        let parsed = SSHSIGPayload.parse(from: wire256)
        #expect(parsed != nil)
        #expect(parsed?.namespace == "git")
        #expect(parsed?.hashAlgorithm == "sha256")
        #expect(parsed?.messageHash == hash256)

        // Valid Git SSHSIG payload (sha512)
        let hash512 = Data(repeating: 0x99, count: 64)
        let payload512 = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha512", messageHash: hash512)
        let wire512 = payload512.serialize()
        let parsed512 = SSHSIGPayload.parse(from: wire512)
        #expect(parsed512 != nil)
        #expect(parsed512?.hashAlgorithm == "sha512")
        #expect(parsed512?.messageHash == hash512)

        // 1. Wrong magic
        var badMagic = wire256
        badMagic[0] = 0x58
        #expect(SSHSIGPayload.parse(from: badMagic) == nil)

        // 2. Non-git namespace
        let filePayload = SSHSIGPayload(namespace: "file", hashAlgorithm: "sha256", messageHash: hash256)
        #expect(SSHSIGPayload.parse(from: filePayload.serialize()) == nil)

        // 3. Invalid hash length (31 bytes for sha256)
        var invalidLenWire = SSHSIGPayload.magic
        invalidLenWire.appendWireString("git")
        invalidLenWire.appendWireString("")
        invalidLenWire.appendWireString("sha256")
        invalidLenWire.appendWireData(Data(repeating: 0x01, count: 31))
        #expect(SSHSIGPayload.parse(from: invalidLenWire) == nil)

        // 4. Trailing garbage bytes (fail closed)
        var trailingGarbageWire = wire256
        trailingGarbageWire.append(Data([0x00, 0x01, 0x02]))
        #expect(SSHSIGPayload.parse(from: trailingGarbageWire) == nil)

        // 5. Non-empty reserved field
        var badReservedWire = SSHSIGPayload.magic
        badReservedWire.appendWireString("git")
        badReservedWire.appendWireString("reserved-data")
        badReservedWire.appendWireString("sha256")
        badReservedWire.appendWireData(hash256)
        #expect(SSHSIGPayload.parse(from: badReservedWire) == nil)

        // 6. Arbitrary non-SSHSIG payload
        let sshAuthPayload = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        #expect(SSHSIGPayload.parse(from: sshAuthPayload) == nil)
    }

    @Test func testGitSigningGrantLifecycle() throws {
        let label = "grant-test-\(UUID().uuidString)"
        let myPid = getpid()
        let mySnap = try #require(ProcessInspector.processParentSnapshot(pid: myPid), "Failed to get process snapshot for test runner")
        let approved = GitApprovedProcess(pid: myPid, startTime: mySnap.startTime, path: "/usr/bin/git")
        let grant = GitSigningGrant(keyLabel: label, duration: 0.2, maxOperations: 3, approvedProcess: approved)

        #expect(grant.isValid)
        #expect(grant.remainingOperations == 3)

        // Consume operations
        #expect(grant.consumeOperation(clientIdentity: "/usr/bin/git", peerProcess: approved))
        #expect(grant.remainingOperations == 2)
        #expect(grant.consumeOperation(clientIdentity: "/usr/bin/git", peerProcess: approved))
        #expect(grant.remainingOperations == 1)
        #expect(grant.consumeOperation(clientIdentity: "/usr/bin/git", peerProcess: approved))
        #expect(grant.remainingOperations == 0)

        // Exceeded operation limit
        #expect(!grant.consumeOperation(clientIdentity: "/usr/bin/git", peerProcess: approved))
        #expect(!grant.isValid)

        // Expiry by time
        let timeGrant = GitSigningGrant(keyLabel: label, duration: 0.05, maxOperations: 100, approvedProcess: approved)
        #expect(timeGrant.isValid)
        usleep(70_000)
        #expect(!timeGrant.isValid)
        #expect(!timeGrant.consumeOperation(clientIdentity: "/usr/bin/git", peerProcess: approved))
    }

    @Test func testGitSigningGraceManagerRebaseFlow() throws {
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)

        let label = "rebase-key-\(UUID().uuidString)"

        // Step 1: First commit
        #expect(!graceManager.hasRecentGitSignature(for: label))
        graceManager.recordGitSignature(for: label)
        #expect(graceManager.hasRecentGitSignature(for: label, windowSeconds: 2.0))

        // Step 2: Second commit within window (<30s) prompts user
        var promptCalled = false
        graceManager.setPresenter(ClosureGitSigningGracePresenter { keyLabel, clientDesc in
            promptCalled = true
            return .grantFiveMinutes
        })

        let choice = graceManager.prompt(keyLabel: label, clientDesc: "git (PID 1234)")
        #expect(promptCalled)
        #expect(choice == .grantFiveMinutes)

        let myPid = getpid()
        let mySnap = try #require(ProcessInspector.processParentSnapshot(pid: myPid), "Failed to get process snapshot for test runner")
        let approved = GitApprovedProcess(pid: myPid, startTime: mySnap.startTime, path: "/usr/bin/git")

        // Issue grant
        let grant = graceManager.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            duration: 300,
            maxOperations: 50,
            context: LAContext(),
            approvedProcess: approved
        )
        #expect(graceManager.getValidGrant(for: label) != nil)
        #expect(grant.remainingOperations == 50)

        // Step 3: Subsequent rebase commits consume grant
        let result = graceManager.withGrant(for: label, clientIdentity: "/usr/bin/git", peerProcess: approved) { _ in "signed" }
        #expect(result == "signed")
        #expect(grant.remainingOperations == 49)
        let untrustedPeer = GitApprovedProcess(pid: myPid + 9999, startTime: mySnap.startTime, path: "/tmp/fake-git")
        #expect(
            graceManager.withGrant(for: label, clientIdentity: "/tmp/fake-git", peerProcess: untrustedPeer) { _ in "signed" } == nil,
            "A grant must not be transferable to another client identity or unapproved process"
        )

        // Invalidation clears grant
        graceManager.invalidateAll(broadcast: false)
        #expect(graceManager.getValidGrant(for: label) == nil)
    }

    @Test func testKeyPurposeDomainIsolation() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator, privateKeyStore: store)

        let label = "git-only-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .gitSigningOnly)
        #expect(keyInfo.purpose == .gitSigningOnly)

        // Verify stored record preserves purpose
        let loaded = try #require(try store.load(label: label, context: LAContext(), prompt: ""))
        let record = try StoredPrivateKeyRecord.decode(from: loaded)
        #expect(record.purpose == .gitSigningOnly)

        // SSH Agent identities answer must EXCLUDE gitSigningOnly keys
        let server = SSHAgentServer(keyManager: manager)
        let identitiesData = server.handleRequestIdentities()
        #expect(!identitiesData.isEmpty)
        let blobInIdentities = identitiesData.range(of: keyInfo.publicKeyBlob) != nil
        #expect(!blobInIdentities, "Git-only key must never be advertised in SSH identities listing")

        // Signing non-Git payload with git-only key must be REJECTED (Data([5]))
        var signRequestWire = Data()
        signRequestWire.appendWireData(keyInfo.publicKeyBlob)
        signRequestWire.appendWireData(Data("ssh-userauth-challenge".utf8))
        var flags: UInt32 = 0
        Swift.withUnsafeBytes(of: &flags) { signRequestWire.append(contentsOf: $0) }

        let response = server.handleSignRequest(payload: signRequestWire, clientPid: getpid())
        #expect(response == Data([5]), "Non-Git payload must be strictly rejected for gitSigningOnly key")

        // Signing valid Git SSHSIG payload must SUCCEED
        let validGitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x55, count: 32)).serialize()
        var validSignRequest = Data()
        validSignRequest.appendWireData(keyInfo.publicKeyBlob)
        validSignRequest.appendWireData(validGitPayload)
        Swift.withUnsafeBytes(of: &flags) { validSignRequest.append(contentsOf: $0) }

        let gitResponse = server.handleSignRequest(payload: validSignRequest, clientPid: getpid())
        #expect(gitResponse.first == 14, "Git SSHSIG payload must be signed successfully")
    }

    @Test func testTamperedPublicPurposeCannotBroadenGitOnlyKey() throws {
        let store = InMemoryPrivateKeyStore()
        let manager = makeKeyManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store
        )
        let original = try manager.generateKey(
            label: "purpose-tamper-\(UUID().uuidString)",
            keyPurpose: .gitSigningOnly
        )
        let gitPayload = SSHSIGPayload(
            namespace: "git",
            hashAlgorithm: "sha256",
            messageHash: Data(repeating: 0x42, count: 32)
        ).serialize()

        // Authoritative Git-only signing
        _ = try manager.signSSH(key: original, data: gitPayload, prompt: "Git", useCache: true)

        let tampered = SSHKeyInfo(
            label: original.label,
            publicKeyOpenSSH: original.publicKeyOpenSSH,
            publicKeyBlob: original.publicKeyBlob,
            fingerprint: original.fingerprint,
            createdAt: original.createdAt,
            algorithmName: original.algorithmName,
            storage: original.storage,
            biometricPolicy: original.biometricPolicy,
            keyPurpose: .general
        )

        #expect {
            try manager.signSSH(
                key: tampered,
                data: Data("ssh-userauth-challenge".utf8),
                prompt: "SSH",
                useCache: true
            )
        } throws: { error in
            guard case PrivateKeyRecordError.purposeMismatch(let expected, let actual) = error else {
                return false
            }
            return expected == KeyPurpose.general.rawValue && actual == KeyPurpose.gitSigningOnly.rawValue
        }

        #expect {
            try manager.authorizeGitSigningGrant(
                key: tampered,
                prompt: "Grant",
                clientIdentity: "/usr/bin/git"
            )
        } throws: { error in
            guard case PrivateKeyRecordError.purposeMismatch = error else {
                return false
            }
            return true
        }
    }

    @Test func testGitOnlyKeyCannotBeUsedForNonGitSigning() throws {
        let manager = makeKeyManager()
        let key = try manager.generateKey(
            label: "git-only-operations-\(UUID().uuidString)",
            keyPurpose: .gitSigningOnly
        )

        #expect {
            try manager.signSSH(
                key: key,
                data: Data("arbitrary-non-git-challenge".utf8),
                prompt: "Generic"
            )
        } throws: { error in
            guard case PrivateKeyRecordError.purposeNotAllowed = error else {
                return false
            }
            return true
        }
    }

    @Test func testSSHAgentServerRebaseGraceFlow() throws {
        let store = InMemoryPrivateKeyStore()

        let authenticator = CountingAuthenticator()
        var promptCount = 0
        let customGraceManager = GitSigningGraceManager(
            observeSystemEvents: false,
            presenter: ClosureGitSigningGracePresenter { _, _ in
                promptCount += 1
                return .grantFiveMinutes
            }
        )
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )
        let server = SSHAgentServer(
            keyManager: manager,
            gitSigningGraceManager: customGraceManager
        )

        let label = "rebase-flow-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        let makeGitSignRequest: () -> Data = {
            let gitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x77, count: 32)).serialize()
            var req = Data()
            req.appendWireData(keyInfo.publicKeyBlob)
            req.appendWireData(gitPayload)
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
            return req
        }

        // Commit #1: First commit (single commit)
        let resp1 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(resp1.first == 14)
        #expect(authenticator.authenticationCount == 1, "First commit requires standard single Touch ID")
        #expect(promptCount == 0, "First commit must not show modal dialog")
        #expect(customGraceManager.getValidGrant(for: label) == nil, "No grant issued on first single commit")

        // Commit #2: Repeated commit within 30s (Rebase detected!)
        let resp2 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(resp2.first == 14)
        #expect(promptCount == 1, "Second commit within 30s must trigger session dialog")
        #expect(authenticator.authenticationCount == 2, "Second commit requires Touch ID to authorize 5-minute grant")

        let activeGrant = try #require(customGraceManager.getValidGrant(for: label))
        #expect(activeGrant.isValid)
        #expect(activeGrant.remainingOperations == 199, "Commit #2 consumes 1 operation of the 200 grant")

        // Commit #3: Subsequent commit during rebase
        let resp3 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(resp3.first == 14)
        #expect(authenticator.authenticationCount == 2, "Third commit must NOT prompt Touch ID (0 prompts)")
        #expect(promptCount == 1, "Third commit must NOT show dialog")
        #expect(activeGrant.remainingOperations == 198, "Commit #3 consumes another operation")

        // Invalidation (e.g. End Session / Screen Lock)
        customGraceManager.invalidateAll(broadcast: false)
        #expect(customGraceManager.getValidGrant(for: label) == nil)
    }

    @Test func testResolveClientIdentityDifferentiatesProcesses() {
        let currentPid = getpid()
        guard let currentPath = ProcessInspector.getProcessPath(pid: currentPid) else {
            return
        }

        let identity1 = ProcessInspector.resolveClientIdentity(pid: currentPid, processPath: currentPath)
        let identity2 = ProcessInspector.resolveClientIdentity(pid: currentPid, processPath: currentPath)

        // Same process call must produce identical identity
        #expect(identity1 == identity2)
        #expect(identity1.contains(currentPath))

        // Different executable paths or different processes must produce distinct identities
        let fakeIdentity = ProcessInspector.resolveClientIdentity(pid: currentPid, processPath: "/usr/bin/git")
        #expect(identity1 != fakeIdentity)

        // PID 1 (launchd) has no parent or init parent, must differ from current process
        if let launchdPath = ProcessInspector.getProcessPath(pid: 1) {
            let launchdIdentity = ProcessInspector.resolveClientIdentity(pid: 1, processPath: launchdPath)
            #expect(identity1 != launchdIdentity)
        }
    }

    @Test func testSameParentDoesNotInheritGitSigningGrant() {
        let shell: pid_t = 10
        let approvedGit: pid_t = 20
        let siblingGit: pid_t = 21
        let signer: pid_t = 30
        let shellStart: UInt64 = 1_000
        let approvedStart: UInt64 = 2_000
        let siblingStart: UInt64 = 2_100
        let signerStart: UInt64 = 3_000

        let processes: [pid_t: ProcessParentSnapshot] = [
            1: ProcessParentSnapshot(startTime: 1, parentPid: 0),
            shell: ProcessParentSnapshot(startTime: shellStart, parentPid: 1),
            approvedGit: ProcessParentSnapshot(startTime: approvedStart, parentPid: shell),
            siblingGit: ProcessParentSnapshot(startTime: siblingStart, parentPid: shell),
            signer: ProcessParentSnapshot(startTime: signerStart, parentPid: approvedGit),
        ]
        let processPaths: [pid_t: String] = [
            1: "/sbin/launchd",
            shell: "/bin/zsh",
            approvedGit: "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
            siblingGit: "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
            signer: "/usr/bin/ssh-keygen",
        ]
        let lookup: (pid_t) -> ProcessParentSnapshot? = { processes[$0] }
        let pathLookup: (pid_t) -> String? = { processPaths[$0] }

        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: approvedGit,
                peerStartTime: approvedStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup,
                processPathLookup: pathLookup
            ),
            "The approved git process keeps its own grant"
        )
        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: signer,
                peerStartTime: signerStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup,
                processPathLookup: pathLookup
            ),
            "A signer helper child of the approved git, such as ssh-keygen, keeps the grant"
        )
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: siblingGit,
                peerStartTime: siblingStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup,
                processPathLookup: pathLookup
            ),
            "A new git started by the same shell must not inherit the grant"
        )

        var reused = processes
        reused[approvedGit] = ProcessParentSnapshot(startTime: approvedStart &+ 1, parentPid: shell)
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: approvedGit,
                peerStartTime: approvedStart &+ 1,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: { reused[$0] },
                processPathLookup: pathLookup
            ),
            "A recycled PID must not inherit the grant approved for the previous instance"
        )
    }

    @Test func testGitGrantAnchorModelsRealProcessShape() {
        let shellPid: pid_t = 10
        let gitGPid: pid_t = 20
        let signer2Pid: pid_t = 30
        let signer3Pid: pid_t = 31
        let gitG2Pid: pid_t = 40
        let signerUnderDifferentGitPid: pid_t = 41
        let shellSignerPid: pid_t = 50

        let shellStart: UInt64 = 1_000
        let gitGStart: UInt64 = 2_000
        let signer2Start: UInt64 = 3_000
        let signer3Start: UInt64 = 3_100
        let gitG2Start: UInt64 = 4_000
        let signerDifferentGitStart: UInt64 = 4_100
        let shellSignerStart: UInt64 = 5_000

        let processes: [pid_t: ProcessParentSnapshot] = [
            1: ProcessParentSnapshot(startTime: 1, parentPid: 0),
            shellPid: ProcessParentSnapshot(startTime: shellStart, parentPid: 1),
            gitGPid: ProcessParentSnapshot(startTime: gitGStart, parentPid: shellPid),
            signer2Pid: ProcessParentSnapshot(startTime: signer2Start, parentPid: gitGPid),
            signer3Pid: ProcessParentSnapshot(startTime: signer3Start, parentPid: gitGPid),
            gitG2Pid: ProcessParentSnapshot(startTime: gitG2Start, parentPid: shellPid),
            signerUnderDifferentGitPid: ProcessParentSnapshot(startTime: signerDifferentGitStart, parentPid: gitG2Pid),
            shellSignerPid: ProcessParentSnapshot(startTime: shellSignerStart, parentPid: shellPid),
        ]
        let processPaths: [pid_t: String] = [
            1: "/sbin/launchd",
            shellPid: "/bin/zsh",
            gitGPid: "/usr/bin/git",
            signer2Pid: "/usr/bin/ssh-keygen",
            signer3Pid: "/usr/bin/ssh-keygen",
            gitG2Pid: "/usr/bin/git",
            signerUnderDifferentGitPid: "/usr/bin/ssh-keygen",
            shellSignerPid: "/usr/bin/ssh-keygen",
        ]

        let processInfo: (pid_t) -> ProcessParentSnapshot? = { processes[$0] }
        let pathLookup: (pid_t) -> String? = { processPaths[$0] }

        // Approved signer #2 (parent git G) anchors on parent git G
        guard let anchor = ProcessInspector.grantAnchor(
            peerPid: signer2Pid,
            peerPath: processPaths[signer2Pid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        ) else {
            Issue.record("grantAnchor must succeed for signer #2 under git G")
            return
        }

        #expect(anchor.pid == gitGPid, "Anchor PID must be parent git G")
        #expect(anchor.startTime == gitGStart, "Anchor start time must match git G")
        #expect(anchor.path == "/usr/bin/git", "Anchor path must match parent git")

        // Peer signer #3 (same parent G) is covered
        let signer3 = GitApprovedProcess(pid: signer3Pid, startTime: signer3Start)
        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: signer3.pid,
                peerStartTime: signer3.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "Peer signer #3 under the same git G must be covered by the anchor grant"
        )

        // Signer under different git is NOT covered
        let signerDifferentGit = GitApprovedProcess(
            pid: signerUnderDifferentGitPid,
            startTime: signerDifferentGitStart
        )
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerDifferentGit.pid,
                peerStartTime: signerDifferentGit.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "Signer under a different git G2 must NOT be covered by the anchor grant"
        )

        // Recycled git pid is NOT covered
        var recycledProcesses = processes
        recycledProcesses[gitGPid] = ProcessParentSnapshot(startTime: gitGStart &+ 1, parentPid: shellPid)
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signer3.pid,
                peerStartTime: signer3.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: { recycledProcesses[$0] },
                processPathLookup: pathLookup
            ),
            "Recycled git pid must NOT be covered"
        )

        // Anchor on shell is refused
        let shellSignerAnchor = ProcessInspector.grantAnchor(
            peerPid: shellSignerPid,
            peerPath: processPaths[shellSignerPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        #expect(shellSignerAnchor == nil, "Anchor on shell must be refused when signer parent is a shell")

        let directShellAnchor = ProcessInspector.grantAnchor(
            peerPid: shellPid,
            peerPath: processPaths[shellPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        #expect(directShellAnchor == nil, "Anchor directly on shell must be refused")

        let launchdAnchor = ProcessInspector.grantAnchor(
            peerPid: 1,
            peerPath: processPaths[1]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        #expect(launchdAnchor == nil, "Anchor on launchd must be refused")
    }

    @Test func testCustomGpgSSHProgramResolvedAsKnownHelper() {
        let shellPid: pid_t = 10
        let gitPid: pid_t = 20
        let customSignerPid: pid_t = 30
        let unknownProgPid: pid_t = 35

        let processes: [pid_t: ProcessParentSnapshot] = [
            1: ProcessParentSnapshot(startTime: 1, parentPid: 0),
            shellPid: ProcessParentSnapshot(startTime: 100, parentPid: 1),
            gitPid: ProcessParentSnapshot(startTime: 200, parentPid: shellPid),
            customSignerPid: ProcessParentSnapshot(startTime: 300, parentPid: gitPid),
            unknownProgPid: ProcessParentSnapshot(startTime: 350, parentPid: gitPid),
        ]
        let paths: [pid_t: String] = [
            shellPid: "/bin/bash",
            gitPid: "/usr/local/bin/git",
            customSignerPid: "/opt/homebrew/bin/my-signer",
            unknownProgPid: "/usr/bin/curl",
        ]

        let processInfo: (pid_t) -> ProcessParentSnapshot? = { processes[$0] }
        let pathLookup: (pid_t) -> String? = { paths[$0] }

        // When gpg.ssh.program resolves to /opt/homebrew/bin/my-signer
        let customResolver: () -> String? = { "/opt/homebrew/bin/my-signer" }

        let customAnchor = ProcessInspector.grantAnchor(
            peerPid: customSignerPid,
            peerPath: paths[customSignerPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup,
            resolvedGpgSSHProgram: customResolver
        )
        #expect(customAnchor != nil)
        #expect(customAnchor?.pid == gitPid)
        #expect(customAnchor?.startTime == 200)
        #expect(customAnchor?.path == "/usr/local/bin/git")

        // Unknown program (e.g. curl) under git is NOT a known signer helper
        let unknownAnchor = ProcessInspector.grantAnchor(
            peerPid: unknownProgPid,
            peerPath: paths[unknownProgPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup,
            resolvedGpgSSHProgram: customResolver
        )
        #expect(unknownAnchor == nil, "Unknown program that is not a signer helper must be refused as an anchor helper")
    }

    @Test func testResolveGpgSSHProgramTimesOutAndKillsHangingProcess() throws {
        let scriptURL = testRootURL.appendingPathComponent("hanging-git.sh")
        let scriptContent = "#!/bin/sh\nsleep 10\n"
        try scriptContent.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let start = Date()
        let result = ProcessInspector.resolveGpgSSHProgram(gitExecutablePath: scriptURL.path, timeout: 0.08)
        let elapsed = Date().timeIntervalSince(start)

        #expect(result == nil, "resolveGpgSSHProgram must return nil on timeout")
        #expect(elapsed >= 0.06, "Must wait for the timeout duration")
        #expect(elapsed < 2.0, "Must terminate child process without hanging until sleep completes")
    }

    @Test func testResolveGpgSSHProgramParsesOutputSuccessfully() throws {
        let scriptURL = testRootURL.appendingPathComponent("mock-git.sh")
        let scriptContent = "#!/bin/sh\necho \"  /opt/bin/mock-signer  \"\n"
        try scriptContent.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let result = ProcessInspector.resolveGpgSSHProgram(gitExecutablePath: scriptURL.path, timeout: 2.0)
        #expect(result == "/opt/bin/mock-signer")
    }

    @Test func testCycleSafeAncestorWalk() {
        // Model an adversarial or corrupted cycle: PID 100 -> 101 -> 100
        let processes: [pid_t: ProcessParentSnapshot] = [
            100: ProcessParentSnapshot(startTime: 1000, parentPid: 101),
            101: ProcessParentSnapshot(startTime: 1001, parentPid: 100),
        ]
        let covered = ProcessInspector.gitGrantCoversPeer(
            peerPid: 100,
            peerStartTime: 1000,
            approvedPid: 200,
            approvedStartTime: 2000,
            processInfo: { processes[$0] }
        )
        #expect(!covered, "Cycle in process tree must terminate safely and return false")
    }

    @Test func testRefusedAnchorsOnAllShellsAndTerminals() {
        let refusedNames = [
            "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
            "Terminal", "iTerm", "iTerm2", "kitty", "alacritty", "wezterm", "tmux", "screen", "login",
            "launchd"
        ]
        for name in refusedNames {
            let path = "/usr/bin/\(name)"
            let refused = ProcessInspector.isRefusedAnchor(pid: 42, path: path)
            #expect(refused, "Executable named \(name) must be recognized as refused anchor")

            let anchor = ProcessInspector.grantAnchor(
                peerPid: 42,
                peerPath: path,
                processInfo: { _ in ProcessParentSnapshot(startTime: 100, parentPid: 1) },
                processPathLookup: { _ in "/bin/bash" }
            )
            #expect(anchor == nil, "grantAnchor must refuse \(name)")
        }
    }

    @Test func testGrantAnchorAcceptsGitAndXCTestInDebug() {
        let gitPid: pid_t = 100
        let gitPath = "/nix/store/0123456789abcdef0123456789abcdef-git-2.40.0/bin/git"
        let gitAnchor = ProcessInspector.grantAnchor(
            peerPid: gitPid,
            peerPath: gitPath,
            processInfo: { _ in ProcessParentSnapshot(startTime: 1000, parentPid: 1) },
            processPathLookup: { _ in gitPath }
        )
        #expect(gitAnchor != nil, "grantAnchor must accept git with valid Nix store path")
        #expect(gitAnchor?.pid == gitPid)

        let xctestPid: pid_t = 200
        let xctestPath = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/Library/Xcode/Agents/xctest"
        let xctestAnchor = ProcessInspector.grantAnchor(
            peerPid: xctestPid,
            peerPath: xctestPath,
            processInfo: { _ in ProcessParentSnapshot(startTime: 2000, parentPid: 1) },
            processPathLookup: { _ in xctestPath }
        )
        #if DEBUG
        #expect(xctestAnchor != nil, "xctest must be accepted as an anchor in DEBUG builds")
        #expect(xctestAnchor?.pid == xctestPid)
        #else
        #expect(xctestAnchor == nil, "xctest must NOT be accepted as an anchor in release builds")
        #endif
    }

    @Test func testGitSigningPromptBypassesModalInHeadlessSession() {
        let previousProvider = GitSigningPrompt.sessionCheckProvider
        defer { GitSigningPrompt.sessionCheckProvider = previousProvider }

        // Simulate headless/non-GUI environment
        GitSigningPrompt.sessionCheckProvider = { false }

        let start = Date()
        let choice = GitSigningPrompt.displayModal(keyLabel: "test-key", clientDesc: "git (PID 9999)")
        let elapsed = Date().timeIntervalSince(start)

        // Must return .singleShot immediately (< 0.5s), avoiding the 30-second CFUserNotificationDisplayAlert hang
        #expect(choice == .singleShot)
        #expect(elapsed < 0.5)
    }

    @Test func testModalDefaultButtonIsTheLeastPrivilegedChoice() {
        // Return / default button must never start an unattended signing session.
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse)) ==
            .singleShot
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationAlternateResponse)) ==
            .cancel
        )
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationOtherResponse)) ==
            .grantFiveMinutes
        )
    }

    @Test func testModalTimeoutAndUnknownResponsesCancel() {
        // CFUserNotification reports a timeout / dismissal as the cancel response (3).
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationCancelResponse)) ==
            .cancel
        )
        // Only the low two bits carry the response; higher flag bits must not change the outcome.
        #expect(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse) | 0x100) ==
            .singleShot
        )
    }

    @Test func testAuthorizeGitSigningGrantUsesBiometricsForCurrentSet() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = PolicyCapturingAuthenticator()
        let customGraceManager = GitSigningGraceManager(observeSystemEvents: false)
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )

        let label = "strict-grant-\(UUID().uuidString)"
        let key = try installEd25519Record(
            store: store,
            label: label,
            recordPolicy: .biometryCurrentSet,
            publishedPolicy: .biometryCurrentSet
        )

        let grant = try manager.authorizeGitSigningGrant(
            key: key,
            prompt: "Grant",
            clientIdentity: "/usr/bin/git"
        )

        #expect(authenticator.policies == [.deviceOwnerAuthenticationWithBiometrics])
        #expect(customGraceManager.getValidGrant(for: label)?.keyLabel == grant.keyLabel)
        #expect(grant.isValid)
    }

    @Test func testAuthorizeGitSigningGrantRejectsWeakerContextForStrictRecord() async throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = PolicyCapturingAuthenticator()
        let customGraceManager = GitSigningGraceManager(observeSystemEvents: false)
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )

        let label = "downgraded-grant-\(UUID().uuidString)"
        let key = try installEd25519Record(
            store: store,
            label: label,
            recordPolicy: .biometryCurrentSet,
            publishedPolicy: .userPresence
        )

        #expect {
            try manager.authorizeGitSigningGrant(
                key: key,
                prompt: "Grant",
                clientIdentity: "/usr/bin/git"
            )
        } throws: { error in
            guard case PrivateKeyRecordError.metadataMismatch(let field, let expected, let actual) = error else {
                return false
            }
            return field == "biometricPolicy" &&
                   expected == BiometricPolicy.userPresence.rawValue &&
                   actual == BiometricPolicy.biometryCurrentSet.rawValue
        }

        #expect(authenticator.policies == [.deviceOwnerAuthentication])
        #expect(customGraceManager.getValidGrant(for: label) == nil)

        let context = try #require(authenticator.contexts.last)
        context.interactionNotAllowed = true

        let (evaluatedSuccess, evaluatedError): (Bool, Error?) = await withCheckedContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "reuse") { success, error in
                continuation.resume(returning: (success, error))
            }
        }
        #expect(!evaluatedSuccess)
        #expect((evaluatedError as? LAError)?.code == .invalidContext)
    }

    @Test func testFailedSignatureUnderNewGrantInvalidatesGrant() throws {
        final class FailingGrantSigningProvider: SecureEnclaveSigningProviding, @unchecked Sendable {

            private let inner = InMemorySecureEnclaveSigningProvider()
            var signCount = 0

            var isAvailable: Bool { inner.isAvailable }

            func generateKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKeyData: Data) {
                try inner.generateKey(accessControl: accessControl)
            }

            func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> Data {
                try inner.derivePublicKey(dataRepresentation: dataRepresentation, context: context)
            }

            func signature(for data: Data, dataRepresentation: Data, context: LAContext?) throws -> P256.Signing.ECDSASignature {
                signCount += 1
                if signCount == 2 {
                    throw NSError(domain: "test", code: -1, userInfo: nil)
                }
                return try inner.signature(for: data, dataRepresentation: dataRepresentation, context: context)
            }
        }
        let signingProvider = FailingGrantSigningProvider()
        let customGraceManager = GitSigningGraceManager(
            observeSystemEvents: false,
            presenter: ClosureGitSigningGracePresenter { _, _ in .grantFiveMinutes }
        )
        let manager = makeKeyManager(
            authenticator: CountingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            signingProvider: signingProvider,
            gitSigningGraceManager: customGraceManager
        )
        let server = SSHAgentServer(
            keyManager: manager,
            gitSigningGraceManager: customGraceManager
        )
        let label = "grant-fail-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        let makeGitSignRequest: () -> Data = {
            let gitPayload = SSHSIGPayload(
                namespace: "git",
                hashAlgorithm: "sha256",
                messageHash: Data(repeating: 0x77, count: 32)
            ).serialize()
            var req = Data()
            req.appendWireData(keyInfo.publicKeyBlob)
            req.appendWireData(gitPayload)
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
            return req
        }

        let first = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(first.first == 14)

        let second = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(second == Data([5]))
        #expect(
            customGraceManager.getValidGrant(for: label) == nil,
            "A signature failure under a new grant must invalidate that grant"
        )
    }

    private func installEd25519Record(
        store: InMemoryPrivateKeyStore,
        label: String,
        recordPolicy: BiometricPolicy?,
        publishedPolicy: BiometricPolicy?
    ) throws -> SSHKeyInfo {
        let privateKey = P256.Signing.PrivateKey()
        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: recordPolicy,
            keyPurpose: .general,
            keyData: privateKey.rawRepresentation
        )
        defer { record.wipe() }
        try store.save(label: label, data: try record.encode())
        let blob = try KeychainManager.derivePublicKeyBlob(record: record)
        return SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 \(blob.base64EncodedString()) \(label)",
            publicKeyBlob: blob,
            fingerprint: "SHA256:test",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: publishedPolicy,
            keyPurpose: .general
        )
    }

    @Test func testGitSigningPromptDescSanitizesRLOAndZeroWidthCharacters() throws {
        let store = InMemoryPrivateKeyStore()

        let authenticator = CountingAuthenticator()
        var capturedPromptDesc = ""
        let customGraceManager = GitSigningGraceManager(
            observeSystemEvents: false,
            presenter: ClosureGitSigningGracePresenter { _, desc in
                capturedPromptDesc = desc
                return .cancel
            }
        )
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )
        let server = SSHAgentServer(
            keyManager: manager,
            gitSigningGraceManager: customGraceManager,
            peerProcessValidator: { _, _, _ in true }
        )

        let label = "git-sanitize-rlo-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        let makeGitSignRequest: () -> Data = {
            let gitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x77, count: 32)).serialize()
            var req = Data()
            req.appendWireData(keyInfo.publicKeyBlob)
            req.appendWireData(gitPayload)
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
            return req
        }

        let hostilePath = "/tmp/evil\u{202E}\u{200B}\u{200E}\u{FEFF}/git"

        // Commit #1
        _ = server.handleSignRequest(
            payload: makeGitSignRequest(),
            clientPid: getpid(),
            clientExecutablePath: hostilePath
        )

        // Commit #2 triggers git modal dialog
        _ = server.handleSignRequest(
            payload: makeGitSignRequest(),
            clientPid: getpid(),
            clientExecutablePath: hostilePath
        )

        #expect(!capturedPromptDesc.isEmpty, "Modal prompt must have been presented")
        #expect(
            capturedPromptDesc == "/tmp/evil/git (PID \(getpid()))",
            "promptDesc must strip RLO and zero-width characters without them in the description"
        )
        #expect(!capturedPromptDesc.unicodeScalars.contains("\u{202E}"), "promptDesc must not contain RLO character")
        #expect(!capturedPromptDesc.unicodeScalars.contains("\u{200B}"), "promptDesc must not contain zero-width space")
        #expect(!capturedPromptDesc.unicodeScalars.contains("\u{200E}"), "promptDesc must not contain LTR mark")
        #expect(!capturedPromptDesc.unicodeScalars.contains("\u{FEFF}"), "promptDesc must not contain zero-width no-break space")
    }

    @Test func testGitSigningPromptDescTruncatesLongPathPreservingTailWithEllipsis() throws {
        let store = InMemoryPrivateKeyStore()

        let authenticator = CountingAuthenticator()
        var capturedPromptDesc = ""
        let customGraceManager = GitSigningGraceManager(
            observeSystemEvents: false,
            presenter: ClosureGitSigningGracePresenter { _, desc in
                capturedPromptDesc = desc
                return .cancel
            }
        )
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )
        let server = SSHAgentServer(
            keyManager: manager,
            gitSigningGraceManager: customGraceManager,
            peerProcessValidator: { _, _, _ in true }
        )

        let label = "git-long-path-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        let makeGitSignRequest: () -> Data = {
            let gitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x77, count: 32)).serialize()
            var req = Data()
            req.appendWireData(keyInfo.publicKeyBlob)
            req.appendWireData(gitPayload)
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
            return req
        }

        let longPath = "/usr/local/" + String(repeating: "a", count: 600) + "/git"
        #expect(longPath.count >= 600)

        // Commit #1
        _ = server.handleSignRequest(
            payload: makeGitSignRequest(),
            clientPid: getpid(),
            clientExecutablePath: longPath
        )

        // Commit #2 triggers git modal dialog
        _ = server.handleSignRequest(
            payload: makeGitSignRequest(),
            clientPid: getpid(),
            clientExecutablePath: longPath
        )

        #expect(!capturedPromptDesc.isEmpty, "Modal prompt must have been presented")
        #expect(capturedPromptDesc.hasPrefix("/usr/local/"), "Long path must preserve leading prefix")
        #expect(capturedPromptDesc.contains("…"), "Long path must contain middle ellipsis")
        #expect(capturedPromptDesc.contains("/git (PID \(getpid()))"), "Long path must preserve the tail")
        let pidSuffix = " (PID \(getpid()))"
        #expect(capturedPromptDesc.count <= 80 + pidSuffix.count, "promptDesc must be bounded to ~80 chars plus PID")
    }

    @Test func testGitSigningConcurrentSignRequestsSerializePromptProvider() throws {
        try fixture.runSync {
            let store = InMemoryPrivateKeyStore()
            let authenticator = CountingAuthenticator()

            struct CallInterval {
                let entry: Date
                let exit: Date
            }
            let lock = NSLock()
            var intervals: [CallInterval] = []

            let customGraceManager = GitSigningGraceManager(
                observeSystemEvents: false,
                presenter: ClosureGitSigningGracePresenter { _, _ in
                    let entry = Date()
                    Thread.sleep(forTimeInterval: 0.05)
                    let exit = Date()
                    lock.lock()
                    intervals.append(CallInterval(entry: entry, exit: exit))
                    lock.unlock()
                    return .cancel
                }
            )
            let manager = makeKeyManager(
                authenticator: authenticator,
                privateKeyStore: store,
                gitSigningGraceManager: customGraceManager
            )
            let server = SSHAgentServer(
                keyManager: manager,
                gitSigningGraceManager: customGraceManager
            )

            let label = "git-concurrent-\(UUID().uuidString)"
            let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

            let makeGitSignRequest: () -> Data = {
                let gitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x77, count: 32)).serialize()
                var req = Data()
                req.appendWireData(keyInfo.publicKeyBlob)
                req.appendWireData(gitPayload)
                var flags: UInt32 = 0
                Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
                return req
            }

            // Commit #1: Establishes recent Git signature for this PID
            let resp1 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
            #expect(resp1.first == 14)

            // Two concurrent sign requests (Commit #2 candidates)
            let readySem = DispatchSemaphore(value: 0)
            let startSem = DispatchSemaphore(value: 0)
            let group = DispatchGroup()

            for _ in 0..<2 {
                group.enter()
                Thread.detachNewThread {
                    readySem.signal()
                    startSem.wait()
                    _ = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
                    group.leave()
                }
            }

            #expect(readySem.wait(timeout: .now() + 5) == .success)
            #expect(readySem.wait(timeout: .now() + 5) == .success)
            startSem.signal()
            startSem.signal()

            #expect(group.wait(timeout: .now() + 5) == .success)
            #expect(intervals.count == 2, "Both requests should have invoked promptProvider")

            if intervals.count == 2 {
                let sorted = intervals.sorted(by: { $0.entry < $1.entry })
                let first = sorted[0]
                let second = sorted[1]
                #expect(
                    second.entry.timeIntervalSince1970 >= first.exit.timeIntervalSince1970,
                    "Injected promptProvider must be called sequentially without overlap"
                )
            }
        }
    }

    @Test func testGitSigningGrantChainRestriction() {
        let launchdPid: pid_t = 1
        let shellPid: pid_t = 10
        let approvedGitPid: pid_t = 20
        let childGitPid: pid_t = 30
        let shHookPid: pid_t = 40
        let shScriptPid: pid_t = 50
        let gitUnderScriptPid: pid_t = 55
        let pythonPid: pid_t = 60
        let makePid: pid_t = 65

        let signerUnderApprovedGitPid: pid_t = 70
        let signerUnderChildGitPid: pid_t = 71
        let signerUnderShHookPid: pid_t = 72
        let signerUnderGitUnderScriptPid: pid_t = 73
        let signerUnderPythonPid: pid_t = 74
        let signerUnderMakePid: pid_t = 75
        let nonSignerHelperPid: pid_t = 76
        let customSignerUnderChildGitPid: pid_t = 77
        let customSignerUnderShPid: pid_t = 78

        let approvedStartTime: UInt64 = 2000
        let childGitStartTime: UInt64 = 3000
        let defaultStartTime: UInt64 = 5000

        let processes: [pid_t: ProcessParentSnapshot] = [
            launchdPid: ProcessParentSnapshot(startTime: 1, parentPid: 0),
            shellPid: ProcessParentSnapshot(startTime: 100, parentPid: launchdPid),
            approvedGitPid: ProcessParentSnapshot(startTime: approvedStartTime, parentPid: shellPid),
            childGitPid: ProcessParentSnapshot(startTime: childGitStartTime, parentPid: approvedGitPid),
            shHookPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: approvedGitPid),
            shScriptPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: approvedGitPid),
            gitUnderScriptPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: shScriptPid),
            pythonPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: approvedGitPid),
            makePid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: approvedGitPid),

            signerUnderApprovedGitPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: approvedGitPid),
            signerUnderChildGitPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: childGitPid),
            signerUnderShHookPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: shHookPid),
            signerUnderGitUnderScriptPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: gitUnderScriptPid),
            signerUnderPythonPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: pythonPid),
            signerUnderMakePid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: makePid),
            nonSignerHelperPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: childGitPid),
            customSignerUnderChildGitPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: childGitPid),
            customSignerUnderShPid: ProcessParentSnapshot(startTime: defaultStartTime, parentPid: shHookPid),
        ]

        let processPaths: [pid_t: String] = [
            launchdPid: "/sbin/launchd",
            shellPid: "/bin/zsh",
            approvedGitPid: "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
            childGitPid: "/nix/store/s0m3h4sh0123456789abcdef01234567-git-2.42.0/bin/git",
            shHookPid: "/bin/sh",
            shScriptPid: "/bin/bash",
            gitUnderScriptPid: "/usr/bin/git",
            pythonPid: "/usr/bin/python3",
            makePid: "/usr/bin/make",

            signerUnderApprovedGitPid: "/usr/bin/ssh-keygen",
            signerUnderChildGitPid: "/usr/bin/ssh-keygen",
            signerUnderShHookPid: "/usr/bin/ssh-keygen",
            signerUnderGitUnderScriptPid: "/usr/bin/ssh-keygen",
            signerUnderPythonPid: "/usr/bin/ssh-keygen",
            signerUnderMakePid: "/usr/bin/ssh-keygen",
            nonSignerHelperPid: "/bin/sh",
            customSignerUnderChildGitPid: "/opt/homebrew/bin/custom-signer",
            customSignerUnderShPid: "/opt/homebrew/bin/custom-signer",
        ]

        let processInfo: (pid_t) -> ProcessParentSnapshot? = { processes[$0] }
        let pathLookup: (pid_t) -> String? = { processPaths[$0] }
        let customResolver: () -> String? = { "/opt/homebrew/bin/custom-signer" }

        // 1. git -> ssh-keygen: covered
        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderApprovedGitPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> ssh-keygen must be covered"
        )

        // 2. git -> git -> ssh-keygen: covered (rebase spawning child git commit)
        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderChildGitPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> git -> ssh-keygen must be covered"
        )

        // 3. git -> sh -> ssh-keygen: refused (e.g. git hook)
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderShHookPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> sh -> ssh-keygen must be refused"
        )

        // 4. git -> sh -> git -> ssh-keygen: refused (e.g. rebase -x running a script that commits)
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderGitUnderScriptPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> sh -> git -> ssh-keygen must be refused"
        )

        // Other non-git intermediate ancestors: refused
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderPythonPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> python -> ssh-keygen must be refused"
        )
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderMakePid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "git -> make -> ssh-keygen must be refused"
        )

        // Non-signer helper peer: refused
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: nonSignerHelperPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "Non-signer helper peer must be refused"
        )

        // Custom gpg.ssh.program: covered for git-only chain, refused for non-git chain
        #expect(
            ProcessInspector.gitGrantCoversPeer(
                peerPid: customSignerUnderChildGitPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup,
                resolvedGpgSSHProgram: customResolver
            ),
            "Custom gpg.ssh.program on git-only chain must be covered"
        )
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: customSignerUnderShPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup,
                resolvedGpgSSHProgram: customResolver
            ),
            "Custom gpg.ssh.program on non-git chain must be refused"
        )

        // 5. PID reuse / changed start time: refused
        // a) Approved process PID reused with different start time
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderChildGitPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime &+ 1,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "Approved process with changed start time must be refused"
        )

        // b) Peer process PID reused with different start time
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderChildGitPid,
                peerStartTime: defaultStartTime &+ 1,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: processInfo,
                processPathLookup: pathLookup
            ),
            "Peer process with changed start time must be refused"
        )

        // c) Intermediate git process PID reused / missing snapshot
        var brokenProcesses = processes
        brokenProcesses[childGitPid] = nil
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: signerUnderChildGitPid,
                peerStartTime: defaultStartTime,
                approvedPid: approvedGitPid,
                approvedStartTime: approvedStartTime,
                processInfo: { brokenProcesses[$0] },
                processPathLookup: pathLookup
            ),
            "Missing intermediate process snapshot must be refused"
        )
    }

    @Test func testGitSigningGrantRejectsMismatchedOrRecycledPID() throws {
        let manager = GitSigningGraceManager(observeSystemEvents: false)
        let label = "git-anchor-test-\(UUID().uuidString)"
        let myPid = getpid()
        let mySnap = try #require(ProcessInspector.processParentSnapshot(pid: myPid), "Failed to get process snapshot for test runner")
        let approvedPid = myPid
        let approvedStart = mySnap.startTime
        let approvedPath = "/usr/bin/git"
        let approvedProcess = GitApprovedProcess(pid: approvedPid, startTime: approvedStart, path: approvedPath)

        let grant = manager.recordGrant(
            keyLabel: label,
            clientIdentity: approvedPath,
            duration: 300,
            maxOperations: 10,
            context: LAContext(),
            approvedProcess: approvedProcess
        )

        // Matching peer process must be accepted
        #expect(
            grant.consumeOperation(clientIdentity: approvedPath, peerProcess: approvedProcess),
            "Peer matching approved process must be allowed"
        )

        // 1. Peer with different PID must be rejected, even if executable path is /usr/bin/git
        let differentPidPeer = GitApprovedProcess(pid: myPid + 99999, startTime: approvedStart, path: approvedPath)
        #expect(
            !grant.consumeOperation(clientIdentity: approvedPath, peerProcess: differentPidPeer),
            "Peer with different PID must be rejected"
        )

        // 2. Peer with recycled PID (same PID, different start time) must be rejected
        let recycledPidPeer = GitApprovedProcess(pid: approvedPid, startTime: approvedStart + 10, path: approvedPath)
        #expect(
            !grant.consumeOperation(clientIdentity: approvedPath, peerProcess: recycledPidPeer),
            "Recycled PID with different start time must be rejected"
        )

        // 3. Fallback to bare string comparison must be rejected (no peer process provided)
        #expect(
            !grant.consumeOperation(clientIdentity: approvedPath, peerProcess: nil),
            "Missing peerProcess must fail closed and reject bare string match"
        )

        // 4. Grant without approvedProcess must reject consumeOperation even if clientIdentity matches
        let unanchoredGrant = manager.recordGrant(
            keyLabel: "unanchored-\(UUID().uuidString)",
            clientIdentity: approvedPath,
            duration: 300,
            maxOperations: 10,
            context: LAContext(),
            approvedProcess: nil
        )
        #expect(
            !unanchoredGrant.consumeOperation(clientIdentity: approvedPath, peerProcess: nil),
            "Unanchored grant without approvedProcess must fail closed on bare string comparison"
        )
        #expect(
            !unanchoredGrant.consumeOperation(clientIdentity: approvedPath, peerProcess: approvedProcess),
            "Unanchored grant must not allow client operations"
        )
    }

    @Test func testGitSigningGraceRejectsUntrustedExecutablePaths() {
        // 1. Allowlist rejects untrusted signer helpers (basename matching like /tmp/ssh-keygen is rejected)
        #expect(!ProcessInspector.isSignerHelper(path: "/tmp/ssh-keygen"), "/tmp/ssh-keygen must be rejected")
        #expect(!ProcessInspector.isSignerHelper(path: "/tmp/git"), "/tmp/git must be rejected as helper")
        #expect(!ProcessInspector.isSignerHelper(path: "/Users/test/.local/bin/ssh-keygen"), "Untrusted path must be rejected")

        // Canonical/trusted signer helper paths
        #expect(ProcessInspector.isSignerHelper(path: "/usr/bin/ssh-keygen"))
        #expect(ProcessInspector.isSignerHelper(path: "/usr/local/bin/ssh-keygen"))
        #expect(ProcessInspector.isSignerHelper(path: "/opt/homebrew/bin/ssh-keygen"))
        #expect(ProcessInspector.isSignerHelper(path: "/run/current-system/sw/bin/ssh-keygen"))
        #expect(ProcessInspector.isSignerHelper(path: "/nix/store/s0m3h4sh0123456789abcdef01234567-openssh-9.5/bin/ssh-keygen"))
        #expect(!ProcessInspector.isSignerHelper(path: "/nix/store/evil/sub/bin/ssh-keygen"))
        #expect(!ProcessInspector.isSignerHelper(path: "/nix/store/../../tmp/bin/ssh-keygen"))
        #expect(!ProcessInspector.isTrustedSshBinary(path: "/nix/store/evil/sub/bin/ssh"))
        #expect(!ProcessInspector.isTrustedSshBinary(path: "/nix/store/short-openssh/bin/ssh"))
        #expect(ProcessInspector.isTrustedSshBinary(path: "/nix/store/s0m3h4sh0123456789abcdef01234567-openssh-9.5/bin/ssh"))

        // 2. grantAnchor rejects untrusted git paths (e.g. /tmp/git)
        let mockProcesses: [pid_t: ProcessParentSnapshot] = [
            100: ProcessParentSnapshot(startTime: 1000, parentPid: 1),
            200: ProcessParentSnapshot(startTime: 2000, parentPid: 100)
        ]
        let mockPaths: [pid_t: String] = [
            100: "/tmp/git",
            200: "/usr/bin/ssh-keygen"
        ]
        let pInfo: (pid_t) -> ProcessParentSnapshot? = { mockProcesses[$0] }
        let pLookup: (pid_t) -> String? = { mockPaths[$0] }

        // Direct anchor on /tmp/git must be rejected
        #expect(
            ProcessInspector.grantAnchor(
                peerPid: 100,
                peerPath: "/tmp/git",
                processInfo: pInfo,
                processPathLookup: pLookup
            ) == nil,
            "Direct anchor on /tmp/git must be rejected"
        )

        // ssh-keygen child under /tmp/git parent must be rejected
        #expect(
            ProcessInspector.grantAnchor(
                peerPid: 200,
                peerPath: "/usr/bin/ssh-keygen",
                processInfo: pInfo,
                processPathLookup: pLookup
            ) == nil,
            "Signer helper under /tmp/git parent must be rejected"
        )

        // Direct anchor on canonical git paths must succeed
        for trustedGit in [
            "/usr/bin/git",
            "/usr/local/bin/git",
            "/opt/homebrew/bin/git",
            "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
            "/run/current-system/sw/bin/git",
            "/nix/store/s0m3h4sh0123456789abcdef01234567-git-2.42.0/bin/git"
        ] {
            let anchor = ProcessInspector.grantAnchor(
                peerPid: 100,
                peerPath: trustedGit,
                processInfo: { _ in ProcessParentSnapshot(startTime: 1000, parentPid: 1) },
                processPathLookup: { _ in trustedGit }
            )
            #expect(anchor != nil, "\(trustedGit) must be recognized as valid direct git anchor")
            #expect(anchor?.pid == 100)
            #expect(anchor?.startTime == 1000)
        }

        // 3. gitGrantCoversPeer rejects untrusted helper and untrusted intermediate git
        let untrustedHelperPid: pid_t = 300
        let untrustedGitPid: pid_t = 301
        let canonicalGitPid: pid_t = 302
        let coverProcesses: [pid_t: ProcessParentSnapshot] = [
            untrustedHelperPid: ProcessParentSnapshot(startTime: 3000, parentPid: canonicalGitPid),
            303: ProcessParentSnapshot(startTime: 3000, parentPid: untrustedGitPid),
            untrustedGitPid: ProcessParentSnapshot(startTime: 2500, parentPid: canonicalGitPid),
            canonicalGitPid: ProcessParentSnapshot(startTime: 2000, parentPid: 1)
        ]
        let coverPaths: [pid_t: String] = [
            untrustedHelperPid: "/tmp/ssh-keygen",
            303: "/usr/bin/ssh-keygen",
            untrustedGitPid: "/tmp/git",
            canonicalGitPid: "/usr/bin/git"
        ]

        // /tmp/ssh-keygen under /usr/bin/git -> rejected
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: untrustedHelperPid,
                peerStartTime: 3000,
                peerPath: "/tmp/ssh-keygen",
                approvedPid: canonicalGitPid,
                approvedStartTime: 2000,
                processInfo: { coverProcesses[$0] },
                processPathLookup: { coverPaths[$0] }
            ),
            "/tmp/ssh-keygen must be rejected by gitGrantCoversPeer"
        )

        // /usr/bin/ssh-keygen under /tmp/git -> rejected
        #expect(
            !ProcessInspector.gitGrantCoversPeer(
                peerPid: 303,
                peerStartTime: 3000,
                peerPath: "/usr/bin/ssh-keygen",
                approvedPid: canonicalGitPid,
                approvedStartTime: 2000,
                processInfo: { coverProcesses[$0] },
                processPathLookup: { coverPaths[$0] }
            ),
            "Intermediate /tmp/git must be rejected by gitGrantCoversPeer"
        )
    }

    @Test func test_F02_gitSigningGrantSignsWithoutKeychainReReadAndZeroizesBufferOnInvalidate() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = makeKeyManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "git-grant-f02-key",
            biometricPolicy: .userPresence,
            keyPurpose: .gitSigningOnly
        )

        let anchor = GitApprovedProcess(pid: 1234, startTime: 100, path: "/usr/bin/git")
        let grant = try manager.authorizeGitSigningGrant(
            key: key,
            prompt: "Authorize Git signing",
            clientIdentity: "/usr/bin/git",
            approvedProcess: anchor
        )

        #expect(store.loadCallCount == 1, "Initial authorization loads record once")
        #expect(grant.isValid, "Grant is active before invalidation")

        let hash256 = Data(repeating: 0x42, count: 32)
        let payload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: hash256)
        let dataToSign = payload.serialize()

        // Sign using grant
        let sigBlob = try grant.sign(dataToSign, using: manager)
        var reader = DataReader(data: sigBlob)
        #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
        guard let rawSig = reader.readWireData() else {
            Issue.record("Missing signature in wire blob")
            return
        }
        #expect(rawSig.count > 64)

        // Ensure store was not re-read
        #expect(store.loadCallCount == 1, "Grant signing must use grant-scoped hardware signer without re-reading store")

        // Invalidate grant
        grant.invalidate()
        #expect(!grant.isValid, "Grant must be invalid")
        #expect(throws: (any Error).self) {
            try grant.sign(dataToSign, using: manager)
        }
    }

    @Test func testCustomPresenterInjectionWithoutTouchingStaticState() throws {
        final class CustomPresenterSpy: GitSigningGracePresenter, @unchecked Sendable {
            struct Call: Equatable {
                let keyLabel: String
                let clientDesc: String
                let timeout: TimeInterval
            }
            private let lock = NSLock()
            private var _calls: [Call] = []
            var responseChoice: GitSigningPromptChoice = .grantFiveMinutes

            var calls: [Call] {
                lock.lock()
                defer { lock.unlock() }
                return _calls
            }

            func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
                lock.lock()
                _calls.append(Call(keyLabel: keyLabel, clientDesc: clientDesc, timeout: timeout))
                let choice = responseChoice
                lock.unlock()
                return choice
            }
        }

        let spy = CustomPresenterSpy()
        let customGraceManager = GitSigningGraceManager(observeSystemEvents: false, presenter: spy)

        // 1. Direct prompt on manager receives the call on injected presenter
        let choice1 = customGraceManager.prompt(keyLabel: "injected-key", clientDesc: "git (PID 4242)", timeout: 12.5)
        #expect(choice1 == .grantFiveMinutes)
        #expect(spy.calls.count == 1)
        #expect(spy.calls.first?.keyLabel == "injected-key")
        #expect(spy.calls.first?.clientDesc == "git (PID 4242)")
        #expect(spy.calls.first?.timeout == 12.5)

        // 2. Default timeout convenience method
        spy.responseChoice = .singleShot
        let choice2 = customGraceManager.prompt(keyLabel: "injected-key-2", clientDesc: "git (PID 4243)")
        #expect(choice2 == .singleShot)
        #expect(spy.calls.count == 2)
        #expect(spy.calls.last?.keyLabel == "injected-key-2")
        #expect(spy.calls.last?.clientDesc == "git (PID 4243)")
        #expect(spy.calls.last?.timeout == 30.0)

        // 3. Dependency injection into SSHAgentServer and KeychainManager:
        // Run full rebase flow through SSHAgentServer and verify prompt is received by spy
        // without touching static GitSigningGraceManager.promptProvider or GitSigningGraceManager.shared
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let keyManager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store,
            gitSigningGraceManager: customGraceManager
        )
        let server = SSHAgentServer(
            keyManager: keyManager,
            gitSigningGraceManager: customGraceManager
        )

        let label = "injected-rebase-\(UUID().uuidString)"
        let keyInfo = try keyManager.generateKey(label: label, keyPurpose: .general)

        let makeGitSignRequest: () -> Data = {
            let gitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x88, count: 32)).serialize()
            var req = Data()
            req.appendWireData(keyInfo.publicKeyBlob)
            req.appendWireData(gitPayload)
            var flags: UInt32 = 0
            Swift.withUnsafeBytes(of: &flags) { req.append(contentsOf: $0) }
            return req
        }

        // Reset spy responseChoice for server interaction
        spy.responseChoice = .grantFiveMinutes

        // Commit #1: standard Touch ID, no prompt
        let resp1 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(resp1.first == 14)
        #expect(spy.calls.count == 2, "Commit #1 must not trigger prompt")
        #expect(customGraceManager.getValidGrant(for: label) == nil)

        // Commit #2 within 30s: rapid signing triggers custom presenter prompt via SSHAgentServer!
        let resp2 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        #expect(resp2.first == 14)
        #expect(spy.calls.count == 3, "Commit #2 must route prompt directly through custom presenter")
        #expect(spy.calls.last?.keyLabel == label)

        // Verify active grant exists on injected manager and NOT on shared manager
        let activeGrant = try #require(customGraceManager.getValidGrant(for: label))
        #expect(activeGrant.isValid)
        #expect(GitSigningGraceManager.shared.getValidGrant(for: label) == nil, "Shared GitSigningGraceManager must not be touched")
    }
}

private final class PolicyCapturingAuthenticator: UserAuthenticating {
    private let lock = NSLock()
    private var recordedPolicies: [LAPolicy] = []
    private var recordedContexts: [LAContext] = []

    var policies: [LAPolicy] {
        lock.lock()
        defer { lock.unlock() }
        return recordedPolicies
    }

    var contexts: [LAContext] {
        lock.lock()
        defer { lock.unlock() }
        return recordedContexts
    }

    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext {
        capture(policy: policy)
    }

    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
        capture(policy: policy)
    }

    private func capture(policy: LAPolicy) -> LAContext {
        let context = LAContext()
        lock.lock()
        recordedPolicies.append(policy)
        recordedContexts.append(context)
        lock.unlock()
        return context
    }
}

private final class LoadFailingPrivateKeyStore: PrivateKeyStoring {
    private let inner = InMemoryPrivateKeyStore()
    private let lock = NSLock()
    private var loads = 0
    private let failOnLoadNumber: Int

    init(failOnLoadNumber: Int) {
        self.failOnLoadNumber = failOnLoadNumber
    }

    func contains(label: String) -> Bool {
        inner.contains(label: label)
    }

    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags) throws {
        try inner.save(label: label, data: data, accessControlFlags: accessControlFlags)
    }

    func load(label: String, context: LAContext, prompt: String) throws -> Data? {
        lock.lock()
        loads += 1
        let shouldFail = loads >= failOnLoadNumber
        lock.unlock()
        if shouldFail {
            throw NSError(
                domain: "ClavisTest",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "injected private-key load failure"]
            )
        }
        return try inner.load(label: label, context: context, prompt: prompt)
    }

    func remove(label: String, context: LAContext?, prompt: String) throws {
        try inner.remove(label: label, context: context, prompt: prompt)
    }
}
