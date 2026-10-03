import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class GitSigningGraceTests: ClavisBaseTestCase {

    func testSSHSIGPayloadStrictParsing() throws {
        // Valid Git SSHSIG payload (sha256)
        let hash256 = Data(repeating: 0x42, count: 32)
        let payload256 = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: hash256)
        let wire256 = payload256.serialize()

        let parsed = SSHSIGPayload.parse(from: wire256)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.namespace, "git")
        XCTAssertEqual(parsed?.hashAlgorithm, "sha256")
        XCTAssertEqual(parsed?.messageHash, hash256)

        // Valid Git SSHSIG payload (sha512)
        let hash512 = Data(repeating: 0x99, count: 64)
        let payload512 = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha512", messageHash: hash512)
        let wire512 = payload512.serialize()
        let parsed512 = SSHSIGPayload.parse(from: wire512)
        XCTAssertNotNil(parsed512)
        XCTAssertEqual(parsed512?.hashAlgorithm, "sha512")
        XCTAssertEqual(parsed512?.messageHash, hash512)

        // 1. Wrong magic
        var badMagic = wire256
        badMagic[0] = 0x58
        XCTAssertNil(SSHSIGPayload.parse(from: badMagic))

        // 2. Non-git namespace
        let filePayload = SSHSIGPayload(namespace: "file", hashAlgorithm: "sha256", messageHash: hash256)
        XCTAssertNil(SSHSIGPayload.parse(from: filePayload.serialize()))

        // 3. Invalid hash length (31 bytes for sha256)
        var invalidLenWire = SSHSIGPayload.magic
        invalidLenWire.appendWireString("git")
        invalidLenWire.appendWireString("")
        invalidLenWire.appendWireString("sha256")
        invalidLenWire.appendWireData(Data(repeating: 0x01, count: 31))
        XCTAssertNil(SSHSIGPayload.parse(from: invalidLenWire))

        // 4. Trailing garbage bytes (fail closed)
        var trailingGarbageWire = wire256
        trailingGarbageWire.append(Data([0x00, 0x01, 0x02]))
        XCTAssertNil(SSHSIGPayload.parse(from: trailingGarbageWire))

        // 5. Non-empty reserved field
        var badReservedWire = SSHSIGPayload.magic
        badReservedWire.appendWireString("git")
        badReservedWire.appendWireString("reserved-data")
        badReservedWire.appendWireString("sha256")
        badReservedWire.appendWireData(hash256)
        XCTAssertNil(SSHSIGPayload.parse(from: badReservedWire))

        // 6. Arbitrary non-SSHSIG payload
        let sshAuthPayload = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        XCTAssertNil(SSHSIGPayload.parse(from: sshAuthPayload))
    }


    func testGitSigningGrantLifecycle() throws {
        let label = "grant-test-\(UUID().uuidString)"
        let grant = GitSigningGrant(keyLabel: label, duration: 0.2, maxOperations: 3)

        XCTAssertTrue(grant.isValid)
        XCTAssertEqual(grant.remainingOperations, 3)

        // Consume operations
        XCTAssertTrue(grant.consumeOperation(clientIdentity: "test-client"))
        XCTAssertEqual(grant.remainingOperations, 2)
        XCTAssertTrue(grant.consumeOperation(clientIdentity: "test-client"))
        XCTAssertEqual(grant.remainingOperations, 1)
        XCTAssertTrue(grant.consumeOperation(clientIdentity: "test-client"))
        XCTAssertEqual(grant.remainingOperations, 0)

        // Exceeded operation limit
        XCTAssertFalse(grant.consumeOperation(clientIdentity: "test-client"))
        XCTAssertFalse(grant.isValid)

        // Expiry by time
        let timeGrant = GitSigningGrant(keyLabel: label, duration: 0.05, maxOperations: 100)
        XCTAssertTrue(timeGrant.isValid)
        usleep(70_000)
        XCTAssertFalse(timeGrant.isValid)
        XCTAssertFalse(timeGrant.consumeOperation(clientIdentity: "test-client"))
    }


    func testGitSigningGraceManagerRebaseFlow() throws {
        let graceManager = GitSigningGraceManager(observeSystemEvents: false)
        let label = "rebase-key-\(UUID().uuidString)"

        // Step 1: First commit
        XCTAssertFalse(graceManager.hasRecentGitSignature(for: label))
        graceManager.recordGitSignature(for: label)
        XCTAssertTrue(graceManager.hasRecentGitSignature(for: label, windowSeconds: 2.0))

        // Step 2: Second commit within window (<30s) prompts user
        var promptCalled = false
        GitSigningGraceManager.promptProvider = { keyLabel, clientDesc in
            promptCalled = true
            return .grantFiveMinutes
        }
        defer {
            GitSigningGraceManager.promptProvider = { label, clientDesc in
                GitSigningPrompt.displayModal(keyLabel: label, clientDesc: clientDesc)
            }
        }

        let choice = GitSigningGraceManager.promptProvider(label, "git (PID 1234)")
        XCTAssertTrue(promptCalled)
        XCTAssertEqual(choice, .grantFiveMinutes)

        // Issue grant
        let grant = graceManager.recordGrant(
            keyLabel: label,
            clientIdentity: "/usr/bin/git",
            duration: 300,
            maxOperations: 50,
            context: LAContext()
        )
        XCTAssertNotNil(graceManager.getValidGrant(for: label))
        XCTAssertEqual(grant.remainingOperations, 50)

        // Step 3: Subsequent rebase commits consume grant
        let result = graceManager.withGrant(for: label, clientIdentity: "/usr/bin/git") { _ in "signed" }
        XCTAssertEqual(result, "signed")
        XCTAssertEqual(grant.remainingOperations, 49)
        XCTAssertNil(
            graceManager.withGrant(for: label, clientIdentity: "/tmp/fake-git") { _ in "signed" },
            "A grant must not be transferable to another client identity"
        )

        // Invalidation clears grant
        graceManager.invalidateAll(broadcast: false)
        XCTAssertNil(graceManager.getValidGrant(for: label))
    }


    func testKeyPurposeDomainIsolation() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let manager = KeychainManager(authenticator: authenticator, privateKeyStore: store)

        let label = "git-only-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .gitSigningOnly)
        XCTAssertEqual(keyInfo.purpose, .gitSigningOnly)

        // Verify stored record preserves purpose
        let loaded = try XCTUnwrap(store.load(label: label, context: LAContext(), prompt: ""))
        let record = try StoredPrivateKeyRecord.decode(from: loaded)
        XCTAssertEqual(record.purpose, .gitSigningOnly)

        // SSH Agent identities answer must EXCLUDE gitSigningOnly keys
        let server = SSHAgentServer(keyManager: manager)
        let identitiesData = server.handleRequestIdentities()
        XCTAssertFalse(identitiesData.isEmpty)
        let blobInIdentities = identitiesData.range(of: keyInfo.publicKeyBlob) != nil
        XCTAssertFalse(blobInIdentities, "Git-only key must never be advertised in SSH identities listing")

        // Signing non-Git payload with git-only key must be REJECTED (Data([5]))
        var signRequestWire = Data()
        signRequestWire.appendWireData(keyInfo.publicKeyBlob)
        signRequestWire.appendWireData(Data("ssh-userauth-challenge".utf8))
        var flags: UInt32 = 0
        Swift.withUnsafeBytes(of: &flags) { signRequestWire.append(contentsOf: $0) }

        let response = server.handleSignRequest(payload: signRequestWire, clientPid: getpid())
        XCTAssertEqual(response, Data([5]), "Non-Git payload must be strictly rejected for gitSigningOnly key")

        // Signing valid Git SSHSIG payload must SUCCEED
        let validGitPayload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x55, count: 32)).serialize()
        var validSignRequest = Data()
        validSignRequest.appendWireData(keyInfo.publicKeyBlob)
        validSignRequest.appendWireData(validGitPayload)
        Swift.withUnsafeBytes(of: &flags) { validSignRequest.append(contentsOf: $0) }

        let gitResponse = server.handleSignRequest(payload: validSignRequest, clientPid: getpid())
        XCTAssertEqual(gitResponse.first, 14, "Git SSHSIG payload must be signed successfully")
    }

    func testTamperedPublicPurposeCannotBroadenGitOnlyKey() throws {
        let store = InMemoryPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            sessionCache: makeSessionCache()
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

        // Prime the cache with the authoritative Git-only purpose.
        _ = try manager.signSSH(key: original, data: gitPayload, prompt: "Git", useCache: true)

        let tampered = Ed25519KeyInfo(
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

        XCTAssertThrowsError(
            try manager.signSSH(
                key: tampered,
                data: Data("ssh-userauth-challenge".utf8),
                prompt: "SSH",
                useCache: true
            )
        ) { error in
            guard case PrivateKeyRecordError.purposeMismatch(let expected, let actual) = error else {
                return XCTFail("Expected purposeMismatch, got \(error)")
            }
            XCTAssertEqual(expected, KeyPurpose.general.rawValue)
            XCTAssertEqual(actual, KeyPurpose.gitSigningOnly.rawValue)
        }

        XCTAssertThrowsError(
            try manager.authorizeGitSigningGrant(
                key: tampered,
                prompt: "Grant",
                clientIdentity: "/usr/bin/git"
            )
        ) { error in
            guard case PrivateKeyRecordError.purposeMismatch = error else {
                return XCTFail("Expected purposeMismatch, got \(error)")
            }
        }
    }

    func testGitOnlyKeyCannotBeUsedForAgeOrGenericSigning() throws {
        let manager = makeKeyManager()
        let key = try manager.generateKey(
            label: "git-only-operations-\(UUID().uuidString)",
            keyPurpose: .gitSigningOnly
        )

        XCTAssertFalse(key.isAgeCompatible)
        XCTAssertThrowsError(
            try manager.unwrapAgeFileKey(
                label: key.label,
                prompt: "Age",
                wrappedKey: Data(),
                epkB64: ""
            )
        ) { error in
            guard case PrivateKeyRecordError.purposeNotAllowed = error else {
                return XCTFail("Expected purposeNotAllowed, got \(error)")
            }
        }
        XCTAssertThrowsError(
            try manager.sign(
                label: key.label,
                data: Data("arbitrary".utf8),
                prompt: "Generic",
                useCache: true
            )
        ) { error in
            guard case PrivateKeyRecordError.purposeNotAllowed = error else {
                return XCTFail("Expected purposeNotAllowed, got \(error)")
            }
        }
    }


    func testSSHAgentServerRebaseGraceFlow() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let manager = KeychainManager(authenticator: authenticator, privateKeyStore: store)
        let server = SSHAgentServer(keyManager: manager)

        let label = "rebase-flow-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        var promptCount = 0
        GitSigningGraceManager.promptProvider = { _, _ in
            promptCount += 1
            return .grantFiveMinutes
        }
        defer {
            GitSigningGraceManager.promptProvider = { l, c in
                GitSigningPrompt.displayModal(keyLabel: l, clientDesc: c)
            }
            GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        }

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
        XCTAssertEqual(resp1.first, 14)
        XCTAssertEqual(authenticator.authenticationCount, 1, "First commit requires standard single Touch ID")
        XCTAssertEqual(promptCount, 0, "First commit must not show modal dialog")
        XCTAssertNil(GitSigningGraceManager.shared.getValidGrant(for: label), "No grant issued on first single commit")

        // Commit #2: Repeated commit within 30s (Rebase detected!)
        let resp2 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        XCTAssertEqual(resp2.first, 14)
        XCTAssertEqual(promptCount, 1, "Second commit within 30s must trigger session dialog")
        XCTAssertEqual(authenticator.authenticationCount, 2, "Second commit requires Touch ID to authorize 5-minute grant")

        let activeGrant = try XCTUnwrap(GitSigningGraceManager.shared.getValidGrant(for: label))
        XCTAssertTrue(activeGrant.isValid)
        XCTAssertEqual(activeGrant.remainingOperations, 199, "Commit #2 consumes 1 operation of the 200 grant")

        // Commit #3: Subsequent commit during rebase
        let resp3 = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        XCTAssertEqual(resp3.first, 14)
        XCTAssertEqual(authenticator.authenticationCount, 2, "Third commit must NOT prompt Touch ID (0 prompts)")
        XCTAssertEqual(promptCount, 1, "Third commit must NOT show dialog")
        XCTAssertEqual(activeGrant.remainingOperations, 198, "Commit #3 consumes another operation")

        // Invalidation (e.g. End Session / Screen Lock)
        GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        XCTAssertNil(GitSigningGraceManager.shared.getValidGrant(for: label))
    }

    func testResolveClientIdentityDifferentiatesProcesses() {
        let currentPid = getpid()
        guard let currentPath = SSHAgentServer.getProcessPath(pid: currentPid) else {
            return
        }

        let identity1 = SSHAgentServer.resolveClientIdentity(pid: currentPid, processPath: currentPath)
        let identity2 = SSHAgentServer.resolveClientIdentity(pid: currentPid, processPath: currentPath)

        // Same process call must produce identical identity
        XCTAssertEqual(identity1, identity2)
        XCTAssertTrue(identity1.contains(currentPath))

        // Different executable paths or different processes must produce distinct identities
        let fakeIdentity = SSHAgentServer.resolveClientIdentity(pid: currentPid, processPath: "/usr/bin/git")
        XCTAssertNotEqual(identity1, fakeIdentity)

        // PID 1 (launchd) has no parent or init parent, must differ from current process
        if let launchdPath = SSHAgentServer.getProcessPath(pid: 1) {
            let launchdIdentity = SSHAgentServer.resolveClientIdentity(pid: 1, processPath: launchdPath)
            XCTAssertNotEqual(identity1, launchdIdentity)
        }
    }

    func testSameParentDoesNotInheritGitSigningGrant() {
        let shell: pid_t = 10
        let approvedGit: pid_t = 20
        let siblingGit: pid_t = 21
        let hook: pid_t = 30
        let shellStart: UInt64 = 1_000
        let approvedStart: UInt64 = 2_000
        let siblingStart: UInt64 = 2_100
        let hookStart: UInt64 = 3_000

        let processes: [pid_t: ProcessParentSnapshot] = [
            1: ProcessParentSnapshot(startTime: 1, parentPid: 0),
            shell: ProcessParentSnapshot(startTime: shellStart, parentPid: 1),
            approvedGit: ProcessParentSnapshot(startTime: approvedStart, parentPid: shell),
            siblingGit: ProcessParentSnapshot(startTime: siblingStart, parentPid: shell),
            hook: ProcessParentSnapshot(startTime: hookStart, parentPid: approvedGit),
        ]
        let lookup: (pid_t) -> ProcessParentSnapshot? = { processes[$0] }

        XCTAssertTrue(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: approvedGit,
                peerStartTime: approvedStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup
            ),
            "The approved git process keeps its own grant"
        )
        XCTAssertTrue(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: hook,
                peerStartTime: hookStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup
            ),
            "A child of the approved git, such as a rebase helper or hook, keeps the grant"
        )
        XCTAssertFalse(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: siblingGit,
                peerStartTime: siblingStart,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: lookup
            ),
            "A new git started by the same shell must not inherit the grant"
        )

        var reused = processes
        reused[approvedGit] = ProcessParentSnapshot(startTime: approvedStart &+ 1, parentPid: shell)
        XCTAssertFalse(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: approvedGit,
                peerStartTime: approvedStart &+ 1,
                approvedPid: approvedGit,
                approvedStartTime: approvedStart,
                processInfo: { reused[$0] }
            ),
            "A recycled PID must not inherit the grant approved for the previous instance"
        )
    }

    func testGitGrantAnchorModelsRealProcessShape() {
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
        guard let anchor = SSHAgentServer.grantAnchor(
            peerPid: signer2Pid,
            peerPath: processPaths[signer2Pid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        ) else {
            XCTFail("grantAnchor must succeed for signer #2 under git G")
            return
        }

        XCTAssertEqual(anchor.pid, gitGPid, "Anchor PID must be parent git G")
        XCTAssertEqual(anchor.startTime, gitGStart, "Anchor start time must match git G")
        XCTAssertEqual(anchor.path, "/usr/bin/git", "Anchor path must match parent git")

        // Peer signer #3 (same parent G) is covered
        let signer3 = GitApprovedProcess(pid: signer3Pid, startTime: signer3Start)
        XCTAssertTrue(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: signer3.pid,
                peerStartTime: signer3.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: processInfo
            ),
            "Peer signer #3 under the same git G must be covered by the anchor grant"
        )

        // Signer under different git is NOT covered
        let signerDifferentGit = GitApprovedProcess(
            pid: signerUnderDifferentGitPid,
            startTime: signerDifferentGitStart
        )
        XCTAssertFalse(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: signerDifferentGit.pid,
                peerStartTime: signerDifferentGit.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: processInfo
            ),
            "Signer under a different git G2 must NOT be covered by the anchor grant"
        )

        // Recycled git pid is NOT covered
        var recycledProcesses = processes
        recycledProcesses[gitGPid] = ProcessParentSnapshot(startTime: gitGStart &+ 1, parentPid: shellPid)
        XCTAssertFalse(
            SSHAgentServer.gitGrantCoversPeer(
                peerPid: signer3.pid,
                peerStartTime: signer3.startTime,
                approvedPid: anchor.pid,
                approvedStartTime: anchor.startTime,
                processInfo: { recycledProcesses[$0] }
            ),
            "Recycled git pid must NOT be covered"
        )

        // Anchor on shell is refused
        let shellSignerAnchor = SSHAgentServer.grantAnchor(
            peerPid: shellSignerPid,
            peerPath: processPaths[shellSignerPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        XCTAssertNil(shellSignerAnchor, "Anchor on shell must be refused when signer parent is a shell")

        let directShellAnchor = SSHAgentServer.grantAnchor(
            peerPid: shellPid,
            peerPath: processPaths[shellPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        XCTAssertNil(directShellAnchor, "Anchor directly on shell must be refused")

        let launchdAnchor = SSHAgentServer.grantAnchor(
            peerPid: 1,
            peerPath: processPaths[1]!,
            processInfo: processInfo,
            processPathLookup: pathLookup
        )
        XCTAssertNil(launchdAnchor, "Anchor on launchd must be refused")
    }

    func testCustomGpgSSHProgramResolvedAsKnownHelper() {
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

        let customAnchor = SSHAgentServer.grantAnchor(
            peerPid: customSignerPid,
            peerPath: paths[customSignerPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup,
            resolvedGpgSSHProgram: customResolver
        )
        XCTAssertNotNil(customAnchor)
        XCTAssertEqual(customAnchor?.pid, gitPid)
        XCTAssertEqual(customAnchor?.startTime, 200)
        XCTAssertEqual(customAnchor?.path, "/usr/local/bin/git")

        // Unknown program (e.g. curl) under git is NOT a known signer helper
        let unknownAnchor = SSHAgentServer.grantAnchor(
            peerPid: unknownProgPid,
            peerPath: paths[unknownProgPid]!,
            processInfo: processInfo,
            processPathLookup: pathLookup,
            resolvedGpgSSHProgram: customResolver
        )
        XCTAssertNil(unknownAnchor, "Unknown program that is not a signer helper must be refused as an anchor helper")
    }

    func testResolveGpgSSHProgramTimesOutAndKillsHangingProcess() throws {
        let scriptURL = testRootURL.appendingPathComponent("hanging-git.sh")
        let scriptContent = "#!/bin/sh\nsleep 10\n"
        try scriptContent.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let start = Date()
        let result = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptURL.path, timeout: 0.3)
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertNil(result, "resolveGpgSSHProgram must return nil on timeout")
        XCTAssertGreaterThanOrEqual(elapsed, 0.28, "Must wait for the timeout duration")
        XCTAssertLessThan(elapsed, 2.0, "Must terminate child process without hanging until sleep completes")
    }

    func testResolveGpgSSHProgramParsesOutputSuccessfully() throws {
        let scriptURL = testRootURL.appendingPathComponent("mock-git.sh")
        let scriptContent = "#!/bin/sh\necho \"  /opt/bin/mock-signer  \"\n"
        try scriptContent.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let result = SSHAgentServer.resolveGpgSSHProgram(gitExecutablePath: scriptURL.path, timeout: 2.0)
        XCTAssertEqual(result, "/opt/bin/mock-signer")
    }

    func testCycleSafeAncestorWalk() {
        // Model an adversarial or corrupted cycle: PID 100 -> 101 -> 100
        let processes: [pid_t: ProcessParentSnapshot] = [
            100: ProcessParentSnapshot(startTime: 1000, parentPid: 101),
            101: ProcessParentSnapshot(startTime: 1001, parentPid: 100),
        ]
        let covered = SSHAgentServer.gitGrantCoversPeer(
            peerPid: 100,
            peerStartTime: 1000,
            approvedPid: 200,
            approvedStartTime: 2000,
            processInfo: { processes[$0] }
        )
        XCTAssertFalse(covered, "Cycle in process tree must terminate safely and return false")
    }

    func testRefusedAnchorsOnAllShellsAndTerminals() {
        let refusedNames = [
            "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
            "Terminal", "iTerm", "iTerm2", "kitty", "alacritty", "wezterm", "tmux", "screen", "login",
            "launchd"
        ]
        for name in refusedNames {
            let path = "/usr/bin/\(name)"
            let refused = SSHAgentServer.isRefusedAnchor(pid: 42, path: path)
            XCTAssertTrue(refused, "Executable named \(name) must be recognized as refused anchor")

            let anchor = SSHAgentServer.grantAnchor(
                peerPid: 42,
                peerPath: path,
                processInfo: { _ in ProcessParentSnapshot(startTime: 100, parentPid: 1) },
                processPathLookup: { _ in "/bin/bash" }
            )
            XCTAssertNil(anchor, "grantAnchor must refuse \(name)")
        }
    }

    func testGrantAnchorAcceptsGitAndXCTestInDebug() {
        let gitPid: pid_t = 100
        let gitPath = "/nix/store/abc-git-2.40.0/bin/git"
        let gitAnchor = SSHAgentServer.grantAnchor(
            peerPid: gitPid,
            peerPath: gitPath,
            processInfo: { _ in ProcessParentSnapshot(startTime: 1000, parentPid: 1) },
            processPathLookup: { _ in gitPath }
        )
        XCTAssertNotNil(gitAnchor, "grantAnchor must accept git with arbitrary Nix store path")
        XCTAssertEqual(gitAnchor?.pid, gitPid)

        let xctestPid: pid_t = 200
        let xctestPath = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/Library/Xcode/Agents/xctest"
        let xctestAnchor = SSHAgentServer.grantAnchor(
            peerPid: xctestPid,
            peerPath: xctestPath,
            processInfo: { _ in ProcessParentSnapshot(startTime: 2000, parentPid: 1) },
            processPathLookup: { _ in xctestPath }
        )
        #if DEBUG
        XCTAssertNotNil(xctestAnchor, "xctest must be accepted as an anchor in DEBUG builds")
        XCTAssertEqual(xctestAnchor?.pid, xctestPid)
        #else
        XCTAssertNil(xctestAnchor, "xctest must NOT be accepted as an anchor in release builds")
        #endif
    }

    func testGitSigningPromptBypassesModalInHeadlessSession() {
        let previousProvider = GitSigningPrompt.sessionCheckProvider
        defer { GitSigningPrompt.sessionCheckProvider = previousProvider }

        // Simulate headless/non-GUI environment
        GitSigningPrompt.sessionCheckProvider = { false }

        let start = Date()
        let choice = GitSigningPrompt.displayModal(keyLabel: "test-key", clientDesc: "git (PID 9999)")
        let elapsed = Date().timeIntervalSince(start)

        // Must return .singleShot immediately (< 0.5s), avoiding the 30-second CFUserNotificationDisplayAlert hang
        XCTAssertEqual(choice, .singleShot)
        XCTAssertLessThan(elapsed, 0.5)
    }

    func testModalDefaultButtonIsTheLeastPrivilegedChoice() {
        // Return / default button must never start an unattended signing session.
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse)),
            .singleShot
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationAlternateResponse)),
            .cancel
        )
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationOtherResponse)),
            .grantFiveMinutes
        )
    }

    func testModalTimeoutAndUnknownResponsesCancel() {
        // CFUserNotification reports a timeout / dismissal as the cancel response (3).
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationCancelResponse)),
            .cancel
        )
        // Only the low two bits carry the response; higher flag bits must not change the outcome.
        XCTAssertEqual(
            GitSigningPrompt.choice(forResponseFlags: CFOptionFlags(kCFUserNotificationDefaultResponse) | 0x100),
            .singleShot
        )
    }

    func testAuthorizeGitSigningGrantUsesBiometricsForCurrentSet() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = PolicyCapturingAuthenticator()
        let manager = KeychainManager(authenticator: authenticator, privateKeyStore: store)
        defer { GitSigningGraceManager.shared.invalidateAll(broadcast: false) }

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

        XCTAssertEqual(authenticator.policies, [.deviceOwnerAuthenticationWithBiometrics])
        XCTAssertEqual(GitSigningGraceManager.shared.getValidGrant(for: label)?.keyLabel, grant.keyLabel)
        XCTAssertTrue(grant.isValid)
    }

    func testAuthorizeGitSigningGrantRejectsWeakerContextForStrictRecord() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = PolicyCapturingAuthenticator()
        let manager = KeychainManager(authenticator: authenticator, privateKeyStore: store)
        defer { GitSigningGraceManager.shared.invalidateAll(broadcast: false) }

        let label = "downgraded-grant-\(UUID().uuidString)"
        let key = try installEd25519Record(
            store: store,
            label: label,
            recordPolicy: .biometryCurrentSet,
            publishedPolicy: .userPresence
        )

        XCTAssertThrowsError(
            try manager.authorizeGitSigningGrant(
                key: key,
                prompt: "Grant",
                clientIdentity: "/usr/bin/git"
            )
        ) { error in
            guard case PrivateKeyRecordError.metadataMismatch(let field, let expected, let actual) = error else {
                return XCTFail("Expected metadataMismatch, got \(error)")
            }
            XCTAssertEqual(field, "biometricPolicy")
            XCTAssertEqual(expected, BiometricPolicy.userPresence.rawValue)
            XCTAssertEqual(actual, BiometricPolicy.biometryCurrentSet.rawValue)
        }

        XCTAssertEqual(authenticator.policies, [.deviceOwnerAuthentication])
        XCTAssertNil(GitSigningGraceManager.shared.getValidGrant(for: label))

        let context = try XCTUnwrap(authenticator.contexts.last)
        context.interactionNotAllowed = true
        let evaluated = expectation(description: "invalidated context cannot be reused")
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "reuse") { success, error in
            XCTAssertFalse(success)
            XCTAssertEqual((error as? LAError)?.code, .invalidContext)
            evaluated.fulfill()
        }
        wait(for: [evaluated], timeout: 2)
    }

    func testFailedSignatureUnderNewGrantInvalidatesGrant() throws {
        let store = LoadFailingPrivateKeyStore(failOnLoadNumber: 3)
        let manager = KeychainManager(authenticator: CountingAuthenticator(), privateKeyStore: store)
        let server = SSHAgentServer(keyManager: manager)
        let label = "grant-fail-\(UUID().uuidString)"
        let keyInfo = try manager.generateKey(label: label, keyPurpose: .general)

        GitSigningGraceManager.promptProvider = { _, _ in .grantFiveMinutes }
        defer {
            GitSigningGraceManager.promptProvider = { keyLabel, clientDesc in
                GitSigningPrompt.displayModal(keyLabel: keyLabel, clientDesc: clientDesc)
            }
            GitSigningGraceManager.shared.invalidateAll(broadcast: false)
        }

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
        XCTAssertEqual(first.first, 14)

        let second = server.handleSignRequest(payload: makeGitSignRequest(), clientPid: getpid())
        XCTAssertEqual(second, Data([5]))
        XCTAssertNil(
            GitSigningGraceManager.shared.getValidGrant(for: label),
            "A signature failure under a new grant must invalidate that grant"
        )
    }

    private func installEd25519Record(
        store: InMemoryPrivateKeyStore,
        label: String,
        recordPolicy: BiometricPolicy?,
        publishedPolicy: BiometricPolicy?
    ) throws -> Ed25519KeyInfo {
        let privateKey = Curve25519.Signing.PrivateKey()
        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: recordPolicy,
            keyPurpose: .general,
            keyData: privateKey.rawRepresentation
        )
        defer { record.wipe() }
        try store.save(label: label, data: try record.encode())
        let blob = try KeychainManager.derivePublicKeyBlob(record: record)
        return Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 \(blob.base64EncodedString()) \(label)",
            publicKeyBlob: blob,
            fingerprint: "SHA256:test",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain,
            biometricPolicy: publishedPolicy,
            keyPurpose: .general
        )
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
