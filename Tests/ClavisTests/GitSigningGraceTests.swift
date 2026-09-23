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
}
