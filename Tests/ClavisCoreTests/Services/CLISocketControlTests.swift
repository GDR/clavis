import Foundation
import Testing
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("CLISocketControlTests")
struct CLISocketControlTests {
    private struct Harness {
        let fixture: ClavisTestFixture
        let socketDirURL: URL
        let sockPath: String
        let pinStore: InMemoryMasterKeyPinStore
        let vaultStore: EncryptedVaultStore
        let privateKeyStore: InMemoryPrivateKeyStore
        let authenticator: CountingAuthenticator
        let promptGate: SigningPromptGate
        let gitGrace: GitSigningGraceManager
        let sessions: AgentSessionRegistry
        let generations: KeyPolicyGenerations
        let auditRecorder: InMemoryAuditRecorder
        let keyManager: KeychainManager
        let server: SSHAgentServer
        let lifecycle: AgentLifecycleManager

        init(
            role: AgentSocketRole = .personal,
            controlPeerValidator: @escaping (Int32) -> Bool = { _ in true },
            peerProcessValidator: @escaping (pid_t, String, UInt64) -> Bool = { _, _, _ in true },
            promptGate: SigningPromptGate = SigningPromptGate(),
            customAuthenticator: UserAuthenticating? = nil,
            keyAgreementProvider: SecureEnclaveKeyAgreementProviding? = nil,
            startServer: Bool = true
        ) throws {
            let fixture = try ClavisTestFixture()
            let socketDirURL = URL(
                fileURLWithPath: "/tmp/clavis-cli-\(UUID().uuidString.prefix(8))",
                isDirectory: true
            )
            try FileManager.default.createDirectory(
                at: socketDirURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let sockPath = socketDirURL.appendingPathComponent("cli.sock").path
            let pinStore = InMemoryMasterKeyPinStore()
            let vaultStore = EncryptedVaultStore(
                vaultDirectoryURL: fixture.context.vaultDirectoryURL,
                pinStore: pinStore,
                keyAgreementProvider: keyAgreementProvider ?? fixture.context.keyAgreementProvider
            )
            let privateKeyStore = InMemoryPrivateKeyStore()
            let countingAuthenticator = CountingAuthenticator()
            let resolvedAuthenticator: UserAuthenticating = customAuthenticator ?? countingAuthenticator
            let gitGrace = GitSigningGraceManager(observeSystemEvents: false)
            let auditRecorder = InMemoryAuditRecorder()
            let sessions = AgentSessionRegistry(auditRecorder: auditRecorder, watchRootExit: false)
            let generations = KeyPolicyGenerations()
            let keyManager = fixture.makeKeyManager(
                authenticator: resolvedAuthenticator,
                privateKeyStore: privateKeyStore,
                vaultStore: vaultStore,
                agentGrantRevoker: { label in
                    Issue.record("agentGrantRevoker must not be invoked inside daemon CLI control for '\(label)'")
                },
                auditRecorder: auditRecorder,
                gitSigningGraceManager: gitGrace
            )
            let server = SSHAgentServer(
                applicationAccess: TestApplicationAccess(),
                keyPolicyGenerations: generations,
                socketPath: sockPath,
                role: role,
                keyManager: keyManager,
                vaultStore: vaultStore,
                promptGate: promptGate,
                gitSigningGraceManager: gitGrace,
                controlPeerValidator: controlPeerValidator,
                peerProcessValidator: peerProcessValidator,
                auditRecorder: auditRecorder,
                agentSessions: sessions,
                agentPolicies: InMemoryAgentPolicyStore(),
                authenticator: resolvedAuthenticator,
                testContext: fixture.context
            )
            if startServer {
                try server.start()
            }
            let lifecycle = AgentLifecycleManager(
                socketPath: sockPath,
                isTrustedServerPeer: { _ in true }
            )

            self.fixture = fixture
            self.socketDirURL = socketDirURL
            self.sockPath = sockPath
            self.pinStore = pinStore
            self.vaultStore = vaultStore
            self.privateKeyStore = privateKeyStore
            self.authenticator = countingAuthenticator
            self.promptGate = promptGate
            self.gitGrace = gitGrace
            self.sessions = sessions
            self.generations = generations
            self.auditRecorder = auditRecorder
            self.keyManager = keyManager
            self.server = server
            self.lifecycle = lifecycle
        }

        func cleanup() {
            server.stop()
            try? FileManager.default.removeItem(at: socketDirURL)
            fixture.cleanup()
        }
    }

    @Test func testSocketOnlyListAndExportPub() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            let emptyList = CLIService.handleSocketOnly(
                args: ["clavis", "list"],
                agentLifecycle: harness.lifecycle
            )
            #expect(emptyList?.exitCode == 0)
            #expect(emptyList?.output == CLIMessages.noKeysFound())

            let missingUsage = CLIService.handleSocketOnly(
                args: ["clavis", "export-pub"],
                agentLifecycle: harness.lifecycle
            )
            #expect(missingUsage?.exitCode == 1)
            #expect(missingUsage?.error == CLIMessages.usage(for: .exportPub))

            let generated = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "cli-key"],
                agentLifecycle: harness.lifecycle
            )
            #expect(generated?.exitCode == 0)
            #expect(generated?.output.contains("Successfully generated key 'cli-key'") == true)

            let expectedInfo = try #require(try harness.keyManager.fetchKeyInfo(label: "cli-key"))

            let populatedList = CLIService.handleSocketOnly(
                args: ["clavis", "list"],
                agentLifecycle: harness.lifecycle
            )
            #expect(populatedList?.exitCode == 0)
            #expect(populatedList?.output.contains("Found 1 key(s) in Keychain:") == true)
            #expect(populatedList?.output.contains(" - [cli-key]") == true)
            #expect(populatedList?.output.contains(expectedInfo.fingerprint) == true)
            #expect(populatedList?.output.contains(expectedInfo.publicKeyOpenSSH) == true)

            let exported = CLIService.handleSocketOnly(
                args: ["clavis", "export-pub", "cli-key"],
                agentLifecycle: harness.lifecycle
            )
            #expect(exported?.exitCode == 0)
            #expect(exported?.output == expectedInfo.publicKeyOpenSSH)

            let missingKey = CLIService.handleSocketOnly(
                args: ["clavis", "export-pub", "does-not-exist"],
                agentLifecycle: harness.lifecycle
            )
            #expect(missingKey?.exitCode == 1)
            #expect(missingKey?.error == CLIMessages.keyNotFound(label: "does-not-exist"))
        }
    }

    @Test func testSocketOnlyGeneratePurposes() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            let resDefault = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "default-key"],
                agentLifecycle: harness.lifecycle
            )
            #expect(resDefault?.exitCode == 0)

            let resAgent = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "agent-key", "--agent"],
                agentLifecycle: harness.lifecycle
            )
            #expect(resAgent?.exitCode == 0)

            let resGit = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "git-key", "--git-only"],
                agentLifecycle: harness.lifecycle
            )
            #expect(resGit?.exitCode == 0)

            let conflict = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "bad-key", "--agent", "--git-only"],
                agentLifecycle: harness.lifecycle
            )
            #expect(conflict?.exitCode == 1)
            #expect(conflict?.error == CLIMessages.agentAndGitOnlyExclusive)

            let defaultInfo = try harness.keyManager.fetchKeyInfo(label: "default-key")
            let agentInfo = try harness.keyManager.fetchKeyInfo(label: "agent-key")
            let gitInfo = try harness.keyManager.fetchKeyInfo(label: "git-key")
            #expect(defaultInfo?.purpose == .general)
            #expect(agentInfo?.purpose == .agent)
            #expect(gitInfo?.purpose == .gitSigningOnly)

            let listed = CLIService.handleSocketOnly(
                args: ["clavis", "list"],
                agentLifecycle: harness.lifecycle
            )
            #expect(listed?.exitCode == 0)
            #expect(listed?.output.contains(" - [default-key]\n") == true)
            #expect(listed?.output.contains(" - [agent-key] [Agent]") == true)
            #expect(listed?.output.contains(" - [git-key] [Git Only]") == true)
        }
    }

    @Test func testSocketOnlyKindChangeRoundtripAndLocalRevocation() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            let genResult = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "kind-key"],
                agentLifecycle: harness.lifecycle
            )
            #expect(genResult?.exitCode == 0)
            let initialKey = try #require(try harness.keyManager.fetchKeyInfo(label: "kind-key"))
            let genBefore = harness.generations.current(for: initialKey)

            harness.gitGrace.recordGrant(
                keyLabel: "kind-key",
                clientIdentity: "git",
                context: LAContext()
            )
            #expect(harness.gitGrace.currentActiveGrant?.keyLabel == "kind-key")

            let invalidTarget = CLIService.handleSocketOnly(
                args: ["clavis", "kind", "kind-key", "git-only"],
                agentLifecycle: harness.lifecycle
            )
            #expect(invalidTarget?.exitCode == 1)
            #expect(invalidTarget?.error?.contains("Invalid target kind") == true)
            #expect(harness.authenticator.authenticationCount == 0)

            let toAgent = CLIService.handleSocketOnly(
                args: ["clavis", "kind", "kind-key", "agent"],
                agentLifecycle: harness.lifecycle
            )
            #expect(toAgent?.exitCode == 0)
            #expect(toAgent?.output == CLIMessages.successfullyChangedKind(label: "kind-key", newPurpose: .agent))
            #expect(harness.authenticator.authenticationCount == 1)
            #expect(try harness.keyManager.fetchKeyInfo(label: "kind-key")?.purpose == .agent)
            #expect(harness.gitGrace.currentActiveGrant == nil)
            #expect(!harness.generations.matches(fingerprint: initialKey.fingerprint, generation: genBefore))

            let session = try harness.lifecycle.registerAgentSession(
                keyLabel: "kind-key",
                toolName: "codex",
                leaseMinutes: 5
            )
            #expect(harness.sessions.summaries().contains(where: { $0.id == session.id }))
            #expect(harness.authenticator.authenticationCount == 2)

            let toPersonal = CLIService.handleSocketOnly(
                args: ["clavis", "kind", "kind-key", "personal"],
                agentLifecycle: harness.lifecycle
            )
            #expect(toPersonal?.exitCode == 0)
            #expect(toPersonal?.output == CLIMessages.successfullyChangedKind(label: "kind-key", newPurpose: .general))
            #expect(harness.authenticator.authenticationCount == 3)
            #expect(try harness.keyManager.fetchKeyInfo(label: "kind-key")?.purpose == .general)
            #expect(harness.sessions.summaries().isEmpty)
        }
    }

    @Test func testSocketOnlyDeleteRequiresYesAndRevokesLocallyWithoutDeadlock() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            let genResult = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "del-key", "--agent"],
                agentLifecycle: harness.lifecycle
            )
            #expect(genResult?.exitCode == 0)
            let keyInfo = try #require(try harness.keyManager.fetchKeyInfo(label: "del-key"))
            let genBefore = harness.generations.current(for: keyInfo)

            let session = try harness.lifecycle.registerAgentSession(
                keyLabel: "del-key",
                toolName: "claude",
                leaseMinutes: 5
            )
            harness.gitGrace.recordGrant(
                keyLabel: "del-key",
                clientIdentity: "git",
                context: LAContext()
            )
            #expect(harness.sessions.summaries().contains(where: { $0.id == session.id }))
            #expect(harness.gitGrace.currentActiveGrant?.keyLabel == "del-key")
            let authCountAfterSession = harness.authenticator.authenticationCount
            #expect(authCountAfterSession == 1)

            let refused = CLIService.handleSocketOnly(
                args: ["clavis", "delete", "del-key"],
                agentLifecycle: harness.lifecycle
            )
            #expect(refused?.exitCode == 1)
            #expect(refused?.error == CLIMessages.usage(for: .delete))
            #expect(harness.authenticator.authenticationCount == authCountAfterSession)
            #expect(harness.privateKeyStore.contains(label: "del-key"))
            #expect(harness.sessions.summaries().contains(where: { $0.id == session.id }))

            let deleted = CLIService.handleSocketOnly(
                args: ["clavis", "delete", "del-key", "--yes"],
                agentLifecycle: harness.lifecycle
            )
            #expect(deleted?.exitCode == 0)
            #expect(deleted?.output == CLIMessages.successfullyDeleted(label: "del-key"))
            #expect(harness.authenticator.authenticationCount == authCountAfterSession + 1)
            #expect(!harness.privateKeyStore.contains(label: "del-key"))
            #expect(try harness.keyManager.fetchKeyInfo(label: "del-key") == nil)
            #expect(harness.gitGrace.currentActiveGrant == nil)
            #expect(harness.sessions.summaries().isEmpty)
            #expect(!harness.generations.matches(fingerprint: keyInfo.fingerprint, generation: genBefore))
        }
    }

    @Test func testSocketOnlyLockClearsActiveDaemonGrantsAndSessions() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            let genResult = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "lock-key", "--agent"],
                agentLifecycle: harness.lifecycle
            )
            #expect(genResult?.exitCode == 0)

            let session = try harness.lifecycle.registerAgentSession(
                keyLabel: "lock-key",
                toolName: "tool",
                leaseMinutes: 5
            )
            harness.gitGrace.recordGrant(
                keyLabel: "lock-key",
                clientIdentity: "git",
                context: LAContext()
            )
            #expect(harness.sessions.summaries().contains(where: { $0.id == session.id }))
            #expect(harness.gitGrace.currentActiveGrant?.keyLabel == "lock-key")

            let lockResult = CLIService.handleSocketOnly(
                args: ["clavis", "lock"],
                agentLifecycle: harness.lifecycle
            )
            #expect(lockResult?.exitCode == 0)
            #expect(lockResult?.output == CLIMessages.lockedAll)
            #expect(harness.gitGrace.currentActiveGrant == nil)
            // INV-21 (D-40): the agent session survives lock until its lease expires.
            #expect(harness.sessions.summaries().contains(where: { $0.id == session.id }))
        }
    }

    @Test func testSocketOnlyVaultRepairFlows() async throws {
        let harness = try Harness()
        defer { harness.cleanup() }

        try await harness.fixture.run {
            // Non-TTY must be refused before verifyMasterKey() runs (no master key exists on disk yet).
            let nonTTY = CLIService.handleSocketOnly(
                args: ["clavis", "vault", "repair"],
                agentLifecycle: harness.lifecycle,
                isTTY: false
            )
            #expect(nonTTY?.exitCode == 1)
            #expect(nonTTY?.error?.contains("TTY") == true)
            #expect(nonTTY?.error?.contains("verify") != true)

            // Initialize vault master key via key generation, then remove pin to simulate lost pin.
            let genResult = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "vault-seed"],
                agentLifecycle: harness.lifecycle
            )
            #expect(genResult?.exitCode == 0)
            let originalPin = try #require(try harness.pinStore.loadPin())

            try harness.pinStore.removePin()
            #expect(try harness.pinStore.loadPin() == nil)

            let cancelled = CLIService.handleSocketOnly(
                args: ["clavis", "vault", "repair"],
                agentLifecycle: harness.lifecycle,
                isTTY: true,
                confirmationPrompt: { "no" }
            )
            #expect(cancelled?.exitCode == 1)
            #expect(cancelled?.error?.contains("cancelled") == true)
            #expect(cancelled?.output.contains("Master key fingerprint: SHA256:") == true)
            #expect(cancelled?.output.contains("master.key created:") == true)
            #expect(try harness.pinStore.loadPin() == nil)

            let repaired = CLIService.handleSocketOnly(
                args: ["clavis", "vault", "repair"],
                agentLifecycle: harness.lifecycle,
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(repaired?.exitCode == 0)
            #expect(repaired?.output.contains("Vault master key pin successfully repaired.") == true)
            #expect(try harness.pinStore.loadPin() == originalPin)

            // Mismatched pin must refuse without --replace-pin and replace with --replace-pin + "yes".
            let wrongPin = Data(repeating: 0xee, count: 32)
            let oldFingerprint = EncryptedVaultStore.fingerprint(forPin: wrongPin)
            try harness.pinStore.savePin(wrongPin)

            let mismatchRefused = CLIService.handleSocketOnly(
                args: ["clavis", "vault", "repair"],
                agentLifecycle: harness.lifecycle,
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(mismatchRefused?.exitCode == 1)
            #expect(mismatchRefused?.output.contains("Keychain pinned fingerprint: \(oldFingerprint)") == true)
            #expect(mismatchRefused?.error?.contains("--replace-pin") == true)
            #expect(try harness.pinStore.loadPin() == wrongPin)

            let mismatchReplaced = CLIService.handleSocketOnly(
                args: ["clavis", "vault", "repair", "--replace-pin"],
                agentLifecycle: harness.lifecycle,
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(mismatchReplaced?.exitCode == 0)
            #expect(mismatchReplaced?.output.contains("Keychain pinned fingerprint: \(oldFingerprint)") == true)
            #expect(mismatchReplaced?.output.contains("WARNING: Replacing existing mismatched") == true)
            #expect(mismatchReplaced?.output.contains("Vault master key pin successfully repaired.") == true)
            #expect(try harness.pinStore.loadPin() == originalPin)
        }
    }

    @Test func testCLIControlSecurityRejectionsAndFailClosed() async throws {
        // 1. Untrusted control peer rejected with SSH_AGENT_FAILURE (Data([5])).
        let untrustedHarness = try Harness(controlPeerValidator: { _ in false })
        defer { untrustedHarness.cleanup() }

        try await untrustedHarness.fixture.run {
            let listJson = try JSONEncoder().encode(CLIControlRequest.listKeys)
            var listPayload = Data([SSHAgentServer.cliControlRequest])
            listPayload.appendWireData(listJson)

            #expect(
                untrustedHarness.server.processAgentRequest(
                    payload: listPayload,
                    clientPid: getpid(),
                    clientExecutablePath: "/clavis",
                    clientStartTime: 7,
                    isTrustedControlPeer: { false }
                ) == Data([5])
            )

            #expect(throws: (any Error).self) {
                try untrustedHarness.lifecycle.sendCLIControl(.listKeys)
            }
        }

        // 2. Agent role (.agent) rejects opcode 252 even from a trusted peer.
        let agentRoleHarness = try Harness(role: .agent, controlPeerValidator: { _ in true })
        defer { agentRoleHarness.cleanup() }

        try await agentRoleHarness.fixture.run {
            let listJson = try JSONEncoder().encode(CLIControlRequest.listKeys)
            var listPayload = Data([SSHAgentServer.cliControlRequest])
            listPayload.appendWireData(listJson)

            #expect(
                agentRoleHarness.server.processAgentRequest(
                    payload: listPayload,
                    clientPid: getpid(),
                    clientExecutablePath: "/clavis",
                    clientStartTime: 7,
                    isTrustedControlPeer: { true }
                ) == Data([5])
            )

            #expect(throws: (any Error).self) {
                try agentRoleHarness.lifecycle.sendCLIControl(.listKeys)
            }
        }

        // 3. Stale/reused peer PID (peerProcessValidator == false) rejects mutating requests.
        let stalePeerHarness = try Harness(peerProcessValidator: { _, _, _ in false }, startServer: false)
        defer { stalePeerHarness.cleanup() }

        try await stalePeerHarness.fixture.run {
            let genJson = try JSONEncoder().encode(
                CLIControlRequest.generateKey(
                    label: "should-fail",
                    algorithm: "ECDSA P-256",
                    storageType: .secureEnclave,
                    biometricPolicy: .userPresence,
                    keyPurpose: .general
                )
            )
            var genPayload = Data([SSHAgentServer.cliControlRequest])
            genPayload.appendWireData(genJson)

            #expect(
                stalePeerHarness.server.processAgentRequest(
                    payload: genPayload,
                    clientPid: getpid(),
                    clientExecutablePath: "/clavis",
                    clientStartTime: 7,
                    isTrustedControlPeer: { true }
                ) == Data([5])
            )
            #expect(try stalePeerHarness.keyManager.listKeys().isEmpty)
        }

        // 4. Socket-only CLI fails closed when daemon is unavailable (no in-process fallback).
        let stoppedHarness = try Harness(startServer: false)
        defer { stoppedHarness.cleanup() }

        var isolatedContext = stoppedHarness.fixture.context
        isolatedContext.environment = [:]
        TestContextScope.$current.withValue(isolatedContext) {
            let result = CLIService.handleSocketOnly(
                args: ["clavis", "list"],
                agentLifecycle: stoppedHarness.lifecycle
            )
            #expect(result?.exitCode == 1)
            #expect(result?.error?.contains("Clavis SSH Agent daemon is not running and could not be started.") == true)
        }
    }

    @Test func testSaveVaultMasterKeyPinServerSideEnforcementAndPromptGate() async throws {
        final class ToggleKeyAgreementProvider: SecureEnclaveKeyAgreementProviding, @unchecked Sendable {
            private let inner = InMemorySecureEnclaveKeyAgreementProvider()
            private let lock = NSLock()
            private var _failSharedSecret = false
            private(set) var sharedSecretCalls = 0

            var isAvailable: Bool { true }
            var failSharedSecret: Bool {
                get { lock.lock(); defer { lock.unlock() }; return _failSharedSecret }
                set { lock.lock(); defer { lock.unlock() }; _failSharedSecret = newValue }
            }

            func generateMasterKey(accessControl: SecAccessControl) throws -> (dataRepresentation: Data, publicKey: P256.KeyAgreement.PublicKey) {
                try inner.generateMasterKey(accessControl: accessControl)
            }

            func derivePublicKey(dataRepresentation: Data, context: LAContext?) throws -> P256.KeyAgreement.PublicKey {
                try inner.derivePublicKey(dataRepresentation: dataRepresentation, context: context)
            }

            func sharedSecret(
                dataRepresentation: Data,
                with peerPublicKey: P256.KeyAgreement.PublicKey,
                context: LAContext?
            ) throws -> SharedSecret {
                lock.lock()
                sharedSecretCalls += 1
                let shouldFail = _failSharedSecret
                lock.unlock()
                if shouldFail {
                    throw NSError(domain: "TestSE", code: -2, userInfo: [NSLocalizedDescriptionKey: "Simulated SE auth failure"])
                }
                return try inner.sharedSecret(dataRepresentation: dataRepresentation, with: peerPublicKey, context: context)
            }
        }

        let keyAgreement = ToggleKeyAgreementProvider()
        let gate = SigningPromptGate(maxConsecutiveDenials: 1, cooldown: 60)
        let harness = try Harness(promptGate: gate, keyAgreementProvider: keyAgreement)
        defer { harness.cleanup() }

        func decodeCLIResponse(_ raw: Data) throws -> CLIControlResponse {
            #expect(raw.first == 6)
            var reader = DataReader(data: Data(raw.dropFirst()))
            guard let json = reader.readWireData() else {
                Issue.record("Missing wire payload in CLIControlResponse")
                throw CancellationError()
            }
            #expect(reader.isEOF)
            return try JSONDecoder().decode(CLIControlResponse.self, from: json)
        }

        try await harness.fixture.run {
            let genResult = CLIService.handleSocketOnly(
                args: ["clavis", "generate", "vault-sec"],
                agentLifecycle: harness.lifecycle
            )
            #expect(genResult?.exitCode == 0)
            let originalPin = try #require(try harness.pinStore.loadPin())

            // Overwrite pin with attacker value; server must enforce every guard without relying on client.
            let attackerPin = Data(repeating: 0xAA, count: 32)
            try harness.pinStore.savePin(attackerPin)

            // 1. Short / invalid length pin rejected without touching pinStore.
            let shortRes = try harness.lifecycle.sendCLIControl(
                .saveVaultMasterKeyPin(expectedPin: Data([0x01, 0x02]), replacePin: true)
            )
            if case .failure = shortRes {} else {
                Issue.record("Expected short pin to be rejected")
            }
            #expect(try harness.pinStore.loadPin() == attackerPin)

            // 2. Wrong 32-byte pin (does not match master.pub) rejected server-side.
            let wrong32Res = try harness.lifecycle.sendCLIControl(
                .saveVaultMasterKeyPin(expectedPin: Data(repeating: 0xBB, count: 32), replacePin: true)
            )
            if case .failure = wrong32Res {} else {
                Issue.record("Expected mismatched 32-byte pin to be rejected")
            }
            #expect(try harness.pinStore.loadPin() == attackerPin)

            // 3. Matching pin with replacePin=false rejected server-side when mismatched pin is stored.
            let noReplaceRes = try harness.lifecycle.sendCLIControl(
                .saveVaultMasterKeyPin(expectedPin: originalPin, replacePin: false)
            )
            if case .failure = noReplaceRes {} else {
                Issue.record("Expected server to reject pin overwrite when replacePin is false")
            }
            #expect(try harness.pinStore.loadPin() == attackerPin)

            // 4. Failed Touch ID / verifyMasterKey rejected even with valid expectedPin & replacePin=true.
            let callsBeforeFail = keyAgreement.sharedSecretCalls
            keyAgreement.failSharedSecret = true
            let authFailedRes = try harness.lifecycle.sendCLIControl(
                .saveVaultMasterKeyPin(expectedPin: originalPin, replacePin: true)
            )
            if case .failure = authFailedRes {} else {
                Issue.record("Expected failed verifyMasterKey to block pin repair")
            }
            #expect(keyAgreement.sharedSecretCalls == callsBeforeFail + 1)
            #expect(try harness.pinStore.loadPin() == attackerPin)
            keyAgreement.failSharedSecret = false

            // 5. Gate cooldown blocks .saveVaultMasterKeyPin (proving promptGate serialization).
            let req = SigningPromptGate.Requester(executablePath: "/clavis", pid: getpid())
            _ = try? gate.run(requester: req) { throw UserAuthenticationError.rejected(nil) }
            let saveJson = try JSONEncoder().encode(
                CLIControlRequest.saveVaultMasterKeyPin(expectedPin: originalPin, replacePin: true)
            )
            var savePayload = Data([SSHAgentServer.cliControlRequest])
            savePayload.appendWireData(saveJson)
            let cooledResponse = try decodeCLIResponse(
                harness.server.processAgentRequest(
                    payload: savePayload,
                    clientPid: getpid(),
                    clientExecutablePath: "/clavis",
                    clientStartTime: 7,
                    isTrustedControlPeer: { true }
                )
            )
            if case .failure(let msg) = cooledResponse {
                #expect(msg.contains("temporarily refused"))
            } else {
                Issue.record("Expected promptGate cooldown to block saveVaultMasterKeyPin")
            }
            #expect(try harness.pinStore.loadPin() == attackerPin)

            // 6. Valid pin + replacePin=true on fresh non-cooled gate succeeds and restores originalPin.
            let callsBeforeSuccess = keyAgreement.sharedSecretCalls
            let okRes = try harness.lifecycle.sendCLIControl(
                .saveVaultMasterKeyPin(expectedPin: originalPin, replacePin: true)
            )
            #expect(okRes == .ok)
            #expect(keyAgreement.sharedSecretCalls == callsBeforeSuccess + 1)
            #expect(try harness.pinStore.loadPin() == originalPin)
        }
    }

    @Test func testCLIControlRevalidatesPeerProcessWhileQueuedAndDuringAuth() throws {
        final class HookedAuthenticator: UserAuthenticating, @unchecked Sendable {
            private let lock = NSLock()
            private var _count = 0
            var onAuthenticate: (() -> Void)?

            var count: Int {
                lock.lock(); defer { lock.unlock() }
                return _count
            }

            private func incrementCount() {
                lock.lock()
                _count += 1
                lock.unlock()
            }

            func authenticate(reason: String, policy: LAPolicy) throws -> LAContext {
                incrementCount()
                onAuthenticate?()
                return LAContext()
            }

            func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
                incrementCount()
                onAuthenticate?()
                return LAContext()
            }
        }

        final class LockedBool: @unchecked Sendable {
            private let lock = NSLock()
            private var value: Bool
            init(_ value: Bool) { self.value = value }
            func get() -> Bool { lock.lock(); defer { lock.unlock() }; return value }
            func set(_ newValue: Bool) { lock.lock(); defer { lock.unlock() }; value = newValue }
        }

        let peerValid = LockedBool(true)
        let hookAuth = HookedAuthenticator()
        let gate = SigningPromptGate()
        let harness = try Harness(
            peerProcessValidator: { _, _, _ in peerValid.get() },
            promptGate: gate,
            customAuthenticator: hookAuth,
            startServer: false
        )
        defer { harness.cleanup() }

        func frame(_ request: CLIControlRequest) throws -> Data {
            let json = try JSONEncoder().encode(request)
            var payload = Data([SSHAgentServer.cliControlRequest])
            payload.appendWireData(json)
            return payload
        }

        try harness.fixture.runSync {
            // Seed a key to target with changeKind and deleteKey.
            let seedRes = harness.server.processAgentRequest(
                payload: try frame(.generateKey(
                    label: "target-key",
                    algorithm: "ECDSA P-256",
                    storageType: .secureEnclave,
                    biometricPolicy: .userPresence,
                    keyPurpose: .general
                )),
                clientPid: getpid(),
                clientExecutablePath: "/clavis",
                clientStartTime: 7,
                isTrustedControlPeer: { true }
            )
            #expect(seedRes.first == 6)

            // Part A: Peer becomes invalid while queued in SigningPromptGate.
            let gateEntered = DispatchSemaphore(value: 0)
            let releaseGate = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                try? gate.run(requester: .init(executablePath: "/other", pid: 999)) {
                    gateEntered.signal()
                    _ = releaseGate.wait(timeout: .now() + 5.0)
                }
            }
            #expect(gateEntered.wait(timeout: .now() + 5.0) == .success)

            let queuedDone = DispatchSemaphore(value: 0)
            nonisolated(unsafe) var queuedResponse: Data?
            let deletePayload = try frame(.deleteKey(label: "target-key"))
            let ctx = harness.fixture.context
            DispatchQueue.global().async {
                queuedResponse = TestContextScope.$current.withValue(ctx) {
                    harness.server.processAgentRequest(
                        payload: deletePayload,
                        clientPid: getpid(),
                        clientExecutablePath: "/clavis",
                        clientStartTime: 7,
                        isTrustedControlPeer: { true }
                    )
                }
                queuedDone.signal()
            }

            // Give the worker thread a moment to enter promptGate.run's wait loop, then invalidate peer.
            usleep(20_000)
            peerValid.set(false)
            releaseGate.signal()

            #expect(queuedDone.wait(timeout: .now() + 5.0) == .success)
            #expect(queuedResponse == Data([5]))
            #expect(hookAuth.count == 0)
            #expect(try harness.keyManager.fetchKeyInfo(label: "target-key") != nil)

            // Part B: Peer becomes invalid mid-authentication (before committing changeKind / deleteKey).
            for request in [
                CLIControlRequest.changeKind(label: "target-key", newPurpose: .agent),
                CLIControlRequest.deleteKey(label: "target-key")
            ] {
                peerValid.set(true)
                let authBefore = hookAuth.count
                hookAuth.onAuthenticate = { peerValid.set(false) }
                let response = harness.server.processAgentRequest(
                    payload: try frame(request),
                    clientPid: getpid(),
                    clientExecutablePath: "/clavis",
                    clientStartTime: 7,
                    isTrustedControlPeer: { true }
                )
                hookAuth.onAuthenticate = nil
                #expect(response == Data([5]))
                #expect(hookAuth.count == authBefore + 1)
                let info = try #require(try harness.keyManager.fetchKeyInfo(label: "target-key"))
                #expect(info.purpose == .general)
                #expect(harness.privateKeyStore.contains(label: "target-key"))
            }
        }
    }
}
