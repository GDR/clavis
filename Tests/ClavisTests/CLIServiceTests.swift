import Foundation
import Testing
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

private final class CleanupHook: @unchecked Sendable {
    private let action: () -> Void
    init(action: @escaping () -> Void) {
        self.action = action
    }
    deinit {
        action()
    }
}

@Suite
struct CLIServiceTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }
    private let _cleanup: CleanupHook

    init() throws {
        let fixture = try ClavisTestFixture()
        self.fixture = fixture
        self._cleanup = CleanupHook {
            fixture.cleanup()
        }
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

    @Test func testCLIServiceHelpCommand() {
        let keyManager = makeKeyManager()
        let resHelp = CLIService.handle(args: ["clavis", "help"], keyManager: keyManager)
        #expect(resHelp != nil)
        #expect(resHelp?.exitCode == 0)
        #expect(resHelp?.output.contains("Clavis") ?? false)

        let resDashH = CLIService.handle(args: ["clavis", "-h"], keyManager: keyManager)
        #expect(resDashH?.exitCode == 0)

        let resNoArgs = CLIService.handle(args: ["clavis"], keyManager: keyManager)
        #expect(resNoArgs == nil)
    }

    @Test func testCLIServiceHelpIncludesAllSupportedCommands() {
        let keyManager = makeKeyManager()
        let resHelp = CLIService.handle(args: ["clavis", "help"], keyManager: keyManager)
        #expect(resHelp?.exitCode == 0)
        let helpOutput = resHelp?.output ?? ""
        #expect(helpOutput == CLIMessages.help)

        for command in ["generate", "list", "export", "delete", "lock", "vault repair", "daemon"] {
            #expect(CLIMessages.help.contains(command), "CLIMessages.help missing '\(command)'")
            #expect(helpOutput.contains(command), "Help output missing '\(command)'")
        }
        #expect(
            CLIMessages.help.contains("kind") || CLIMessages.help.contains("key set-kind"),
            "CLIMessages.help missing kind command"
        )
        #expect(
            CLIMessages.help.localizedCaseInsensitiveContains("run"),
            "CLIMessages.help missing run reference"
        )
        #expect(
            CLIMessages.usage(for: .run).contains("run"),
            "CLIMessages.usage(for: .run) missing 'run'"
        )
    }

    @Test func testCLIServiceMissingGenerateArgs() {
        let keyManager = makeKeyManager()
        let missingArgsRes = CLIService.handle(args: ["clavis", "generate"], keyManager: keyManager)
        #expect(missingArgsRes?.exitCode == 1)
        #expect(missingArgsRes?.error == CLIMessages.usage(for: .generate))
    }

    @Test func testCLIDeleteRequiresYesAndFreshAuthentication() throws {
        let store = InMemoryPrivateKeyStore()
        let authenticator = CountingAuthenticator()
        let manager = makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: store
        )
        let label = "delete-auth-\(UUID().uuidString)"
        _ = try manager.generateKey(label: label)

        let refused = CLIService.handle(
            args: ["clavis", "delete", label],
            keyManager: manager
        )
        #expect(refused?.exitCode == 1)
        #expect(refused?.error == "Usage: clavis delete <label> --yes")
        #expect(authenticator.authenticationCount == 0)
        #expect(store.contains(label: label))

        let deleted = CLIService.handle(
            args: ["clavis", "delete", label, "--yes"],
            keyManager: manager
        )
        #expect(deleted?.exitCode == 0)
        #expect(authenticator.authenticationCount == 1)
        #expect(!store.contains(label: label))
    }
}
