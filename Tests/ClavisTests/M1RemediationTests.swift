import Foundation
import Testing
@testable import ClavisCore

@Suite("M1 Seam Isolation Remediation Tests", .serialized)
struct M1RemediationTests {

    @Test("AuditStore seam precedence: TestContextScope takes precedence over customDefaultURL")
    func testAuditStorePrecedenceAndReset() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        // Set static custom URL
        let staticURL = fixture.testRootURL.appendingPathComponent("static_audit.db")
        AuditStore.defaultURL = staticURL
        defer { AuditStore.resetDefaultURLForTesting() }

        // Within TestContextScope, context.auditDatabaseURL must win
        await fixture.run { context in
            #expect(AuditStore.defaultURL == context.auditDatabaseURL)
            #expect(AuditStore.defaultURL != staticURL)
        }

        // Outside TestContextScope, staticURL was used
        #expect(AuditStore.defaultURL == staticURL)

        // Reset clears staticURL
        AuditStore.resetDefaultURLForTesting()
        #expect(AuditStore.defaultURL != staticURL)
        #expect(AuditStore.defaultURL.path.contains("clavis-audit-test-"))
    }

    @Test("SSHAgentServer resolver: TestContextScope lookup is preserved across reassignments")
    func testSSHAgentServerResolverTaskLocalPreserved() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        // Reassign the static resolver
        SSHAgentServer.gpgSSHProgramResolver = { "/custom/static/gpg" }
        defer { SSHAgentServer.resetGpgSSHProgramResolverForTesting() }

        // Within TestContextScope with context resolver returning "/context/gpg"
        var customContext = fixture.context
        customContext.gpgSSHProgramResolver = { "/context/gpg" }

        TestContextScope.$current.withValue(customContext) {
            let resolved = SSHAgentServer.gpgSSHProgramResolver()
            #expect(resolved == "/context/gpg")
        }

        // Outside TestContextScope, static reassigned resolver is called
        #expect(SSHAgentServer.gpgSSHProgramResolver() == "/custom/static/gpg")

        // Reset clears custom static resolver
        SSHAgentServer.resetGpgSSHProgramResolverForTesting()
    }

    @Test("EncryptedVaultStore instance seams: constructor injection takes precedence over TestContextScope")
    func testEncryptedVaultStoreInstanceInjectionPrecedence() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        let customPinStore = InMemoryMasterKeyPinStore()
        let customKeyAgreement = InMemorySecureEnclaveKeyAgreementProvider()

        let customStore = EncryptedVaultStore(
            vaultDirectoryURL: fixture.context.vaultDirectoryURL,
            pinStore: customPinStore,
            keyAgreementProvider: customKeyAgreement
        )

        let defaultStore = EncryptedVaultStore(vaultDirectoryURL: fixture.context.vaultDirectoryURL)

        await fixture.run { context in
            // Custom store must use constructor-injected instances
            #expect(customStore.activePinStore as? InMemoryMasterKeyPinStore === customPinStore)
            #expect(customStore.activeKeyAgreementProvider as? InMemorySecureEnclaveKeyAgreementProvider === customKeyAgreement)

            // Default store must use context instances
            #expect(defaultStore.activePinStore as? InMemoryMasterKeyPinStore === context.inMemoryPinStore)
            #expect(defaultStore.activeKeyAgreementProvider as? InMemorySecureEnclaveKeyAgreementProvider === (context.keyAgreementProvider as? InMemorySecureEnclaveKeyAgreementProvider))
        }
    }

    @Test("ClavisLogger TSAN race: concurrent readers and writers of effectiveMaximumLogFileSize")
    func testClavisLoggerConcurrentFileSize() async throws {
        defer {
            ClavisLogger.customMaximumLogFileSize = nil
        }

        await withTaskGroup(of: Void.self) { group in
            // Writers
            for i in 0..<8 {
                group.addTask {
                    for j in 0..<200 {
                        let size = UInt64(1024 + (i * 200 + j) * 64)
                        ClavisLogger.customMaximumLogFileSize = size
                    }
                }
            }
            // Readers
            for _ in 0..<8 {
                group.addTask {
                    for _ in 0..<200 {
                        let size = ClavisLogger.effectiveMaximumLogFileSize
                        #expect(size >= 1024)
                    }
                }
            }
        }
    }

    @Test("Host filesystem fallback protection: temporary directory fallbacks under ClavisEnvironment.isTesting")
    func testHostFilesystemFallbackProtection() async throws {
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // When running under testing without TestContextScope, fallbacks must never touch ~/.config/clavis
        #expect(ClavisEnvironment.isTesting)

        let defaultVaultURL = EncryptedVaultStore.shared.vaultDirectoryURL
        #expect(!defaultVaultURL.path.hasPrefix(home))
        #expect(defaultVaultURL.path.contains("clavis-test-vault-"))

        let defaultLogURL = ClavisLogger.logFileURL
        #expect(!defaultLogURL.path.hasPrefix(home))
        #expect(defaultLogURL.path.contains("clavis-test-"))

        let defaultAuditURL = AuditStore.defaultURL
        #expect(!defaultAuditURL.path.hasPrefix(home))
        #expect(defaultAuditURL.path.contains("clavis-audit-test-"))
    }

    @Test("TestContext default URLs: lockFileURL and launchAgentURL inside testRootURL")
    func testTestContextDefaultURLs() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        let context = fixture.context
        #expect(context.lockFileURL?.deletingLastPathComponent() == fixture.testRootURL)
        #expect(context.launchAgentURL?.deletingLastPathComponent() == fixture.testRootURL)
        #expect(context.lockFileURL?.lastPathComponent == "clavis.lock")
        #expect(context.launchAgentURL?.lastPathComponent == "com.clavis.agent.plist")

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        await fixture.run { _ in
            #expect(!SingleInstanceLock.shared.lockFileURL.path.hasPrefix(home))
            #expect(!LaunchAtLoginManager.shared.launchAgentURL.path.hasPrefix(home))
        }
    }

    @Test("AuditStore TSAN race: 50 concurrent tasks mutating, reading, and resetting defaultURL")
    func testAuditStoreConcurrentStaticMutationTSAN() async throws {
        let temp1 = FileManager.default.temporaryDirectory.appendingPathComponent("audit-concurrent-1.db")
        let temp2 = FileManager.default.temporaryDirectory.appendingPathComponent("audit-concurrent-2.db")
        defer { AuditStore.resetDefaultURLForTesting() }

        await withTaskGroup(of: Void.self) { group in
            // 20 Writers
            for i in 0..<20 {
                group.addTask {
                    for _ in 0..<150 {
                        AuditStore.defaultURL = (i % 2 == 0) ? temp1 : temp2
                    }
                }
            }
            // 20 Readers
            for _ in 0..<20 {
                group.addTask {
                    for _ in 0..<150 {
                        let url = AuditStore.defaultURL
                        #expect(!url.path.isEmpty)
                    }
                }
            }
            // 10 Resets
            for _ in 0..<10 {
                group.addTask {
                    for _ in 0..<100 {
                        AuditStore.resetDefaultURLForTesting()
                    }
                }
            }
        }
    }
}

