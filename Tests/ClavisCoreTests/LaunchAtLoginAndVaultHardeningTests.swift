import Foundation
import Testing
import CryptoKit
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite(.serialized)
struct LaunchAtLoginAndVaultHardeningTests {

    @Test func testLaunchAtLoginRefusesWhenAgentExecutableNotFound() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let plistURL = fixture.testRootURL.appendingPathComponent("com.clavis.agent.plist")
        LaunchAtLoginManager.customLaunchAgentURL = plistURL
        defer { LaunchAtLoginManager.customLaunchAgentURL = nil }

        setenv("CLAVIS_AGENT_EXECUTABLE", "/nonexistent/path/to/clavis-agent", 1)
        defer { unsetenv("CLAVIS_AGENT_EXECUTABLE") }

        LaunchAtLoginManager.shared.enableLaunchAtLogin()
        #expect(!FileManager.default.fileExists(atPath: plistURL.path),
                "Must refuse to write plist when agent executable cannot be located")
    }

    @Test func testLaunchAtLoginRefusesGroupWritableExecutable() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let plistURL = fixture.testRootURL.appendingPathComponent("com.clavis.agent.plist")
        LaunchAtLoginManager.customLaunchAgentURL = plistURL
        defer { LaunchAtLoginManager.customLaunchAgentURL = nil }

        let insecureBin = fixture.testRootURL.appendingPathComponent("clavis-agent")
        try "#!/bin/sh\nexit 0\n".write(to: insecureBin, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: insecureBin.path)

        setenv("CLAVIS_AGENT_EXECUTABLE", insecureBin.path, 1)
        #if DEBUG
        AgentLifecycleManager.disableCodeSignatureCheckForTesting = true
        defer {
            AgentLifecycleManager.disableCodeSignatureCheckForTesting = false
            unsetenv("CLAVIS_AGENT_EXECUTABLE")
        }
        #else
        defer { unsetenv("CLAVIS_AGENT_EXECUTABLE") }
        #endif

        LaunchAtLoginManager.shared.enableLaunchAtLogin()
        #expect(!FileManager.default.fileExists(atPath: plistURL.path),
                "Must refuse to write plist when executable is group/other writable")
    }

    @Test func testVaultBackupFailureIsSurfacedToCaller() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let vaultDir = fixture.testRootURL.appendingPathComponent("vault-fail")
        try SecureFS.createDirectory(at: vaultDir)

        let label = "vault-fail-test"
        let hash = SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
        let conflictDir = vaultDir.appendingPathComponent("\(hash).enc")
        // Create a directory where the .enc file is expected to be written so write fails
        try FileManager.default.createDirectory(at: conflictDir, withIntermediateDirectories: true)

        let customVault = EncryptedVaultStore(
            vaultDirectoryURL: vaultDir,
            pinStore: fixture.context.inMemoryPinStore,
            keyAgreementProvider: fixture.context.keyAgreementProvider
        )
        let keyManager = fixture.makeKeyManager(vaultStore: customVault)

        #expect(throws: (any Error).self) {
            try keyManager.generateKey(label: label)
        }
        // Ensure unbacked key was removed from store
        let keys = try keyManager.listKeys()
        #expect(!keys.contains(where: { $0.label == label }))
    }
}
