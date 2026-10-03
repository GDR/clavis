import XCTest
import CryptoKit
@testable import ClavisCore

final class LaunchAtLoginAndVaultHardeningTests: ClavisBaseTestCase {

    func testLaunchAtLoginRefusesWhenAgentExecutableNotFound() throws {
        guard let testRoot = testRootURL else { return }
        let plistURL = testRoot.appendingPathComponent("com.clavis.agent.plist")
        LaunchAtLoginManager.customLaunchAgentURL = plistURL
        defer { LaunchAtLoginManager.customLaunchAgentURL = nil }

        setenv("CLAVIS_AGENT_EXECUTABLE", "/nonexistent/path/to/clavis-agent", 1)
        defer { unsetenv("CLAVIS_AGENT_EXECUTABLE") }

        LaunchAtLoginManager.shared.enableLaunchAtLogin()
        XCTAssertFalse(FileManager.default.fileExists(atPath: plistURL.path),
                       "Must refuse to write plist when agent executable cannot be located")
    }

    func testLaunchAtLoginRefusesGroupWritableExecutable() throws {
        guard let testRoot = testRootURL else { return }
        let plistURL = testRoot.appendingPathComponent("com.clavis.agent.plist")
        LaunchAtLoginManager.customLaunchAgentURL = plistURL
        defer { LaunchAtLoginManager.customLaunchAgentURL = nil }

        let insecureBin = testRoot.appendingPathComponent("clavis-agent")
        try "#!/bin/sh\nexit 0\n".write(to: insecureBin, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: insecureBin.path)

        setenv("CLAVIS_AGENT_EXECUTABLE", insecureBin.path, 1)
        #if DEBUG
        AgentLifecycleManager.disableCodeSignatureCheckForTesting = true
        defer {
            AgentLifecycleManager.disableCodeSignatureCheckForTesting = false
            unsetenv("CLAVIS_AGENT_EXECUTABLE")
        }
        #endif

        LaunchAtLoginManager.shared.enableLaunchAtLogin()
        XCTAssertFalse(FileManager.default.fileExists(atPath: plistURL.path),
                       "Must refuse to write plist when executable is group/other writable")
    }

    func testVaultBackupFailureIsSurfacedToCaller() throws {
        guard let testRoot = testRootURL else { return }
        let vaultDir = testRoot.appendingPathComponent("vault-fail")
        try SecureFS.createDirectory(at: vaultDir)
        EncryptedVaultStore.customVaultDirectoryURL = vaultDir
        defer { EncryptedVaultStore.customVaultDirectoryURL = nil }

        let label = "vault-fail-test"
        let hash = SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
        let conflictDir = vaultDir.appendingPathComponent("\(hash).enc")
        // Create a directory where the .enc file is expected to be written so write fails
        try FileManager.default.createDirectory(at: conflictDir, withIntermediateDirectories: true)

        let keyManager = makeKeyManager()

        XCTAssertThrowsError(try keyManager.generateKey(label: label)) { error in
            XCTAssertNotNil(error)
        }
        // Ensure unbacked key was removed from store
        XCTAssertFalse(try keyManager.listKeys().contains(where: { $0.label == label }))
    }
}
