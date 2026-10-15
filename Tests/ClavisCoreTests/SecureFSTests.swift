import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite(.serialized) struct SecureFSTests {

    @Test func testWithUmaskSetsAndRestoresUmask() {
        SecureFS.umaskLock.lock()
        defer { SecureFS.umaskLock.unlock() }

        let original = umask(0o022)
        _ = umask(original)

        var insideMask: mode_t = 0
        SecureFS.withUmask(0o077) {
            let temp = umask(0)
            insideMask = temp
            _ = umask(temp)
        }

        #expect(insideMask == 0o077)
        let restored = umask(0)
        _ = umask(restored)
        #expect(restored == original)
    }

    @Test func testCreateDirectoryEnforces0700Permissions() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testRoot = fixture.testRootURL
        let secureDir = testRoot.appendingPathComponent("secure-dir-\(UUID().uuidString)")
        try SecureFS.createDirectory(at: secureDir)

        #expect(FileManager.default.fileExists(atPath: secureDir.path))
        #expect(SecureFS.isDirectorySecure(at: secureDir))

        var info = stat()
        #expect(lstat(secureDir.path, &info) == 0)
        #expect((info.st_mode & 0o777) == 0o700)
    }

    @Test func testDirectoryModeVerificationRejectsInsecurePermissions() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testRoot = fixture.testRootURL
        let permissiveDir = testRoot.appendingPathComponent("permissive-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: permissiveDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: permissiveDir.path)

        // Initially insecure (group/other have permissions)
        #expect(!SecureFS.isDirectorySecure(at: permissiveDir))

        // Enforcement tightens it to 0700
        try SecureFS.verifyAndEnforceDirectoryPermissions(at: permissiveDir)
        #expect(SecureFS.isDirectorySecure(at: permissiveDir))

        var info = stat()
        #expect(lstat(permissiveDir.path, &info) == 0)
        #expect((info.st_mode & 0o777) == 0o700)
    }

    @Test func testOpenLockFileRejectsSymlinkWithELOOP() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testRoot = fixture.testRootURL
        let targetFile = testRoot.appendingPathComponent("real-target.txt")
        try "content".write(to: targetFile, atomically: true, encoding: .utf8)

        let symlinkPath = testRoot.appendingPathComponent("symlink.lock").path
        try FileManager.default.createSymbolicLink(atPath: symlinkPath, withDestinationPath: targetFile.path)

        // Opening through openLockFile must fail because O_NOFOLLOW is enforced
        let fd = SecureFS.openLockFile(path: symlinkPath, flags: O_RDONLY)
        #expect(fd == -1)
        #expect(errno == ELOOP)
    }

    @Test func testOpenLockFileCreatesRegularFileSecurely() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testRoot = fixture.testRootURL
        let lockPath = testRoot.appendingPathComponent("test.lock").path
        let fd = SecureFS.openLockFile(path: lockPath, flags: O_CREAT | O_RDWR, mode: 0o600)
        #expect(fd >= 0)
        close(fd)

        var info = stat()
        #expect(lstat(lockPath, &info) == 0)
        #expect((info.st_mode & 0o777) == 0o600)
    }
}
