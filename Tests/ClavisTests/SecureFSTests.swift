import XCTest
@testable import ClavisCore

final class SecureFSTests: ClavisBaseTestCase {

    func testWithUmaskSetsAndRestoresUmask() {
        let original = umask(0o022)
        _ = umask(original)

        var insideMask: mode_t = 0
        SecureFS.withUmask(0o077) {
            let temp = umask(0)
            insideMask = temp
            _ = umask(temp)
        }

        XCTAssertEqual(insideMask, 0o077)
        let restored = umask(0)
        _ = umask(restored)
        XCTAssertEqual(restored, original)
    }

    func testCreateDirectoryEnforces0700Permissions() throws {
        guard let testRoot = testRootURL else { return }
        let secureDir = testRoot.appendingPathComponent("secure-dir-\(UUID().uuidString)")
        try SecureFS.createDirectory(at: secureDir)

        XCTAssertTrue(FileManager.default.fileExists(atPath: secureDir.path))
        XCTAssertTrue(SecureFS.isDirectorySecure(at: secureDir))

        var info = stat()
        XCTAssertEqual(lstat(secureDir.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o700)
    }

    func testDirectoryModeVerificationRejectsInsecurePermissions() throws {
        guard let testRoot = testRootURL else { return }
        let permissiveDir = testRoot.appendingPathComponent("permissive-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: permissiveDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: permissiveDir.path)

        // Initially insecure (group/other have permissions)
        XCTAssertFalse(SecureFS.isDirectorySecure(at: permissiveDir))

        // Enforcement tightens it to 0700
        try SecureFS.verifyAndEnforceDirectoryPermissions(at: permissiveDir)
        XCTAssertTrue(SecureFS.isDirectorySecure(at: permissiveDir))

        var info = stat()
        XCTAssertEqual(lstat(permissiveDir.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o700)
    }

    func testOpenLockFileRejectsSymlinkWithELOOP() throws {
        guard let testRoot = testRootURL else { return }
        let targetFile = testRoot.appendingPathComponent("real-target.txt")
        try "content".write(to: targetFile, atomically: true, encoding: .utf8)

        let symlinkPath = testRoot.appendingPathComponent("symlink.lock").path
        try FileManager.default.createSymbolicLink(atPath: symlinkPath, withDestinationPath: targetFile.path)

        // Opening through openLockFile must fail because O_NOFOLLOW is enforced
        let fd = SecureFS.openLockFile(path: symlinkPath, flags: O_RDONLY)
        XCTAssertEqual(fd, -1)
        XCTAssertEqual(errno, ELOOP)
    }

    func testOpenLockFileCreatesRegularFileSecurely() throws {
        guard let testRoot = testRootURL else { return }
        let lockPath = testRoot.appendingPathComponent("test.lock").path
        let fd = SecureFS.openLockFile(path: lockPath, flags: O_CREAT | O_RDWR, mode: 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0)
        close(fd)

        var info = stat()
        XCTAssertEqual(lstat(lockPath, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }
}
