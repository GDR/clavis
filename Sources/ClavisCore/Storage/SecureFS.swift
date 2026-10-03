import Foundation

/// Centralized file-system security helper ensuring restricted file permissions and safe operations.
///
/// Features:
/// - Process-synchronized `umask(0o077)` scoping for sensitive directory and file creation.
/// - Verification and enforcement of `0o700` POSIX mode on directory paths (owned by user, no group/other access).
/// - Enforces `O_NOFOLLOW` flag on lock files to prevent symlink traversal attacks.
public enum SecureFS {
    private static let umaskLock = NSLock()

    /// Executes `body` with process umask set to `mask` (default 0o077), restored upon exit.
    /// Synchronized across threads to prevent race conditions during file creation.
    @discardableResult
    public static func withUmask<T>(_ mask: mode_t = 0o077, _ body: () throws -> T) rethrows -> T {
        umaskLock.lock()
        let oldMask = umask(mask)
        defer {
            _ = umask(oldMask)
            umaskLock.unlock()
        }
        return try body()
    }

    /// Creates a directory with `0o700` POSIX permissions under `umask(0o077)`.
    /// Verifies existing directories meet the 0700 mode requirement.
    public static func createDirectory(at url: URL) throws {
        try withUmask(0o077) {
            try FileManager.default.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try verifyAndEnforceDirectoryPermissions(at: url)
        }
    }

    /// Verifies that the directory exists, is a directory, is owned by current user (or root),
    /// and has no permissions for group or others (mode 0700).
    public static func isDirectorySecure(at url: URL) -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return false }
        guard (info.st_mode & S_IFMT) == S_IFDIR else { return false }
        guard info.st_uid == geteuid() || info.st_uid == 0 else { return false }
        return (info.st_mode & 0o077) == 0
    }

    /// Verifies and tightens permissions to `targetMode` (default `0o700`).
    public static func verifyAndEnforceDirectoryPermissions(at url: URL, targetMode: mode_t = 0o700) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            throw NSError(
                domain: "Clavis.SecureFS",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Failed to stat directory at \(url.path): errno \(errno)"]
            )
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw NSError(
                domain: "Clavis.SecureFS",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Path is not a directory: \(url.path)"]
            )
        }
        guard info.st_uid == geteuid() || info.st_uid == 0 else {
            throw NSError(
                domain: "Clavis.SecureFS",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Directory is not owned by user: \(url.path) (uid: \(info.st_uid))"]
            )
        }
        if (info.st_mode & 0o077) != 0 || (info.st_mode & 0o777) != targetMode {
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: targetMode)], ofItemAtPath: url.path)
        }
    }

    /// Opens a lock file ensuring `O_NOFOLLOW` is always set to prevent symlink traversal.
    public static func openLockFile(path: String, flags: Int32, mode: mode_t = 0o600) -> Int32 {
        let secureFlags = flags | O_NOFOLLOW | O_CLOEXEC
        return withUmask(0o077) {
            open(path, secureFlags, mode)
        }
    }
}
