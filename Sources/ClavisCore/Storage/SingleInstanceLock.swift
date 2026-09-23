import Foundation
import AppKit

public final class SingleInstanceLock: @unchecked Sendable {
    public static let gui = SingleInstanceLock(name: "clavis-gui", bringToFrontOnConflict: true)
    public static let agent = SingleInstanceLock(name: "clavis-agent", bringToFrontOnConflict: false)
    public static let shared = SingleInstanceLock.gui

    public let name: String
    public let bringToFrontOnConflict: Bool
    public var customLockFileURL: URL?

    public static var customLockFileURL: URL? = nil

    private var lockFd: Int32 = -1
    private let lock = NSRecursiveLock()

    public init(name: String = "clavis", bringToFrontOnConflict: Bool = true, customLockFileURL: URL? = nil) {
        self.name = name
        self.bringToFrontOnConflict = bringToFrontOnConflict
        self.customLockFileURL = customLockFileURL
    }

    public var lockFileURL: URL {
        if let custom = customLockFileURL { return custom }
        if let staticCustom = Self.customLockFileURL { return staticCustom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("\(name).lock")
    }

    public static var lockFileURL: URL {
        shared.lockFileURL
    }

    /// Reads the PID stored in the lock file, verifying that the process is alive
    /// and actively holding the advisory flock (preventing stale PID reuse attacks).
    public var lockOwnerPID: pid_t? {
        lock.lock()
        defer { lock.unlock() }

        if lockFd >= 0 {
            return getpid()
        }

        let path = lockFileURL.path
        let fd = open(path, O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // Test if an exclusive flock is actively held by another process.
        // If flock succeeds, no active process holds the lock; the lock file is stale.
        if flock(fd, LOCK_EX | LOCK_NB) == 0 {
            flock(fd, LOCK_UN)
            return nil
        }

        // Lock is actively held by another process. Read the PID.
        var buffer = [CChar](repeating: 0, count: 32)
        let bytesRead = read(fd, &buffer, buffer.count - 1)
        guard bytesRead > 0 else { return nil }
        let pidString = String(cString: buffer).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let pid = pid_t(pidString), pid > 0 else { return nil }

        // Verify process is active
        if kill(pid, 0) == 0 {
            return pid
        }
        return nil
    }

    public func acquire() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if lockFd >= 0 {
            return true // Already acquired in this process
        }

        let path = lockFileURL.path
        let fd = open(path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else {
            ClavisLogger.log("LOCK", "Failed to open lock file at \(path): errno \(errno)")
            return false
        }

        // Attempt non-blocking exclusive flock
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            ClavisLogger.log("LOCK", "Single instance lock '\(name)' is held by another process.")

            if bringToFrontOnConflict {
                // Read existing PID from lock file to activate its window
                if let pid = lockOwnerPID {
                    ClavisLogger.log("LOCK", "Attempting to focus existing process with PID \(pid)")
                    NSRunningApplication(processIdentifier: pid)?.activate(options: [.activateIgnoringOtherApps])
                }

                // Signal existing instance to bring Key Manager window to front
                DistributedNotificationCenter.default().postNotificationName(
                    NSNotification.Name("com.clavis.openKeyManager"),
                    object: nil,
                    userInfo: nil,
                    deliverImmediately: true
                )
            }

            close(fd)
            return false
        }

        self.lockFd = fd

        // Record our PID into the lock file
        ftruncate(fd, 0)
        lseek(fd, 0, SEEK_SET)
        let pidString = "\(getpid())\n"
        pidString.withCString { ptr in
            _ = write(fd, ptr, strlen(ptr))
        }

        ClavisLogger.log("LOCK", "Single instance lock '\(name)' acquired by PID \(getpid()).")
        return true
    }

    public func release() {
        lock.lock()
        defer { lock.unlock() }

        if lockFd >= 0 {
            ftruncate(lockFd, 0)
            flock(lockFd, LOCK_UN)
            close(lockFd)
            lockFd = -1
            // Note: We deliberately do not unlink lockFileURL to prevent flock split-brain race conditions.
            ClavisLogger.log("LOCK", "Single instance lock '\(name)' released.")
        }
    }

    deinit {
        release()
    }
}
