import Foundation
import AppKit

public final class SingleInstanceLock: @unchecked Sendable {
    public static let shared = SingleInstanceLock()
    private var lockFd: Int32 = -1
    private let lock = NSLock()

    public static var lockFileURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("clavis.lock")
    }

    public func acquire() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if lockFd >= 0 {
            return true // Already acquired in this process
        }

        let path = Self.lockFileURL.path
        let fd = open(path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else {
            ClavisLogger.log("LOCK", "Failed to open lock file at \(path): errno \(errno)")
            return false
        }

        // Attempt non-blocking exclusive flock
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            ClavisLogger.log("LOCK", "Single instance lock is held by another process.")

            // Read existing PID from lock file to activate its window
            if let data = try? Data(contentsOf: Self.lockFileURL),
               let pidString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               let pid = pid_t(pidString) {
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

        ClavisLogger.log("LOCK", "Single instance lock acquired by PID \(getpid()).")
        return true
    }

    public func release() {
        lock.lock()
        defer { lock.unlock() }

        if lockFd >= 0 {
            flock(lockFd, LOCK_UN)
            close(lockFd)
            lockFd = -1
            try? FileManager.default.removeItem(at: Self.lockFileURL)
            ClavisLogger.log("LOCK", "Single instance lock released.")
        }
    }

    deinit {
        release()
    }
}
