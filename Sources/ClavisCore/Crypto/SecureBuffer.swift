import Foundation
import Darwin

/// A cryptographically secure, page-aligned heap buffer that is locked into physical RAM
/// using `mlock(2)` to prevent paging out to disk (swap / sleepimage) and is guaranteed
/// to be zeroed out using `memset_s` upon destruction or explicit wipe.
public final class SecureBuffer: @unchecked Sendable {
    private var pointer: UnsafeMutableRawPointer?
    public let count: Int
    private let allocationSize: Int
    private var _isLocked: Bool = false
    private let lock = NSLock()

    public var isLocked: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _isLocked
    }

    public init?(count: Int) {
        guard count > 0 else { return nil }
        self.count = count

        let pageSize = Int(vm_page_size)
        let pages = max(1, (count + pageSize - 1) / pageSize)
        let totalSize = pages * pageSize
        self.allocationSize = totalSize

        var ptr: UnsafeMutableRawPointer? = nil
        let status = posix_memalign(&ptr, pageSize, totalSize)
        guard status == 0, let base = ptr else {
            return nil
        }

        self.pointer = base
        memset_s(base, totalSize, 0, totalSize)

        // Lock memory pages into RAM to prevent swap
        if mlock(base, totalSize) == 0 {
            self._isLocked = true
        }
    }

    public convenience init?(bytes: UnsafeRawPointer, count: Int) {
        self.init(count: count)
        guard let base = self.pointer else { return nil }
        base.copyMemory(from: bytes, byteCount: count)
    }

    public convenience init?(data: Data) {
        guard !data.isEmpty else { return nil }
        self.init(count: data.count)
        guard let base = self.pointer else { return nil }
        data.withUnsafeBytes { raw in
            if let src = raw.baseAddress {
                base.copyMemory(from: src, byteCount: data.count)
            }
        }
    }

    /// Access the secret bytes within a scoped closure.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R? {
        lock.lock()
        defer { lock.unlock() }
        guard let base = pointer else { return nil }
        let buffer = UnsafeRawBufferPointer(start: base, count: count)
        return try body(buffer)
    }

    /// Explicitly zero out and unlock memory immediately.
    public func wipe() {
        lock.lock()
        defer { lock.unlock() }
        guard let base = pointer else { return }

        // 1. Guaranteed memory overwrite using C11 memset_s (not optimized away by LLVM)
        memset_s(base, allocationSize, 0, allocationSize)

        // 2. Unlock from physical RAM
        if _isLocked {
            munlock(base, allocationSize)
            _isLocked = false
        }

        // 3. Free allocated memory
        free(base)
        pointer = nil
    }

    public var isWiped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return pointer == nil
    }

    deinit {
        wipe()
    }
}
