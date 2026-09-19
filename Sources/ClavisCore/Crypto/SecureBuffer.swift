import Foundation
import Darwin

/// A page-aligned heap buffer locked into physical RAM via `mlock(2)` to prevent paging out
/// to disk swap files. Serves as a defense-in-depth measure ensuring our managed memory
/// representation is zeroed with C11 `memset_s` upon deallocation, TTL expiration, or explicit wipe.
///
/// Note: While `mlock(2)` guarantees residency in physical RAM and prevents system paging to swap,
/// Apple does not document exclusion of locked pages from system-level hibernation images.
/// CryptoKit and higher-level frameworks may also hold internal transient heap representations
/// outside this buffer's scope.
public final class SecureBuffer: @unchecked Sendable {
    private var pointer: UnsafeMutableRawPointer?
    public let count: Int
    private let allocationSize: Int
    private var _isLocked: Bool = false
    private let lock = NSLock()

    // Test hook to observe when wipe is executed (e.g. from deinit)
    var onWipe: (() -> Void)?

    public var isLocked: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _isLocked
    }

    /// Primary designated initializer.
    /// Fails closed: if `mlock` fails, the allocated buffer is zeroed, freed, and initialization fails (returns `nil`).
    public init?(count: Int, mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock) {
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

        // Lock memory pages into physical RAM to prevent paging to swap (fail-closed)
        guard mlockFn(base, totalSize) == 0 else {
            memset_s(base, totalSize, 0, totalSize)
            free(base)
            return nil
        }

        self.pointer = base
        self._isLocked = true
        memset_s(base, totalSize, 0, totalSize)
    }

    public convenience init?(bytes: UnsafeRawPointer, count: Int, mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock) {
        self.init(count: count, mlockFn: mlockFn)
        guard let base = self.pointer else { return nil }
        base.copyMemory(from: bytes, byteCount: count)
    }

    public convenience init?(data: Data, mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock) {
        guard !data.isEmpty else { return nil }
        self.init(count: data.count, mlockFn: mlockFn)
        guard let base = self.pointer else { return nil }
        data.withUnsafeBytes { raw in
            if let src = raw.baseAddress {
                base.copyMemory(from: src, byteCount: data.count)
            }
        }
    }

    /// Consumes the provided `Data`, copying its content into locked memory and immediately
    /// zeroing out the input `Data` buffer in-place to avoid unzeroed copy-on-write residue.
    public convenience init?(consuming data: inout Data, mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock) {
        guard !data.isEmpty else { return nil }
        self.init(count: data.count, mlockFn: mlockFn)
        guard let base = self.pointer else { return nil }
        data.withUnsafeMutableBytes { raw in
            if let src = raw.baseAddress {
                base.copyMemory(from: src, byteCount: raw.count)
                memset_s(src, raw.count, 0, raw.count)
            }
        }
        data.removeAll(keepingCapacity: false)
    }

    /// Access the secret bytes within a scoped closure.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R? {
        lock.lock()
        defer { lock.unlock() }
        guard let base = pointer else { return nil }
        let buffer = UnsafeRawBufferPointer(start: base, count: count)
        return try body(buffer)
    }

    /// Zero out memory contents with `memset_s` without freeing pointer (used to verify zeroization in tests).
    func wipeMemoryOnly() {
        lock.lock()
        defer { lock.unlock() }
        guard let base = pointer else { return }
        memset_s(base, allocationSize, 0, allocationSize)
    }

    /// Explicitly zero out and unlock memory immediately.
    public func wipe() {
        lock.lock()
        defer {
            lock.unlock()
            onWipe?()
        }
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
