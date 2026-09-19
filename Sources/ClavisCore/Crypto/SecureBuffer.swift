import Foundation
import Darwin

/// A page-aligned heap buffer locked into physical RAM via `mlock(2)` to prevent paging out
/// to disk swap files. Serves as a defense-in-depth measure ensuring our managed memory
/// representation is zeroed with C11 `memset_s` upon deallocation, TTL expiration, or explicit wipe.
///
/// Note: While `mlock(2)` guarantees residency in physical RAM and prevents system paging to swap,
/// Apple does not document exclusion of locked pages from system-level hibernation images.
/// CryptoKit, Security framework, and higher-level runtimes may hold internal transient representations
/// outside our buffer's control; zeroing here is best-effort for caller-owned representations.
public final class SecureBuffer: @unchecked Sendable {
    private var pointer: UnsafeMutableRawPointer?
    public let count: Int
    private let allocationSize: Int
    private var _isLocked: Bool = false
    private let lock = NSLock()
    private var didNotifyWipe: Bool = false

    /// Verification hook called under buffer lock immediately following successful `memset_s`, while the memory pointer is still valid.
    /// Warning: The callback must NOT re-enter `SecureBuffer` methods as the buffer lock is held and teardown is in progress.
    let onAfterMemsetBeforeFree: (@Sendable (UnsafeRawBufferPointer) -> Void)?

    /// Notification hook invoked outside buffer lock at most once after memory is zeroed and freed.
    let onWipe: (@Sendable () -> Void)?

    public var isLocked: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _isLocked
    }

    /// Primary designated initializer.
    /// Fails closed: if `mlock` fails, the allocated buffer is zeroed, freed, and initialization fails (returns `nil`).
    public init?(
        count: Int,
        mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock,
        onAfterMemsetBeforeFree: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil,
        onWipe: (@Sendable () -> Void)? = nil
    ) {
        guard count > 0 else { return nil }
        self.count = count
        self.onAfterMemsetBeforeFree = onAfterMemsetBeforeFree
        self.onWipe = onWipe

        let pageSize = Int(vm_page_size)
        let pages = max(1, (count + pageSize - 1) / pageSize)
        let totalSize = pages * pageSize
        self.allocationSize = totalSize

        var ptr: UnsafeMutableRawPointer? = nil
        let status = posix_memalign(&ptr, pageSize, totalSize)
        guard status == 0, let base = ptr else {
            return nil
        }

        // Pre-zero buffer
        let preZeroRet = memset_s(base, totalSize, 0, totalSize)
        guard preZeroRet == 0 else {
            free(base)
            return nil
        }

        // Lock memory pages into physical RAM to prevent paging to swap (fail-closed)
        guard mlockFn(base, totalSize) == 0 else {
            let zeroRet = memset_s(base, totalSize, 0, totalSize)
            assert(zeroRet == 0, "memset_s failed in fail-closed branch")
            if zeroRet == 0 {
                onAfterMemsetBeforeFree?(UnsafeRawBufferPointer(start: base, count: count))
            }
            free(base)
            onWipe?()
            return nil
        }

        self.pointer = base
        self._isLocked = true
    }

    public convenience init?(
        bytes: UnsafeRawPointer,
        count: Int,
        mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock,
        onAfterMemsetBeforeFree: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil,
        onWipe: (@Sendable () -> Void)? = nil
    ) {
        self.init(count: count, mlockFn: mlockFn, onAfterMemsetBeforeFree: onAfterMemsetBeforeFree, onWipe: onWipe)
        guard let base = self.pointer else { return nil }
        base.copyMemory(from: bytes, byteCount: count)
    }

    public convenience init?(
        data: Data,
        mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock,
        onAfterMemsetBeforeFree: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil,
        onWipe: (@Sendable () -> Void)? = nil
    ) {
        guard !data.isEmpty else { return nil }
        self.init(count: data.count, mlockFn: mlockFn, onAfterMemsetBeforeFree: onAfterMemsetBeforeFree, onWipe: onWipe)
        guard let base = self.pointer else { return nil }
        data.withUnsafeBytes { raw in
            if let src = raw.baseAddress {
                base.copyMemory(from: src, byteCount: data.count)
            }
        }
    }

    /// Consumes the provided `Data`, copying its content into locked memory and attempting best-effort
    /// in-place zeroing of the caller's `Data` buffer before clearing the container.
    /// The caller's `Data` is wiped in a `defer` block whether initialization succeeds or fails.
    public convenience init?(
        consuming data: inout Data,
        mlockFn: (UnsafeRawPointer?, Int) -> Int32 = Darwin.mlock,
        onAfterMemsetBeforeFree: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil,
        onWipe: (@Sendable () -> Void)? = nil
    ) {
        guard !data.isEmpty else { return nil }
        defer {
            data.withUnsafeMutableBytes { raw in
                if let src = raw.baseAddress {
                    _ = memset_s(src, raw.count, 0, raw.count)
                }
            }
            data.removeAll(keepingCapacity: false)
        }

        self.init(count: data.count, mlockFn: mlockFn, onAfterMemsetBeforeFree: onAfterMemsetBeforeFree, onWipe: onWipe)
        guard let base = self.pointer else { return nil }
        data.withUnsafeBytes { raw in
            if let src = raw.baseAddress {
                base.copyMemory(from: src, byteCount: raw.count)
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

    /// Explicitly zero out and unlock memory promptly.
    public func wipe() {
        var shouldNotifyWipe = false
        lock.lock()
        defer {
            lock.unlock()
            if shouldNotifyWipe {
                onWipe?()
            }
        }
        guard let base = pointer else { return }

        // 1. Guaranteed memory overwrite using C11 memset_s (not optimized away by LLVM)
        let ret = memset_s(base, allocationSize, 0, allocationSize)
        assert(ret == 0, "memset_s failed during SecureBuffer wipe")

        // Execute verification callback under lock while pointer is valid
        let buffer = UnsafeRawBufferPointer(start: base, count: count)
        onAfterMemsetBeforeFree?(buffer)

        // 2. Unlock from physical RAM
        if _isLocked {
            munlock(base, allocationSize)
            _isLocked = false
        }

        // 3. Free allocated memory
        free(base)
        pointer = nil

        if !didNotifyWipe {
            didNotifyWipe = true
            shouldNotifyWipe = true
        }
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
