import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class SessionCacheTests: ClavisBaseTestCase {

    func testSessionCacheManagerExpiration() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes

        let exp = expectation(description: "Key must expire and be wiped by active timer")
        let key = Curve25519.Signing.PrivateKey()
        var raw = key.rawRepresentation
        guard let buffer = SecureBuffer(consuming: &raw, onWipe: {
            exp.fulfill()
        }) else {
            XCTFail("Allocation failed")
            return
        }

        cache.setInternal(label: "cached-key", buffer: buffer, timeoutOverride: 0.05)
        XCTAssertNotNil(cache.getBuffer(label: "cached-key"))
        XCTAssertEqual(cache.cachedCount, 1)

        wait(for: [exp], timeout: 2.0)

        XCTAssertNil(cache.getBuffer(label: "cached-key"))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheDisabled() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .never // Cache off

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "uncached-key", key: key)

        XCTAssertNil(cache.getBuffer(label: "uncached-key"))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheDisabledPerformsSingleShotAndWipes() throws {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .never // Cache off

        let wipeExpectation = expectation(description: "Single-shot buffer must be wiped")
        let keyManager = makeKeyManager(
            sessionCache: cache,
            secureBufferFactory: { data in
                SecureBuffer(consuming: &data, onWipe: {
                    wipeExpectation.fulfill()
                })
            }
        )
        let keyLabel = "never-cache-\(UUID().uuidString)"
        _ = try keyManager.generateKey(label: keyLabel)

        // Sign should succeed under .never without placing anything into sessionCache
        let sampleData = "hello world".data(using: .utf8)!
        let signature = try keyManager.sign(label: keyLabel, data: sampleData, prompt: "Sign under never")
        XCTAssertFalse(signature.isEmpty)
        wait(for: [wipeExpectation], timeout: 1.0)

        // Session cache must remain completely empty
        XCTAssertNil(cache.getBuffer(label: keyLabel))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSecureBufferAllocationAndRAMLocking() {
        let secretData = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])
        guard let buffer = SecureBuffer(data: secretData) else {
            XCTFail("Failed to allocate SecureBuffer")
            return
        }

        XCTAssertEqual(buffer.count, 8)
        XCTAssertFalse(buffer.isWiped)
        XCTAssertTrue(buffer.isLocked, "SecureBuffer should be locked into RAM with mlock(2)")

        let readData = buffer.withUnsafeBytes { raw in
            Data(raw)
        }
        XCTAssertEqual(readData, secretData)
    }


    func testSecureBufferWipe() {
        let secretData = Data([1, 2, 3, 4, 5, 6, 7, 8])
        guard let buffer = SecureBuffer(data: secretData) else {
            XCTFail("Failed to allocate SecureBuffer")
            return
        }

        XCTAssertFalse(buffer.isWiped)
        buffer.wipe()

        XCTAssertTrue(buffer.isWiped)
        XCTAssertFalse(buffer.isLocked)

        let read = buffer.withUnsafeBytes { raw in
            Data(raw)
        }
        XCTAssertNil(read, "withUnsafeBytes must return nil after buffer is wiped")

        // Redundant wipe should be a safe no-op
        buffer.wipe()
        XCTAssertTrue(buffer.isWiped)
    }


    func testSessionCacheManagerZeroingOnClear() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "wipe-on-clear", key: key)

        guard let buffer = cache.getBuffer(label: "wipe-on-clear") else {
            XCTFail("Expected cached buffer")
            return
        }
        XCTAssertFalse(buffer.isWiped)
        XCTAssertTrue(buffer.isLocked)

        // Clearing the cache must immediately zero out and unlock the memory
        cache.clearCache()

        XCTAssertTrue(buffer.isWiped, "Buffer held by session cache must be wiped via memset_s on clearCache()")
        XCTAssertNil(cache.getBuffer(label: "wipe-on-clear"))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheManagerZeroingOnRemove() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "wipe-on-remove", key: key)

        guard let buffer = cache.getBuffer(label: "wipe-on-remove") else {
            XCTFail("Expected cached buffer")
            return
        }
        XCTAssertFalse(buffer.isWiped)

        cache.remove(label: "wipe-on-remove")

        XCTAssertTrue(buffer.isWiped, "Buffer must be wiped when removed from session cache")
        XCTAssertNil(cache.getBuffer(label: "wipe-on-remove"))
    }


    func testCachedP256SoftwareWiping() throws {
        let p256Key = P256.Signing.PrivateKey()
        let raw = p256Key.rawRepresentation
        guard let buf = SecureBuffer(data: raw) else {
            XCTFail("Failed to allocate SecureBuffer for P256")
            return
        }

        let cachedKey = CachedP256SigningKey.software(buf)
        let sampleData = "test message".data(using: .utf8)!

        // Signing works initially
        let signature = try cachedKey.signature(for: sampleData)
        XCTAssertFalse(signature.rawRepresentation.isEmpty)

        // Wipe key
        cachedKey.wipe()
        XCTAssertTrue(buf.isWiped)

        // Subsequent sign attempts fail
        XCTAssertThrowsError(try cachedKey.signature(for: sampleData))
    }


    func testSecureBufferFailClosedOnMlockFailure() {
        let failingMlock: (UnsafeRawPointer?, Int) -> Int32 = { _, _ in -1 }
        final class TestFlag: @unchecked Sendable {
            private let lock = NSLock()
            private var _val: Bool = false
            var value: Bool {
                get { lock.lock(); defer { lock.unlock() }; return _val }
                set { lock.lock(); defer { lock.unlock() }; _val = newValue }
            }
        }

        let callbackTriggered = TestFlag()
        let onWipeTriggered = TestFlag()

        XCTAssertNil(
            SecureBuffer(
                count: 32,
                mlockFn: failingMlock,
                onAfterMemsetBeforeFree: { _ in callbackTriggered.value = true },
                onWipe: { onWipeTriggered.value = true }
            ),
            "SecureBuffer must fail-closed if mlock fails"
        )
        XCTAssertTrue(callbackTriggered.value, "Fail-closed branch must invoke onAfterMemsetBeforeFree before free")
        XCTAssertTrue(onWipeTriggered.value, "Fail-closed branch must invoke onWipe")

        var testData = Data([4, 5, 6])
        XCTAssertNil(SecureBuffer(consuming: &testData, mlockFn: failingMlock), "SecureBuffer(consuming:) must fail-closed if mlock fails")
        XCTAssertTrue(testData.isEmpty, "Consuming init must empty source Data even when mlock fails")
    }


    func testSecureMemoryFallsBackWhenMemsetSFails() {
        var bytes = [UInt8](repeating: 0xA5, count: 32)
        let usedPrimaryZeroizer = bytes.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return true }
            return SecureMemory.zero(
                base,
                byteCount: raw.count,
                memsetS: { _, _, _, _ in EINVAL }
            )
        }

        XCTAssertFalse(usedPrimaryZeroizer)
        XCTAssertEqual(bytes, [UInt8](repeating: 0, count: 32))
    }


    func testSecureBufferConsumingZeroesInputData() {
        var secretData = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
        guard let buffer = SecureBuffer(consuming: &secretData) else {
            XCTFail("Failed to allocate consuming SecureBuffer")
            return
        }

        XCTAssertTrue(secretData.isEmpty, "Consuming init must empty the source Data container")
        XCTAssertEqual(buffer.count, 5)

        let recovered = buffer.withUnsafeBytes { Data($0) }
        XCTAssertEqual(recovered, Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]))
    }


    func testSecureBufferMemoryZeroedBeforeFree() {
        final class TestFlag: @unchecked Sendable {
            private let lock = NSLock()
            private var _val: Bool = false
            var value: Bool {
                get { lock.lock(); defer { lock.unlock() }; return _val }
                set { lock.lock(); defer { lock.unlock() }; _val = newValue }
            }
        }
        let originalBytes: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let zeroCheckSucceeded = TestFlag()

        guard let buffer = SecureBuffer(
            data: Data(originalBytes),
            onAfterMemsetBeforeFree: { inspectedBytes in
                if Array(inspectedBytes) == [0x00, 0x00, 0x00, 0x00] {
                    zeroCheckSucceeded.value = true
                }
            }
        ) else {
            XCTFail("Failed to allocate SecureBuffer")
            return
        }

        buffer.wipe()
        XCTAssertTrue(zeroCheckSucceeded.value, "onAfterMemsetBeforeFree must verify memory is zeroed before free")
        XCTAssertTrue(buffer.isWiped)
    }


    func testSecureBufferDeinitTriggersWipe() {
        final class TestFlag: @unchecked Sendable {
            private let lock = NSLock()
            private var _val: Bool = false
            var value: Bool {
                get { lock.lock(); defer { lock.unlock() }; return _val }
                set { lock.lock(); defer { lock.unlock() }; _val = newValue }
            }
        }
        let wasWiped = TestFlag()
        do {
            let buffer = SecureBuffer(data: Data([1, 2, 3, 4]), onWipe: {
                wasWiped.value = true
            })
            XCTAssertFalse(wasWiped.value)
            _ = buffer?.count
        }
        XCTAssertTrue(wasWiped.value, "SecureBuffer deinit must trigger wipe()")
    }


    func testSessionCacheActiveMonotonicTTLWipe() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes

        let exp = expectation(description: "Buffer must be wiped by active monotonic timer")
        let key = Curve25519.Signing.PrivateKey()
        var raw = key.rawRepresentation
        guard let buffer = SecureBuffer(consuming: &raw, onWipe: {
            exp.fulfill()
        }) else {
            XCTFail("Buffer allocation failed")
            return
        }

        cache.setInternal(label: "active-ttl-test", buffer: buffer, timeoutOverride: 0.05)
        XCTAssertFalse(buffer.isWiped)
        XCTAssertEqual(cache.cachedCount, 1)

        // Wait for timer to execute wipe promptly after deadline
        wait(for: [exp], timeout: 2.0)

        // Must be wiped BEFORE checking cachedCount
        XCTAssertTrue(buffer.isWiped, "Buffer must be wiped by active monotonic timer upon TTL expiration")
        XCTAssertEqual(cache.cachedCount, 0, "Cache count must reflect expired entry")
    }


    func testSessionCacheSystemNotifications() {
        let suiteName = "test-notifications-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        let cache = SessionCacheManager(defaults: defaults, observeSystemEvents: true)
        cache.currentTimeout = .fiveMinutes

        // 1. Sleep notification
        let sleepWipe = expectation(description: "Sleep notification wipes cached buffer")
        var raw1 = Curve25519.Signing.PrivateKey().rawRepresentation
        guard let buf1 = SecureBuffer(consuming: &raw1, onWipe: {
            sleepWipe.fulfill()
        }) else {
            XCTFail("Failed to create buffer 1")
            return
        }
        XCTAssertTrue(cache.set(label: "sleep-test", buffer: buf1))
        XCTAssertFalse(buf1.isWiped)

        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        wait(for: [sleepWipe], timeout: 1.0)
        XCTAssertTrue(buf1.isWiped, "Buffer must be wiped upon willSleepNotification")
        XCTAssertEqual(cache.cachedCount, 0)

        // 2. Screen lock notification
        let screenLockWipe = expectation(description: "Screen lock notification wipes cached buffer")
        var raw2 = Curve25519.Signing.PrivateKey().rawRepresentation
        guard let buf2 = SecureBuffer(consuming: &raw2, onWipe: {
            screenLockWipe.fulfill()
        }) else {
            XCTFail("Failed to create buffer 2")
            return
        }
        XCTAssertTrue(cache.set(label: "screen-lock-test", buffer: buf2))
        XCTAssertFalse(buf2.isWiped)

        DistributedNotificationCenter.default().postNotificationName(
            NSNotification.Name("com.apple.screenIsLocked"),
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
        wait(for: [screenLockWipe], timeout: 1.0)
        XCTAssertTrue(buf2.isWiped, "Buffer must be wiped upon screenIsLocked notification")
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheFlushOnTimeoutChange() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes
        cache.set(label: "flush-test", key: Curve25519.Signing.PrivateKey())
        XCTAssertEqual(cache.cachedCount, 1)

        // Changing timeout flushes cache
        cache.currentTimeout = .never
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheTimeoutChangePurgesCache() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .oneHour

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "timeout-purge-test", key: key)
        XCTAssertEqual(cache.cachedCount, 1)

        // Lowering timeout interval from 1 hour to 5 minutes purges cache
        cache.currentTimeout = .fiveMinutes
        XCTAssertEqual(cache.cachedCount, 0)
        XCTAssertNil(cache.getBuffer(label: "timeout-purge-test"))

        // Add key again
        cache.set(label: "timeout-purge-test-2", key: key)
        XCTAssertEqual(cache.cachedCount, 1)

        // Setting timeout to .never purges cache
        cache.currentTimeout = .never
        XCTAssertEqual(cache.cachedCount, 0)
        XCTAssertNil(cache.getBuffer(label: "timeout-purge-test-2"))

        // Increasing timeout from 5 minutes to 1 hour should NOT purge cache
        cache.currentTimeout = .fiveMinutes
        cache.set(label: "timeout-keep-test", key: key)
        XCTAssertEqual(cache.cachedCount, 1)

        cache.currentTimeout = .oneHour
        XCTAssertEqual(cache.cachedCount, 1)
        XCTAssertNotNil(cache.getBuffer(label: "timeout-keep-test"))
    }


    func testSessionCacheThreadSafety() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .oneHour

        let key = Curve25519.Signing.PrivateKey()
        DispatchQueue.concurrentPerform(iterations: 100) { i in
            let label = "key-\(i % 10)"
            if i % 4 == 0 {
                cache.set(label: label, key: key)
            } else if i % 4 == 1 {
                _ = cache.getBuffer(label: label)
            } else if i % 4 == 2 {
                _ = cache.cachedCount
            } else {
                cache.currentTimeout = (i % 2 == 0) ? .fifteenMinutes : .oneHour
            }
        }
    }


    func testSessionCacheHighConcurrencyStress() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .oneHour

        let sampleKeys = (0..<10).map { _ in Curve25519.Signing.PrivateKey() }

        DispatchQueue.concurrentPerform(iterations: 10000) { i in
            let label = "key-\(i % 10)"
            let op = i % 5
            switch op {
            case 0:
                cache.set(label: label, key: sampleKeys[i % 10])
            case 1:
                _ = cache.getBuffer(label: label)
            case 2:
                _ = cache.cachedCount
            case 3:
                cache.currentTimeout = (i % 2 == 0) ? .fiveMinutes : .never
            case 4:
                cache.clearCache()
            default:
                break
            }
        }
    }


    func testSessionCacheSetDoubleLockWindow() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .never

        let key = Curve25519.Signing.PrivateKey()
        // Setting a key when timeout is .never should not store/return key
                cache.set(label: "double-lock-test", key: key)
        XCTAssertNil(cache.getBuffer(label: "double-lock-test"))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testSessionCacheRejectsStoreAfterLock() {
        let cache = makeSessionCache()
        cache.currentTimeout = .fiveMinutes
        let generation = cache.generationSnapshot()

        cache.clearCache()

        let stored = cache.set(
            label: "stale-authentication",
            key: Curve25519.Signing.PrivateKey(),
            expectedGeneration: generation
        )
        XCTAssertFalse(stored)
        XCTAssertNil(cache.getBuffer(label: "stale-authentication"))
    }


    func testSessionCacheSerializesActiveOperationWithLock() throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .fiveMinutes

        var seed = Curve25519.Signing.PrivateKey().rawRepresentation
        guard let buffer = SecureBuffer(consuming: &seed) else {
            XCTFail("Failed to allocate secure buffer")
            return
        }
        XCTAssertTrue(cache.set(label: "atomic-operation", buffer: buffer))

        let operationStarted = expectation(description: "Cached operation started")
        let operationCompleted = expectation(description: "Cached operation completed")
        let allowOperationToFinish = DispatchSemaphore(value: 0)
        let clearAttempted = DispatchSemaphore(value: 0)
        let clearCompleted = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            _ = try? cache.withCachedBuffer(label: "atomic-operation") { _ in
                operationStarted.fulfill()
                _ = allowOperationToFinish.wait(timeout: .now() + 2)
                return true
            }
            operationCompleted.fulfill()
        }

        wait(for: [operationStarted], timeout: 1)
        DispatchQueue.global().async {
            clearAttempted.signal()
            cache.clearCache()
            clearCompleted.signal()
        }

        XCTAssertEqual(clearAttempted.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            clearCompleted.wait(timeout: .now() + 0.05),
            .timedOut,
            "Lock must wait for an operation that already holds the cache lock"
        )

        allowOperationToFinish.signal()
        wait(for: [operationCompleted], timeout: 1)
        XCTAssertEqual(clearCompleted.wait(timeout: .now() + 1), .success)
        XCTAssertTrue(buffer.isWiped)
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testDistributedLockAllNotification() throws {
        let cache = SessionCacheManager(observeSystemEvents: true)
        let label = "dist-test-\(UUID().uuidString)"
        cache.set(label: label, key: Curve25519.Signing.PrivateKey())
        XCTAssertTrue(cache.isKeyUnlocked(label: label))

        // Simulate broadcast from another process
        DistributedNotificationCenter.default().postNotificationName(
            NSNotification.Name("com.clavis.lockAll"),
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )

        // Allow runloop tick for notification delivery
        let deadline = Date().addingTimeInterval(0.5)
        var cleared = false
        while Date() < deadline {
            if !cache.isKeyUnlocked(label: label) {
                cleared = true
                break
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertTrue(cleared, "Cache should be cleared after receiving com.clavis.lockAll distributed notification")
    }


}
