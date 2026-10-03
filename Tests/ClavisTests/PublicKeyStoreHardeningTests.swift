import XCTest
@testable import ClavisCore

final class PublicKeyStoreHardeningTests: ClavisBaseTestCase {

    override func setUpWithError() throws {
        try super.setUpWithError()
        PublicKeyStore.disableKeychainMirrorForTesting = true
        PublicKeyStore.resetForTesting()
    }

    override func tearDownWithError() throws {
        PublicKeyStore.resetForTesting()
        try super.tearDownWithError()
    }

    private func makeKey(label: String) -> Ed25519KeyInfo {
        Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest \(label)",
            publicKeyBlob: Data(repeating: 0x01, count: 32),
            fingerprint: "SHA256:test"
        )
    }

    func testSaveToKeychainInvalidatesCache() throws {
        let key1 = makeKey(label: "key-1")
        try PublicKeyStore.saveToKeychainChecked(key1)

        let loaded = PublicKeyStore.loadAll()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.label, "key-1")

        // Save second key via saveToKeychainChecked
        let key2 = makeKey(label: "key-2")
        try PublicKeyStore.saveToKeychainChecked(key2)

        // Cache must have been invalidated so loadAll returns both
        let reloaded = PublicKeyStore.loadAll()
        XCTAssertEqual(reloaded.count, 2)
        XCTAssertEqual(reloaded.map(\.label).sorted(), ["key-1", "key-2"])
    }

    func testRemoveFromKeychainInvalidatesCache() throws {
        let key1 = makeKey(label: "key-1")
        let key2 = makeKey(label: "key-2")
        try PublicKeyStore.saveToKeychainChecked(key1)
        try PublicKeyStore.saveToKeychainChecked(key2)

        XCTAssertEqual(PublicKeyStore.loadAll().count, 2)

        // Remove key-1
        try PublicKeyStore.removeFromKeychainChecked(label: "key-1")

        // Cache must be invalidated
        let reloaded = PublicKeyStore.loadAll()
        XCTAssertEqual(reloaded.count, 1)
        XCTAssertEqual(reloaded.first?.label, "key-2")
    }

    func testConcurrentLoadAllDoesNotDeadlock() async throws {
        let key = makeKey(label: "concurrent-key")
        try PublicKeyStore.saveToKeychainChecked(key)

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    let keys = PublicKeyStore.loadAll()
                    XCTAssertEqual(keys.count, 1)
                }
            }
        }
    }

    func testStaleCacheWritePreventedByGenerationCounterOnConcurrentInvalidate() throws {
        PublicKeyStore.disableKeychainMirrorForTesting = false
        defer { PublicKeyStore.disableKeychainMirrorForTesting = true }

        let staleKey = makeKey(label: "stale-key")
        let inFlight = DispatchSemaphore(value: 0)
        let invalidated = DispatchSemaphore(value: 0)

        PublicKeyStore.keychainLoader = {
            inFlight.signal()
            invalidated.wait()
            return [staleKey]
        }

        let loadExpectation = expectation(description: "loadAll completes")
        DispatchQueue.global(qos: .userInitiated).async {
            let loaded = PublicKeyStore.loadAll()
            XCTAssertEqual(loaded.map(\.label), ["stale-key"])
            loadExpectation.fulfill()
        }

        // Wait until loadAll is inside the keychain loader
        inFlight.wait()

        let genBefore = PublicKeyStore.generationForTesting
        // Invalidate cache concurrently while loadAll is reading
        PublicKeyStore.invalidateCache()
        let genAfter = PublicKeyStore.generationForTesting
        XCTAssertEqual(genAfter, genBefore + 1, "invalidateCache must increment generation counter")

        // Allow loadAll to finish its stale read
        invalidated.signal()

        wait(for: [loadExpectation], timeout: 5.0)

        // Since generation changed during the read, cachedKeys must NOT be populated with stale keys
        XCTAssertNil(PublicKeyStore.cachedKeysForTesting, "cachedKeys must not be overwritten with stale data after invalidateCache()")
    }

    func testConcurrentLoadAllAndInvalidateWithBarrier() async throws {
        PublicKeyStore.disableKeychainMirrorForTesting = false
        defer { PublicKeyStore.disableKeychainMirrorForTesting = true }

        let testKey = makeKey(label: "concurrent-key")
        PublicKeyStore.keychainLoader = {
            usleep(useconds_t.random(in: 100...1000))
            return [testKey]
        }

        await withTaskGroup(of: Void.self) { group in
            for i in 0..<24 {
                if i % 4 == 0 {
                    group.addTask {
                        PublicKeyStore.invalidateCache()
                    }
                } else {
                    group.addTask {
                        _ = PublicKeyStore.loadAll()
                    }
                }
            }
        }
    }
}
