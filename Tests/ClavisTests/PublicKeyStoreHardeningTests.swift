import Testing
import Foundation
@testable import ClavisCore

@Suite(.serialized) struct PublicKeyStoreHardeningTests {

    private func makeKey(label: String) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest \(label)",
            publicKeyBlob: Data(repeating: 0x01, count: 32),
            fingerprint: "SHA256:test"
        )
    }

    @Test func testSaveToKeychainInvalidatesCache() throws {
        PublicKeyStore.resetForTesting()
        PublicKeyStore.disableKeychainMirrorForTesting = true
        defer { PublicKeyStore.resetForTesting() }

        let key1 = makeKey(label: "key-1")
        try PublicKeyStore.saveToKeychainChecked(key1)

        let loaded = PublicKeyStore.loadAll()
        #expect(loaded.count == 1)
        #expect(loaded.first?.label == "key-1")

        // Save second key via saveToKeychainChecked
        let key2 = makeKey(label: "key-2")
        try PublicKeyStore.saveToKeychainChecked(key2)

        // Cache must have been invalidated so loadAll returns both
        let reloaded = PublicKeyStore.loadAll()
        #expect(reloaded.count == 2)
        #expect(reloaded.map(\.label).sorted() == ["key-1", "key-2"])
    }

    @Test func testRemoveFromKeychainInvalidatesCache() throws {
        PublicKeyStore.resetForTesting()
        PublicKeyStore.disableKeychainMirrorForTesting = true
        defer { PublicKeyStore.resetForTesting() }

        let key1 = makeKey(label: "key-1")
        let key2 = makeKey(label: "key-2")
        try PublicKeyStore.saveToKeychainChecked(key1)
        try PublicKeyStore.saveToKeychainChecked(key2)

        #expect(PublicKeyStore.loadAll().count == 2)

        // Remove key-1
        try PublicKeyStore.removeFromKeychainChecked(label: "key-1")

        // Cache must be invalidated
        let reloaded = PublicKeyStore.loadAll()
        #expect(reloaded.count == 1)
        #expect(reloaded.first?.label == "key-2")
    }

    @Test func testConcurrentLoadAllDoesNotDeadlock() async throws {
        PublicKeyStore.resetForTesting()
        PublicKeyStore.disableKeychainMirrorForTesting = true
        defer { PublicKeyStore.resetForTesting() }

        let key = makeKey(label: "concurrent-key")
        try PublicKeyStore.saveToKeychainChecked(key)

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    let keys = PublicKeyStore.loadAll()
                    #expect(keys.contains(where: { $0.label == "concurrent-key" }))
                }
            }
        }
    }

    @Test func testStaleCacheWritePreventedByGenerationCounterOnConcurrentInvalidate() throws {
        PublicKeyStore.resetForTesting()
        defer {
            PublicKeyStore.resetForTesting()
        }

        let staleKey = makeKey(label: "stale-key")
        let inFlight = DispatchSemaphore(value: 0)
        let invalidated = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)

        let loader: @Sendable () -> [SSHKeyInfo] = {
            inFlight.signal()
            _ = invalidated.wait(timeout: .now() + 5.0)
            return [staleKey]
        }

        let workerQueue = DispatchQueue(label: "com.clavis.test.publickeystore.stale")
        workerQueue.async {
            PublicKeyStore.$testKeychainLoader.withValue(loader) {
                let loaded = PublicKeyStore.loadAll()
                #expect(loaded.map(\.label) == ["stale-key"])
                done.signal()
            }
        }

        // Wait until loadAll is inside the keychain loader
        #expect(inFlight.wait(timeout: .now() + 5.0) == .success)

        let genBefore = PublicKeyStore.generationForTesting
        // Invalidate cache concurrently while loadAll is reading
        PublicKeyStore.invalidateCache()
        let genAfter = PublicKeyStore.generationForTesting
        #expect(genAfter == genBefore + 1, "invalidateCache must increment generation counter")

        // Allow loadAll to finish its stale read
        invalidated.signal()

        #expect(done.wait(timeout: .now() + 5.0) == .success)

        // Since generation changed during the read, cachedKeys must NOT be populated with stale keys
        #expect(PublicKeyStore.cachedKeysForTesting == nil, "cachedKeys must not be overwritten with stale data after invalidateCache()")
    }

    @Test func testConcurrentLoadAllAndInvalidateWithBarrier() async throws {
        PublicKeyStore.resetForTesting()
        defer {
            PublicKeyStore.resetForTesting()
        }

        let testKey = makeKey(label: "concurrent-key")
        let loader: @Sendable () -> [SSHKeyInfo] = {
            usleep(useconds_t.random(in: 100...1000))
            return [testKey]
        }

        await PublicKeyStore.$testKeychainLoader.withValue(loader) {
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
}
