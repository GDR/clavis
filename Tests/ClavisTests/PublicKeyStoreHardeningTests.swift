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
}
