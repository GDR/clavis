import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

final class AuditKeyringTests: ClavisBaseTestCase {
    func test_008_C1_writerGetsPublicKeyWithoutContext() throws {
        let keyring = SoftwareAuditKeyring(requireContext: true)
        // Writers should get the current public key without passing any LAContext
        let pubKey = try keyring.currentPublicKey()
        XCTAssertFalse(pubKey.keyID.isEmpty)
        XCTAssertEqual(pubKey.keyID.count, 16)
        // Check that subsequent calls return the same key
        let secondPubKey = try keyring.currentPublicKey()
        XCTAssertEqual(pubKey.keyID, secondPubKey.keyID)
        XCTAssertEqual(pubKey.publicKey.x963Representation, secondPubKey.publicKey.x963Representation)
        // Writer calling currentPublicKey made 0 agreeCalls
        XCTAssertEqual(keyring.agreeCalls, 0)
    }

    func test_008_C2_serviceIsDistinctFromVault() {
        XCTAssertNotEqual(
            KeychainAuditKeyring.defaultService,
            KeychainMasterKeyPinStore.serviceName,
            "Audit keyring service must be distinct from vault pin store service"
        )
    }

    func test_008_T2_validateDetectsMismatch() throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let pubKey = try keyring.currentPublicKey()

        // Valid key should be ok
        let statusBefore = keyring.validateCurrent(context: nil)
        XCTAssertEqual(statusBefore, .ok)

        // Tamper with public key stored in the item
        let attackerPriv = P256.KeyAgreement.PrivateKey()
        keyring.tamperPublicKey(for: pubKey.keyID, with: attackerPriv.publicKey)

        let statusAfter = keyring.validateCurrent(context: nil)
        XCTAssertEqual(statusAfter, .mismatch)
    }

    func test_008_T2_concurrentCreateConvergesOnOneKey() throws {
        try XCTSkipUnless(PlatformSupport.hasSecureEnclave)
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLAVIS_RUN_SE_TESTS"] == "1")

        let testService = "com.clavis.audit-read.test.\(UUID().uuidString)"
        let keyring1 = KeychainAuditKeyring(service: testService)
        let keyring2 = KeychainAuditKeyring(service: testService)

        defer {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: testService
            ]
            SecItemDelete(query as CFDictionary)
        }

        let k1 = try keyring1.currentPublicKey()
        let k2 = try keyring2.currentPublicKey()
        XCTAssertEqual(k1.keyID, k2.keyID)
        XCTAssertEqual(k1.publicKey.x963Representation, k2.publicKey.x963Representation)
    }
}
