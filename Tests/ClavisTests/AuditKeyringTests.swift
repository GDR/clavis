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

    func test_004_T2_accessControlFlagsPerMode() throws {
        XCTAssertEqual(flags(for: .passwordOrBiometry), [.privateKeyUsage, .userPresence])
        XCTAssertEqual(flags(for: .biometryOrPIN), [.privateKeyUsage, .biometryAny, .or, .applicationPassword])
        XCTAssertEqual(flags(for: .biometryAndPIN), [.privateKeyUsage, .biometryAny, .and, .applicationPassword])

        XCTAssertFalse(AuditReadMode.passwordOrBiometry.requiresPIN)
        XCTAssertTrue(AuditReadMode.biometryOrPIN.requiresPIN)
        XCTAssertTrue(AuditReadMode.biometryAndPIN.requiresPIN)

        // Verify accessControl creation succeeds for each mode
        XCTAssertNoThrow(try accessControl(for: .passwordOrBiometry))
        XCTAssertNoThrow(try accessControl(for: .biometryOrPIN))
        XCTAssertNoThrow(try accessControl(for: .biometryAndPIN))
    }

    func test_004_T2_softwareKeyringModesAndLifecycle() throws {
        let keyring = SoftwareAuditKeyring(requireContext: true)

        let initialKey = try keyring.currentPublicKey()
        XCTAssertEqual(try keyring.currentMode(), .passwordOrBiometry)

        // Create new PIN-bound key
        let pinContext = LAContext()
        TestContextPinRegistry.shared.setPIN("123456", for: pinContext)
        let pinKey = try keyring.createKey(mode: .biometryOrPIN, context: pinContext)
        XCTAssertNotEqual(pinKey.keyID, initialKey.keyID)

        // Current mode is still passwordOrBiometry until setCurrent
        XCTAssertEqual(try keyring.currentMode(), .passwordOrBiometry)

        // Switch current
        try keyring.setCurrent(keyID: pinKey.keyID)
        XCTAssertEqual(try keyring.currentMode(), .biometryOrPIN)
        XCTAssertEqual(try keyring.currentPublicKey().keyID, pinKey.keyID)

        // Validate current with correct PIN context is ok
        XCTAssertEqual(keyring.validateCurrent(context: pinContext), .ok)

        // Validate current with wrong PIN context is unusable
        let wrongContext = LAContext()
        TestContextPinRegistry.shared.setPIN("wrong!", for: wrongContext)
        XCTAssertEqual(keyring.validateCurrent(context: wrongContext), .unusable)

        // Deleting current key fails
        XCTAssertThrowsError(try keyring.deleteKey(keyID: pinKey.keyID)) { error in
            XCTAssertEqual(error as? AuditKeyringError, .cannotDeleteCurrentKey)
        }

        // Deleting old key succeeds
        try keyring.deleteKey(keyID: initialKey.keyID)
        let knownIDs = try keyring.knownKeyIDs()
        XCTAssertFalse(knownIDs.contains(initialKey.keyID))
        XCTAssertTrue(knownIDs.contains(pinKey.keyID))
    }
}
