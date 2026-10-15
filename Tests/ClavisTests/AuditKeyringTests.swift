import Testing
import Foundation
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

@Suite struct AuditKeyringTests {

    @Test func test_008_C1_writerGetsPublicKeyWithoutContext() throws {
        let keyring = SoftwareAuditKeyring(requireContext: true)
        // Writers should get the current public key without passing any LAContext
        let pubKey = try keyring.currentPublicKey()
        #expect(!pubKey.keyID.isEmpty)
        #expect(pubKey.keyID.count == 16)
        // Check that subsequent calls return the same key
        let secondPubKey = try keyring.currentPublicKey()
        #expect(pubKey.keyID == secondPubKey.keyID)
        #expect(pubKey.publicKey.x963Representation == secondPubKey.publicKey.x963Representation)
        // Writer calling currentPublicKey made 0 agreeCalls
        #expect(keyring.agreeCalls == 0)
    }

    @Test func test_008_C2_serviceIsDistinctFromVault() {
        #expect(
            KeychainAuditKeyring.defaultService != KeychainMasterKeyPinStore.serviceName,
            "Audit keyring service must be distinct from vault pin store service"
        )
    }

    @Test func test_008_T2_validateDetectsMismatch() throws {
        let keyring = SoftwareAuditKeyring(requireContext: false)
        let pubKey = try keyring.currentPublicKey()

        // Valid key should be ok
        let statusBefore = keyring.validateCurrent(context: nil)
        #expect(statusBefore == .ok)

        // Tamper with public key stored in the item
        let attackerPriv = P256.KeyAgreement.PrivateKey()
        keyring.tamperPublicKey(for: pubKey.keyID, with: attackerPriv.publicKey)

        let statusAfter = keyring.validateCurrent(context: nil)
        #expect(statusAfter == .mismatch)
    }

    @Test(.enabled(if: PlatformSupport.hasSecureEnclave && ProcessInfo.processInfo.environment["CLAVIS_RUN_SE_TESTS"] == "1"))
    func test_008_T2_concurrentCreateConvergesOnOneKey() throws {
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
        #expect(k1.keyID == k2.keyID)
        #expect(k1.publicKey.x963Representation == k2.publicKey.x963Representation)
    }

    @Test func test_004_T2_accessControlFlagsPerMode() throws {
        #expect(flags(for: .passwordOrBiometry) == [.privateKeyUsage, .userPresence])
        #expect(flags(for: .biometryOrPIN) == [.privateKeyUsage, .biometryAny, .or, .applicationPassword])
        #expect(flags(for: .biometryAndPIN) == [.privateKeyUsage, .biometryAny, .and, .applicationPassword])

        #expect(!AuditReadMode.passwordOrBiometry.requiresPIN)
        #expect(AuditReadMode.biometryOrPIN.requiresPIN)
        #expect(AuditReadMode.biometryAndPIN.requiresPIN)

        // Verify accessControl creation succeeds for each mode
        #expect(throws: Never.self) {
            _ = try accessControl(for: .passwordOrBiometry)
        }
        #expect(throws: Never.self) {
            _ = try accessControl(for: .biometryOrPIN)
        }
        #expect(throws: Never.self) {
            _ = try accessControl(for: .biometryAndPIN)
        }
    }

    @Test func test_004_T2_softwareKeyringModesAndLifecycle() throws {
        let pinContext = LAContext()
        let wrongContext = LAContext()
        defer {
            TestContextPinRegistry.shared.removePIN(for: pinContext)
            TestContextPinRegistry.shared.removePIN(for: wrongContext)
        }
        let keyring = SoftwareAuditKeyring(requireContext: true)

        let initialKey = try keyring.currentPublicKey()
        #expect(try keyring.currentMode() == .passwordOrBiometry)

        // Create new PIN-bound key
        TestContextPinRegistry.shared.setPIN("123456", for: pinContext)
        let pinKey = try keyring.createKey(mode: .biometryOrPIN, context: pinContext)
        #expect(pinKey.keyID != initialKey.keyID)

        // Current mode is still passwordOrBiometry until setCurrent
        #expect(try keyring.currentMode() == .passwordOrBiometry)

        // Switch current
        try keyring.setCurrent(keyID: pinKey.keyID)
        #expect(try keyring.currentMode() == .biometryOrPIN)
        #expect(try keyring.currentPublicKey().keyID == pinKey.keyID)

        // Validate current with correct PIN context is ok
        #expect(keyring.validateCurrent(context: pinContext) == .ok)

        // Validate current with wrong PIN context is unusable
        TestContextPinRegistry.shared.setPIN("wrong!", for: wrongContext)
        #expect(keyring.validateCurrent(context: wrongContext) == .unusable)

        // Deleting current key fails
        #expect {
            try keyring.deleteKey(keyID: pinKey.keyID)
        } throws: { error in
            error as? AuditKeyringError == .cannotDeleteCurrentKey
        }

        // Deleting old key succeeds
        try keyring.deleteKey(keyID: initialKey.keyID)
        let knownIDs = try keyring.knownKeyIDs()
        #expect(!knownIDs.contains(initialKey.keyID))
        #expect(knownIDs.contains(pinKey.keyID))
    }
}
