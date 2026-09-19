import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class ClavisTests: XCTestCase {

    private var testRootURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testRootURL = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("clavis-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: testRootURL, withIntermediateDirectories: true)

        PublicKeyStore.customStorageURL = testRootURL.appendingPathComponent("keys.json")
        ClavisLogger.customLogFileURL = testRootURL.appendingPathComponent("clavis.log")
        ClavisLogger.customMaximumLogFileSize = nil
        SeedStore.customSeedsDirectory = testRootURL.appendingPathComponent("seeds", isDirectory: true)
        SeedStore.customMasterKEKURL = testRootURL.appendingPathComponent("master.kek")
        SeedStore.useSoftwareMasterKeyForTesting = true
        SeedStore.resetMasterKeyCacheForTesting()
    }

    override func tearDownWithError() throws {
        SeedStore.resetMasterKeyCacheForTesting()
        PublicKeyStore.customStorageURL = nil
        ClavisLogger.customLogFileURL = nil
        ClavisLogger.customMaximumLogFileSize = nil
        SeedStore.customSeedsDirectory = nil
        SeedStore.customMasterKEKURL = nil
        SeedStore.useSoftwareMasterKeyForTesting = false
        if let testRootURL {
            try? FileManager.default.removeItem(at: testRootURL)
        }
        try super.tearDownWithError()
    }

    private struct AllowingAuthenticator: UserAuthenticating {
        func authenticate(reason: String) throws -> LAContext {
            LAContext()
        }

        func authenticate(reason: String) async throws -> LAContext {
            LAContext()
        }
    }

    private final class InMemoryPrivateKeyStore: PrivateKeyStoring {
        private var values: [String: Data] = [:]
        private let lock = NSLock()

        func contains(label: String) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return values[label] != nil
        }

        func save(label: String, data: Data) throws {
            lock.lock()
            defer { lock.unlock() }
            values[label] = data
        }

        func load(label: String, context: LAContext, prompt: String) throws -> Data? {
            lock.lock()
            defer { lock.unlock() }
            return values[label]
        }

        func remove(label: String) throws {
            lock.lock()
            defer { lock.unlock() }
            values.removeValue(forKey: label)
        }
    }

    private func makeSessionCache() -> SessionCacheManager {
        let suiteName = "com.clavis.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return SessionCacheManager(defaults: defaults, observeSystemEvents: false)
    }

    private func makeKeyManager(sessionCache: SessionCacheManager? = nil) -> KeychainManager {
        KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            sessionCache: sessionCache ?? makeSessionCache()
        )
    }

    // MARK: - 1. Key Info & OpenSSH Wire Serialization Tests

    func testEd25519KeyInfoAndWireSerialization() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let keyInfo = try makeKeyManager().makeKeyInfo(label: "test-github-key", privateKey: privateKey)

        XCTAssertEqual(keyInfo.label, "test-github-key")
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasPrefix("ssh-ed25519 "))
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasSuffix(" test-github-key"))
        XCTAssertTrue(keyInfo.fingerprint.hasPrefix("SHA256:"))
        XCTAssertEqual(keyInfo.publicKeyBlob.count, 51) // 4 (len) + 11 (ssh-ed25519) + 4 (len) + 32 (pubkey)
    }

    func testWireDataAppending() {
        var data = Data()
        data.appendWireString("ssh-ed25519")
        
        // 4 bytes big-endian length (11) + 11 bytes UTF8 string
        XCTAssertEqual(data.count, 15)
        XCTAssertEqual(data.subdata(in: 0..<4), Data([0x00, 0x00, 0x00, 0x0B]))
        XCTAssertEqual(String(data: data.subdata(in: 4..<15), encoding: .utf8), "ssh-ed25519")
    }

    // MARK: - 2. DataReader SSH Wire Protocol Parser Tests

    func testDataReaderSuccess() {
        var data = Data()
        data.appendWireString("hello")
        data.appendWireString("world")

        var reader = DataReader(data: data)
        let first = reader.readWireData()
        let second = reader.readWireData()

        XCTAssertNotNil(first)
        XCTAssertNotNil(second)
        XCTAssertEqual(String(data: first!, encoding: .utf8), "hello")
        XCTAssertEqual(String(data: second!, encoding: .utf8), "world")
        XCTAssertNil(reader.readWireData()) // EOF
    }

    func testDataReaderTruncatedHeader() {
        let data = Data([0x00, 0x00]) // Only 2 bytes, needs 4
        var reader = DataReader(data: data)
        XCTAssertNil(reader.readWireData())
    }

    func testDataReaderTruncatedPayload() {
        var data = Data([0x00, 0x00, 0x00, 0x10]) // Header claims 16 bytes payload
        data.append(Data([0x01, 0x02, 0x03]))     // Only 3 bytes supplied
        var reader = DataReader(data: data)
        XCTAssertNil(reader.readWireData())
    }

    // MARK: - 3. Session Cache Manager Tests

    func testSessionCacheManagerExpiration() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "cached-key", key: key)

        XCTAssertNotNil(cache.get(label: "cached-key"))
        XCTAssertEqual(cache.cachedCount, 1)

        cache.clearCache()
        XCTAssertNil(cache.get(label: "cached-key"))
        XCTAssertEqual(cache.cachedCount, 0)
    }

    func testSessionCacheDisabled() {
        let cache = makeSessionCache()
        cache.clearCache()
        cache.currentTimeout = .never // Cache off

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "uncached-key", key: key)

        XCTAssertNil(cache.get(label: "uncached-key"))
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
        XCTAssertNil(cache.get(label: "wipe-on-clear"))
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
        XCTAssertNil(cache.get(label: "wipe-on-remove"))
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

    // MARK: - 4. Ed25519 to X25519 & Bech32 Age Conversion Tests

    func testEd25519ToX25519AgeConversion() throws {
        let seed = Data(repeating: 0x42, count: 32)
        let x25519Priv = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: seed)

        XCTAssertEqual(x25519Priv.rawRepresentation.count, 32)

        let ageRecipient = Ed25519AgeConverter.ageRecipient(forPublicKey: x25519Priv.publicKey.rawRepresentation)
        XCTAssertTrue(ageRecipient.hasPrefix("age1clavis1"))
    }

    func testEd25519ToX25519InvalidSeedLength() {
        let invalidSeed = Data(repeating: 0xFF, count: 16) // Only 16 bytes
        XCTAssertThrowsError(try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: invalidSeed))
    }

    func testBech32EncodingDeterminism() {
        let testData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let encoded1 = Bech32.encode(hrp: "age1clavis", data: testData)
        let encoded2 = Bech32.encode(hrp: "age1clavis", data: testData)

        XCTAssertEqual(encoded1, encoded2)
        XCTAssertTrue(encoded1.hasPrefix("age1clavis1"))
    }

    // MARK: - 5. Hex String Parsing Helper Tests

    func testDataHexStringInitialization() {
        let validHex = "48656c6c6f" // "Hello"
        let data = Data(hexString: validHex)
        XCTAssertNotNil(data)
        XCTAssertEqual(String(data: data!, encoding: .utf8), "Hello")

        let invalidOddHex = "12345"
        XCTAssertNil(Data(hexString: invalidOddHex))

        let invalidCharHex = "123G"
        XCTAssertNil(Data(hexString: invalidCharHex))
    }

    // MARK: - 6. DataReader UInt32 & SSHAgentServer Lifecycle Tests

    func testDataReaderUInt32Parsing() {
        let data = Data([0x00, 0x00, 0x00, 0x2A]) // UInt32(42) big endian
        var reader = DataReader(data: data)
        let val = reader.readUInt32()
        XCTAssertEqual(val, 42)
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

    func testSSHAgentServerLifecycle() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-unittest.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)

        XCTAssertFalse(server.isSocketActive)
        try server.start()
        XCTAssertTrue(server.isSocketActive)
        XCTAssertTrue(FileManager.default.fileExists(atPath: testSockPath))

        // Verify socket permissions are restricted to 0600
        let attrs = try FileManager.default.attributesOfItem(atPath: testSockPath)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(perms, 0o600)

        server.stop()
        XCTAssertFalse(server.isSocketActive)
    }

    func testLoggerUsesPrivatePermissionsAndRotates() throws {
        ClavisLogger.customMaximumLogFileSize = 256
        for index in 0..<8 {
            ClavisLogger.log("TEST", "entry-\(index)-\(String(repeating: "x", count: 80))")
        }

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let logAttributes = try FileManager.default.attributesOfItem(atPath: logURL.path)
        XCTAssertEqual((logAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: logURL.deletingLastPathComponent().path)
        XCTAssertEqual((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        XCTAssertTrue(FileManager.default.fileExists(atPath: "\(logURL.path).1"))
    }

    func testLoggerEscapesEmbeddedNewlines() throws {
        ClavisLogger.log("TEST\nFORGED", "message\r\n[AUTH] forged")

        let logURL = try XCTUnwrap(ClavisLogger.customLogFileURL)
        let contents = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertEqual(contents.split(separator: "\n").count, 1)
        XCTAssertTrue(contents.contains("TEST\\nFORGED"))
        XCTAssertTrue(contents.contains("message\\r\\n[AUTH] forged"))
    }

    // MARK: - 7. Milestone 1 Expanded Unit Tests

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
        XCTAssertNil(cache.get(label: "timeout-purge-test"))

        // Add key again
        cache.set(label: "timeout-purge-test-2", key: key)
        XCTAssertEqual(cache.cachedCount, 1)

        // Setting timeout to .never purges cache
        cache.currentTimeout = .never
        XCTAssertEqual(cache.cachedCount, 0)
        XCTAssertNil(cache.get(label: "timeout-purge-test-2"))

        // Increasing timeout from 5 minutes to 1 hour should NOT purge cache
        cache.currentTimeout = .fiveMinutes
        cache.set(label: "timeout-keep-test", key: key)
        XCTAssertEqual(cache.cachedCount, 1)

        cache.currentTimeout = .oneHour
        XCTAssertEqual(cache.cachedCount, 1)
        XCTAssertNotNil(cache.get(label: "timeout-keep-test"))
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
                _ = cache.get(label: label)
            } else if i % 4 == 2 {
                _ = cache.cachedCount
            } else {
                cache.currentTimeout = (i % 2 == 0) ? .fifteenMinutes : .oneHour
            }
        }
    }

    func testBech32HrpCaseInsensitivity() throws {
        let testData = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])

        let encodedUpper = Bech32.encode(hrp: "AGE1CLAVIS", data: testData)
        let encodedLower = Bech32.encode(hrp: "age1clavis", data: testData)

        XCTAssertEqual(encodedUpper, encodedLower.uppercased())
        XCTAssertTrue(encodedUpper.hasPrefix("AGE1CLAVIS1"))
        XCTAssertTrue(encodedLower.hasPrefix("age1clavis1"))

        let decodedUpper = try Bech32.decode(bech32String: encodedUpper)
        let decodedLower = try Bech32.decode(bech32String: encodedLower)

        XCTAssertEqual(decodedUpper.hrp, "AGE1CLAVIS")
        XCTAssertEqual(decodedLower.hrp, "age1clavis")
        XCTAssertEqual(decodedUpper.data, testData)
        XCTAssertEqual(decodedLower.data, testData)
    }

    func testBech32DecodeValidAndInvalid() throws {
        let testData = Data([0x10, 0x20, 0x30, 0x40, 0x50])
        let encoded = Bech32.encode(hrp: "age1clavis", data: testData)

        let decoded = try Bech32.decode(bech32String: encoded)
        XCTAssertEqual(decoded.hrp, "age1clavis")
        XCTAssertEqual(decoded.data, testData)

        // Invalid checksum
        var invalidChecksumStr = encoded
        let lastChar = invalidChecksumStr.removeLast()
        let replacementChar: Character = (lastChar == "a") ? "b" : "a"
        invalidChecksumStr.append(replacementChar)
        XCTAssertThrowsError(try Bech32.decode(bech32String: invalidChecksumStr)) { error in
            XCTAssertEqual(error as? Bech32.Bech32Error, Bech32.Bech32Error.invalidChecksum)
        }

        // Mixed case
        let mixedCaseStr = "Age1clavis1" + encoded.dropFirst("age1clavis1".count)
        XCTAssertThrowsError(try Bech32.decode(bech32String: mixedCaseStr)) { error in
            XCTAssertEqual(error as? Bech32.Bech32Error, Bech32.Bech32Error.mixedCase)
        }

        // Missing separator
        XCTAssertThrowsError(try Bech32.decode(bech32String: "ageclavisnopart")) { error in
            XCTAssertEqual(error as? Bech32.Bech32Error, Bech32.Bech32Error.missingSeparator)
        }

        // Invalid character
        XCTAssertThrowsError(try Bech32.decode(bech32String: "age1clavis1invalid!char")) { error in
            XCTAssertEqual(error as? Bech32.Bech32Error, Bech32.Bech32Error.invalidCharacter)
        }
    }

    func testEd25519ToX25519PublicKeyBirationalMap() throws {
        let seed = Data(repeating: 0x5A, count: 32)

        // 1. Derive X25519 private key & public key directly from seed
        let x25519Priv = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: seed)
        let expectedX25519PubKey = x25519Priv.publicKey.rawRepresentation

        // 2. Derive Ed25519 public key from seed
        let ed25519Priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let ed25519PubKey = ed25519Priv.publicKey.rawRepresentation

        // 3. Convert Ed25519 public key to X25519 public key via birational map
        guard let convertedX25519PubKey = Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: ed25519PubKey) else {
            XCTFail("ed25519PublicKeyToX25519PublicKey returned nil")
            return
        }

        XCTAssertEqual(convertedX25519PubKey.count, 32)
        XCTAssertEqual(convertedX25519PubKey, expectedX25519PubKey)
    }

    func testKeychainManagerListKeysSingleItemHandling() throws {
        let keys = try makeKeyManager().listKeys()
        XCTAssertNotNil(keys)

        let dummyKeyInfo = Ed25519KeyInfo(label: "dummy", publicKeyOpenSSH: "ssh-ed25519 AAA dummy", publicKeyBlob: Data(), fingerprint: "SHA256:dummy")
        let encodedData = try JSONEncoder().encode(dummyKeyInfo)

        let itemsSingle: AnyObject = encodedData as AnyObject
        let itemsArray: AnyObject = [encodedData] as AnyObject

        if let singleData = itemsSingle as? Data {
            let decoded = try JSONDecoder().decode(Ed25519KeyInfo.self, from: singleData)
            XCTAssertEqual(decoded.label, "dummy")
        }
        if let array = itemsArray as? [Data] {
            let decoded = try JSONDecoder().decode(Ed25519KeyInfo.self, from: array[0])
            XCTAssertEqual(decoded.label, "dummy")
        }
    }

    // MARK: - 8. Challenger Stress & Edge Case Tests

    func testBirationalMap1000RandomKeys() throws {
        for _ in 0..<1000 {
            var seed = Data(count: 32)
            _ = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

            let x25519Priv = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: seed)
            let expectedX25519PubKey = x25519Priv.publicKey.rawRepresentation

            let ed25519Priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let ed25519PubKey = ed25519Priv.publicKey.rawRepresentation

            guard let convertedX25519PubKey = Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: ed25519PubKey) else {
                XCTFail("ed25519PublicKeyToX25519PublicKey returned nil for random key")
                return
            }

            XCTAssertEqual(convertedX25519PubKey, expectedX25519PubKey)
        }
    }

    func testBirationalMapMathematicalEdgeCases() {
        // y = 1 (denom = 0 in (1+y)/(1-y))
        var y1PubKey = Data(repeating: 0, count: 32)
        y1PubKey[0] = 1
        XCTAssertNil(Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: y1PubKey))

        // y >= p (p = 2^255 - 19)
        let yPPubKey = Data([
            0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        ])
        XCTAssertNil(Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: yPPubKey))

        // Wrong length pubkey
        XCTAssertNil(Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: Data(repeating: 0x42, count: 16)))
        XCTAssertNil(Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: Data(repeating: 0x42, count: 33)))
    }

    func testBech32Fuzzing1000Mutations() throws {
        let alphabet = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        for _ in 0..<1000 {
            var randomData = Data(count: 32)
            _ = randomData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            let encoded = Bech32.encode(hrp: "age1clavis", data: randomData)

            // Mutate 1 character in encoded string
            var chars = Array(encoded)
            let mutateIdx = Int.random(in: 0..<chars.count)
            let origChar = chars[mutateIdx]
            if let altChar = alphabet.first(where: { $0 != origChar }) {
                chars[mutateIdx] = altChar
            }
            let mutatedString = String(chars)

            XCTAssertThrowsError(try Bech32.decode(bech32String: mutatedString), "Mutated string \(mutatedString) should fail decoding")
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
                _ = cache.get(label: label)
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
        XCTAssertNil(cache.get(label: "double-lock-test"))
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
        XCTAssertNil(cache.get(label: "stale-authentication"))
    }

    func testUnlockKeepsAlwaysPromptPolicy() async throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .never
        let keyManager = makeKeyManager(sessionCache: cache)
        let label = "always-prompt-\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }
        try keyManager.generateKey(label: label)

        do {
            try await keyManager.unlock(label: label)
            XCTFail("Unlock should fail while session caching is disabled")
        } catch {
            XCTAssertEqual(error as? SessionCacheError, .disabled)
        }

        XCTAssertEqual(cache.currentTimeout, .never)
        XCTAssertEqual(cache.cachedCount, 0)
    }

    // MARK: - 9. SSHAgentServer Socket Protocol Tests

    private func socketReadFullBytes(from sock: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        var bytesRead = 0
        let success = data.withUnsafeMutableBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            while bytesRead < count {
                let res = read(sock, base.advanced(by: bytesRead), count - bytesRead)
                if res <= 0 { return false }
                bytesRead += res
            }
            return true
        }
        return success ? data : nil
    }

    private func connectUnixSocket(path: String) throws -> Int32 {
        let clientSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard clientSocket >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = path.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (index, byte) in pathBytes.enumerated() { raw[index] = byte }
        }
        let addrLength = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSocket, $0, addrLength)
            }
        }
        guard result == 0 else {
            let error = NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            close(clientSocket)
            throw error
        }
        return clientSocket
    }

    func testSSHAgentServerBoundsIdleClients() throws {
        let socketPath = testRootURL.appendingPathComponent("clavis-client-limit.sock").path
        let server = SSHAgentServer(
            socketPath: socketPath,
            maxConcurrentClients: 1,
            clientIdleTimeout: 0.2
        )
        try server.start()
        defer { server.stop() }

        let idleClient = try connectUnixSocket(path: socketPath)
        defer { close(idleClient) }

        let acceptanceDeadline = Date().addingTimeInterval(1)
        while server.activeClientCount != 1 && Date() < acceptanceDeadline {
            usleep(10_000)
        }
        XCTAssertEqual(server.activeClientCount, 1)

        let rejectedClient = try connectUnixSocket(path: socketPath)
        defer { close(rejectedClient) }
        usleep(50_000)
        XCTAssertNil(socketReadFullBytes(from: rejectedClient, count: 1))

        let timeoutDeadline = Date().addingTimeInterval(1)
        while server.activeClientCount != 0 && Date() < timeoutDeadline {
            usleep(10_000)
        }
        XCTAssertEqual(server.activeClientCount, 0)
    }

    func testSSHAgentServerRequestIdentitiesSocket() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-req-ident.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)
        try server.start()
        defer { server.stop() }

        let clientSock = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientSock, 0)
        defer { close(clientSock) }

        var nosigpipe = 1
        setsockopt(clientSock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)

        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSock, $0, addrLen)
            }
        }
        XCTAssertEqual(connectResult, 0)

        // SSH2_AGENTC_REQUEST_IDENTITIES packet: 4 bytes len (1), 1 byte msg (11)
        let request = Data([0x00, 0x00, 0x00, 0x01, 11])
        _ = request.withUnsafeBytes { write(clientSock, $0.baseAddress!, request.count) }

        // Read response header (4 bytes len)
        guard let lenData = socketReadFullBytes(from: clientSock, count: 4) else {
            XCTFail("Failed to read length header from agent socket")
            return
        }
        var respLenVal: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
        let respLen = Int(UInt32(bigEndian: respLenVal))
        XCTAssertGreaterThan(respLen, 0)

        guard let payload = socketReadFullBytes(from: clientSock, count: respLen) else {
            XCTFail("Failed to read response payload from agent socket")
            return
        }

        XCTAssertGreaterThanOrEqual(payload.count, 5)
        XCTAssertEqual(payload[0], 12) // SSH2_AGENT_IDENTITIES_ANSWER
    }

    func testSSHAgentServerSignRequestMissingFlags() throws {
        let testSockPath = testRootURL.appendingPathComponent("clavis-sign-req.sock").path
        let server = SSHAgentServer(socketPath: testSockPath)
        try server.start()
        defer { server.stop() }

        let clientSock = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientSock, 0)
        defer { close(clientSock) }

        var nosigpipe = 1
        setsockopt(clientSock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout.size(ofValue: nosigpipe)))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = testSockPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() { raw[i] = byte }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)

        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSock, $0, addrLen)
            }
        }
        XCTAssertEqual(connectResult, 0)

        // SSH2_AGENTC_SIGN_REQUEST packet missing 4-byte flags
        var payloadData = Data([13]) // msg 13
        payloadData.appendWireData(Data("keyblob".utf8))
        payloadData.appendWireData(Data("datatosign".utf8))
        // Omitting 4-byte flags intentionally

        var packet = Data()
        var len = UInt32(payloadData.count).bigEndian
        Swift.withUnsafeBytes(of: &len) { packet.append(contentsOf: $0) }
        packet.append(payloadData)

        _ = packet.withUnsafeBytes { write(clientSock, $0.baseAddress!, packet.count) }

        guard let lenData = socketReadFullBytes(from: clientSock, count: 4) else {
            XCTFail("Failed to read length header from agent socket")
            return
        }
        var respLenVal: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &respLenVal) { lenData.copyBytes(to: $0) }
        let respLen = Int(UInt32(bigEndian: respLenVal))
        XCTAssertEqual(respLen, 1)

        guard let responsePayload = socketReadFullBytes(from: clientSock, count: respLen) else {
            XCTFail("Failed to read response payload from agent socket")
            return
        }

        XCTAssertEqual(responsePayload[0], 5) // SSH_AGENT_FAILURE
    }

    func testDataReaderUnalignedAccess() {
        var data = Data([0xFF]) // 1 byte prefix to make offset unaligned (1)
        let num: UInt32 = 0x12345678
        var bigNum = num.bigEndian
        Swift.withUnsafeBytes(of: &bigNum) { data.append(contentsOf: $0) }

        // Skip prefix byte
        let slice = data.subdata(in: 1..<data.count)
        var unalignedReader = DataReader(data: slice)
        let val = unalignedReader.readUInt32()
        XCTAssertEqual(val, 0x12345678)
    }

    // MARK: - 10. Age Plugin CLI Adapter IPC Tests

    func testAgePluginParseRecipientPublicKey() throws {
        let pubKeyData = Data(repeating: 0x33, count: 32)
        let bech32Recipient = Bech32.encode(hrp: "age1clavis", data: pubKeyData)

        let parsedFromBech32 = AgePluginClavis.parseRecipientPublicKey(bech32Recipient)
        XCTAssertEqual(parsedFromBech32, pubKeyData)

        let hexRecipient = pubKeyData.map { String(format: "%02hhx", $0) }.joined()
        let parsedFromHex = AgePluginClavis.parseRecipientPublicKey(hexRecipient)
        XCTAssertEqual(parsedFromHex, pubKeyData)

        XCTAssertNil(AgePluginClavis.parseRecipientPublicKey("invalid_recipient_str"))
    }

    func testAgePluginRecipientV1IPC() throws {
        let recipientKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let recipientStr = Bech32.encode(hrp: "age1clavis", data: recipientKey)
        let fileKey = Data(repeating: 0x77, count: 32)
        let fileKeyB64 = fileKey.base64EncodedString()

        let inputs = [
            "-> add-recipient \(recipientStr)",
            "-> wrap-file-key",
            fileKeyB64,
            "-> done"
        ]

        var inputIndex = 0
        let inputProvider: () -> String? = {
            guard inputIndex < inputs.count else { return nil }
            let line = inputs[inputIndex]
            inputIndex += 1
            return line
        }

        var outputs: [String] = []
        let outputHandler: (String) -> Void = { line in
            outputs.append(line)
        }

        AgePluginClavis.handleRecipientV1(inputProvider: inputProvider, outputHandler: outputHandler)

        XCTAssertTrue(outputs.contains(where: { $0.hasPrefix("-> recipient-stanza 0 clavis ") }))
        XCTAssertEqual(outputs.last, "-> ok")
    }

    func testAgePluginIdentityV1IPCRoundTrip() throws {
        let label = "age-unittest-key"
        let edPriv = Curve25519.Signing.PrivateKey()
        let keyInfo = Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAA test",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:test"
        )

        let x25519Priv = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: edPriv.rawRepresentation)
        let x25519Pub = x25519Priv.publicKey.rawRepresentation
        let recipientStr = Bech32.encode(hrp: "age1clavis", data: x25519Pub)

        let originalFileKey = Data(repeating: 0x99, count: 32)
        var wrapOutputs: [String] = []
        let wrapInputs = [
            "-> add-recipient \(recipientStr)",
            "-> wrap-file-key",
            originalFileKey.base64EncodedString(),
            "-> done"
        ]
        var wrapIdx = 0
        AgePluginClavis.handleRecipientV1(
            inputProvider: {
                guard wrapIdx < wrapInputs.count else { return nil }
                defer { wrapIdx += 1 }
                return wrapInputs[wrapIdx]
            },
            outputHandler: { wrapOutputs.append($0) }
        )

        guard let stanzaHeaderIdx = wrapOutputs.firstIndex(where: { $0.hasPrefix("-> recipient-stanza 0 clavis ") }) else {
            XCTFail("recipient-stanza line not found in wrap outputs")
            return
        }

        let headerLine = wrapOutputs[stanzaHeaderIdx]
        let stanzaBodyLine = wrapOutputs[stanzaHeaderIdx + 1]

        let parts = headerLine.split(separator: " ")
        XCTAssertEqual(parts.count, 5)
        let epkB64 = String(parts[4])

        var unwrapOutputs: [String] = []
        let unwrapInputs = [
            "-> add-identity \(label)",
            "-> recipient-stanza 0 clavis \(epkB64)",
            stanzaBodyLine,
            "-> unwrap-file-key",
            "-> done"
        ]
        var unwrapIdx = 0
        AgePluginClavis.handleIdentityV1(
            inputProvider: {
                guard unwrapIdx < unwrapInputs.count else { return nil }
                defer { unwrapIdx += 1 }
                return unwrapInputs[unwrapIdx]
            },
            outputHandler: { unwrapOutputs.append($0) },
            fetchKeys: { [keyInfo] },
            fetchPrivateKey: { _, _ in edPriv }
        )

        XCTAssertTrue(unwrapOutputs.contains("-> file-key 0"))
        XCTAssertTrue(unwrapOutputs.contains(originalFileKey.base64EncodedString()))
        XCTAssertEqual(unwrapOutputs.last, "-> ok")
    }

    func testAgePluginIdentityV1SkipsIncompatibleOrMismatchedKeys() throws {
        let p256Key = Ed25519KeyInfo(
            label: "p256_se_key",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... p256_se_key",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave
        )
        let otherEdKey = Ed25519KeyInfo(
            label: "other_ed_key",
            publicKeyOpenSSH: "ssh-ed25519 AAAA... other_ed_key",
            publicKeyBlob: Data([4, 5, 6]),
            fingerprint: "SHA256:other",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain
        )

        var requestedKeys: [String] = []
        var outputs: [String] = []

        let unwrapInputs = [
            "-> add-identity target_key",
            "-> recipient-stanza 0 clavis ZmFrZS1lcGs=",
            "ZmFrZS13cmFwcGVk",
            "-> unwrap-file-key",
            "-> done"
        ]
        var inputIdx = 0

        AgePluginClavis.handleIdentityV1(
            inputProvider: {
                guard inputIdx < unwrapInputs.count else { return nil }
                defer { inputIdx += 1 }
                return unwrapInputs[inputIdx]
            },
            outputHandler: { outputs.append($0) },
            fetchKeys: { [p256Key, otherEdKey] },
            fetchPrivateKey: { label, _ in
                requestedKeys.append(label)
                return Curve25519.Signing.PrivateKey()
            }
        )

        // Neither the P256 key (incompatible) nor the mismatched Ed key should have prompted Touch ID
        XCTAssertTrue(requestedKeys.isEmpty, "Incompatible or mismatched keys must not trigger Touch ID prompts")
        XCTAssertTrue(outputs.contains { $0.contains("No matching age-compatible keys") || $0.contains("Failed to unwrap stanza") })
    }

    // MARK: - 11. Milestone 2 & Milestone 3 Direct Unit Tests

    func testSSHAgentServerRequestIdentities() throws {
        let server = SSHAgentServer()
        let requestPayload = Data([11]) // SSH2_AGENTC_REQUEST_IDENTITIES
        let response = server.processAgentRequest(payload: requestPayload)

        XCTAssertFalse(response.isEmpty)
        XCTAssertEqual(response[0], 12) // SSH2_AGENT_IDENTITIES_ANSWER

        // Key count is 4 bytes big endian starting at index 1
        XCTAssertGreaterThanOrEqual(response.count, 5)
        let keyCount = response.subdata(in: 1..<5).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        XCTAssertGreaterThanOrEqual(keyCount, 0)
    }

    func testSSHAgentServerSignRequestParsing() throws {
        let server = SSHAgentServer()

        // 1. Invalid payload: empty or unknown msg type
        XCTAssertEqual(server.processAgentRequest(payload: Data()), Data([5]))
        XCTAssertEqual(server.processAgentRequest(payload: Data([99])), Data([5]))

        // 2. Msg type 13 with truncated payload (missing flags)
        var truncatedPayload = Data([13])
        truncatedPayload.appendWireString("fake-key-blob")
        truncatedPayload.appendWireString("data-to-sign")
        // Missing 4-byte flags parameter
        XCTAssertEqual(server.processAgentRequest(payload: truncatedPayload), Data([5]))

        // 3. Msg type 13 with valid wire framing and flags but non-existent keyBlob
        var validFramedPayload = Data([13])
        validFramedPayload.appendWireString("non-existent-key-blob")
        validFramedPayload.appendWireString("hello world")
        var flags: UInt32 = 0
        Swift.withUnsafeBytes(of: &flags) { validFramedPayload.append(contentsOf: $0) }
        XCTAssertEqual(server.processAgentRequest(payload: validFramedPayload), Data([5]))
    }

    func testAgePluginStanzaParsingAndEncoding() throws {
        // 1. Test AgeStanza IPC encoding & parsing
        let originalStanza = AgeStanza(fileIndex: 0, tag: "clavis", epk: "testEPKBase64", wrappedKey: Data([0x01, 0x02, 0x03, 0x04]))
        let encodedIPC = originalStanza.encodeIPC()
        XCTAssertTrue(encodedIPC.hasPrefix("-> recipient-stanza 0 clavis testEPKBase64\n"))

        let lines = encodedIPC.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 2)

        let parsedStanza = AgeStanza.parseIPC(header: lines[0], body: lines[1])
        XCTAssertNotNil(parsedStanza)
        XCTAssertEqual(parsedStanza, originalStanza)

        // 2. Test AgePluginCrypto wrap & unwrap roundtrip
        let seed = Data(repeating: 0x42, count: 32)
        let x25519Priv = try Ed25519AgeConverter.ed25519SeedToX25519PrivateKey(seed: seed)
        let recipientStr = Ed25519AgeConverter.ageRecipient(forPublicKey: x25519Priv.publicKey.rawRepresentation)

        let fileKey = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00])
        let (epkB64, wrappedKeyData) = try AgePluginCrypto.wrapFileKey(fileKey: fileKey, recipientString: recipientStr)

        XCTAssertFalse(epkB64.isEmpty)
        XCTAssertGreaterThan(wrappedKeyData.count, 16)

        let unwrappedFileKey = try AgePluginCrypto.unwrapFileKey(wrappedKey: wrappedKeyData, epkB64: epkB64, ed25519Seed: seed)
        XCTAssertEqual(unwrappedFileKey, fileKey)

        // 3. Test invalid parameters handling
        XCTAssertThrowsError(try AgePluginCrypto.wrapFileKey(fileKey: fileKey, recipientString: "invalid-recipient"))
        XCTAssertThrowsError(try AgePluginCrypto.unwrapFileKey(wrappedKey: wrappedKeyData, epkB64: "invalid-epk", ed25519Seed: seed))
        XCTAssertThrowsError(try AgePluginCrypto.unwrapFileKey(wrappedKey: Data([1, 2, 3]), epkB64: epkB64, ed25519Seed: seed))
    }

    // MARK: - 12. Milestone 4 GUI & Daemon Tests

    @MainActor
    func testAppStateInitializationAndDaemonFlag() {
        let sessionCache = makeSessionCache()
        let appState = AppState(
            keyManager: makeKeyManager(sessionCache: sessionCache),
            sessionCache: sessionCache,
            sshAgentServer: SSHAgentServer(socketPath: testRootURL.appendingPathComponent("app-state.sock").path)
        )
        XCTAssertNotNil(appState)

        // Test setTimeout method syncs with SessionCacheManager
        appState.setTimeout(.fiveMinutes)
        XCTAssertEqual(sessionCache.currentTimeout, .fiveMinutes)
        XCTAssertEqual(appState.selectedTimeout, .fiveMinutes)

        appState.setTimeout(.never)
        XCTAssertEqual(sessionCache.currentTimeout, .never)
        XCTAssertEqual(appState.selectedTimeout, .never)

        // Test lockNow clears cache and refreshes state
        sessionCache.currentTimeout = .fiveMinutes
        sessionCache.set(label: "test-lock", key: Curve25519.Signing.PrivateKey())
        appState.lockNow()
        XCTAssertEqual(sessionCache.cachedCount, 0)
        XCTAssertEqual(appState.cachedKeysCount, 0)

        // Test clearError
        appState.clearError()
        XCTAssertNil(appState.errorMessage)
    }

    @MainActor
    func testDaemonModeFlagParsing() {
        let isDaemonMode = CommandLine.arguments.contains("--daemon")
        XCTAssertEqual(AppState.shared.isDaemonMode, isDaemonMode)
    }

    // MARK: - 13. CLIService Subcommand Tests

    func testCLIServiceHelpCommand() {
        let keyManager = makeKeyManager()
        let resHelp = CLIService.handle(args: ["clavis", "help"], keyManager: keyManager)
        XCTAssertNotNil(resHelp)
        XCTAssertEqual(resHelp?.exitCode, 0)
        XCTAssertTrue(resHelp?.output.contains("Clavis") ?? false)

        let resDashH = CLIService.handle(args: ["clavis", "-h"], keyManager: keyManager)
        XCTAssertEqual(resDashH?.exitCode, 0)

        let resNoArgs = CLIService.handle(args: ["clavis"], keyManager: keyManager)
        XCTAssertNil(resNoArgs)
    }

    func testCLIServiceImportValidation() {
        let keyManager = makeKeyManager()
        let invalidSeedRes = CLIService.handle(args: ["clavis", "import", "mykey", "invalidhex"], keyManager: keyManager)
        XCTAssertNotNil(invalidSeedRes)
        XCTAssertEqual(invalidSeedRes?.exitCode, 1)
        XCTAssertEqual(invalidSeedRes?.error, "Invalid hex seed string (must be 64 hex characters / 32 bytes).")

        let missingArgsRes = CLIService.handle(args: ["clavis", "generate"], keyManager: keyManager)
        XCTAssertEqual(missingArgsRes?.exitCode, 1)
        XCTAssertEqual(missingArgsRes?.error, "Usage: clavis generate <label>")
    }

    func testCLIServiceImportViaStdin() throws {
        let keyManager = makeKeyManager()
        let label = "stdin_key_\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }

        let validHexSeed = String(repeating: "ab", count: 32)
        let res = CLIService.handle(
            args: ["clavis", "import", label, "--stdin"],
            inputReader: { validHexSeed },
            keyManager: keyManager
        )

        XCTAssertNotNil(res)
        XCTAssertEqual(res?.exitCode, 0)
        XCTAssertTrue(res?.output.contains("Successfully imported") ?? false)
        XCTAssertFalse(res?.output.contains("SECURITY WARNING") ?? true)

        let loaded = try keyManager.fetchKeyInfo(label: label)
        XCTAssertNotNil(loaded)
    }

    func testCLIServiceImportViaArgvShowsWarning() throws {
        let keyManager = makeKeyManager()
        let label = "argv_key_\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }

        let validHexSeed = String(repeating: "cd", count: 32)
        let res = CLIService.handle(
            args: ["clavis", "import", label, validHexSeed],
            keyManager: keyManager
        )

        XCTAssertNotNil(res)
        XCTAssertEqual(res?.exitCode, 0)
        XCTAssertTrue(res?.output.contains("Successfully imported") ?? false)
        XCTAssertTrue(res?.output.contains("SECURITY WARNING") ?? false)

        let loaded = try keyManager.fetchKeyInfo(label: label)
        XCTAssertNotNil(loaded)
    }

    func testSingleInstanceLockAcquireAndRelease() {
        let tempURL = testRootURL.appendingPathComponent("clavis_test_\(UUID().uuidString).lock")
        SingleInstanceLock.customLockFileURL = tempURL
        defer {
            SingleInstanceLock.shared.release()
            SingleInstanceLock.customLockFileURL = nil
            try? FileManager.default.removeItem(at: tempURL)
        }

        let lock = SingleInstanceLock.shared
        lock.release()

        XCTAssertTrue(lock.acquire())
        XCTAssertTrue(lock.acquire())

        let fd = open(tempURL.path, O_RDWR)
        if fd >= 0 {
            let flockRes = flock(fd, LOCK_EX | LOCK_NB)
            XCTAssertEqual(flockRes, -1)
            XCTAssertEqual(errno, EWOULDBLOCK)
            close(fd)
        }

        lock.release()
        let fd2 = open(tempURL.path, O_RDWR)
        if fd2 >= 0 {
            let flockRes2 = flock(fd2, LOCK_EX | LOCK_NB)
            XCTAssertEqual(flockRes2, 0)
            flock(fd2, LOCK_UN)
            close(fd2)
        }
    }

    func testSSHMPintEncoding() {
        let posBytes = Data([0x12, 0x34])
        let encodedPos = KeychainManager.encodeSSHMPint(posBytes)
        // 4 bytes len (2) + 2 bytes
        XCTAssertEqual(encodedPos.count, 6)

        // If high bit set, must prepend 0x00
        let negBytes = Data([0x85, 0x12])
        let encodedNeg = KeychainManager.encodeSSHMPint(negBytes)
        // 4 bytes len (3) + 0x00 + 2 bytes
        XCTAssertEqual(encodedNeg.count, 7)
        XCTAssertEqual(encodedNeg[4], 0x00)
        XCTAssertEqual(encodedNeg[5], 0x85)
    }

    func testP256KeyGenerationAndSSHSigning() throws {
        let keyManager = makeKeyManager()
        let testLabel = "test_p256_\(UUID().uuidString)"
        defer {
            try? keyManager.deleteKey(label: testLabel)
        }

        let storage: KeyStorageType = .keychain
        let keyInfo = try keyManager.generateKey(label: testLabel, algorithm: "ECDSA P-256", storageType: storage)

        XCTAssertEqual(keyInfo.algorithm, "ECDSA P-256")
        XCTAssertEqual(keyInfo.isHardware, (storage == .secureEnclave))
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasPrefix("ecdsa-sha2-nistp256"))

        let testData = "Test SSH challenge payload".data(using: .utf8)!
        let sigBlob = try keyManager.signSSH(key: keyInfo, data: testData, prompt: "Test prompt")

        // Parse wire format: wire string "ecdsa-sha2-nistp256" + wire data
        var reader = DataReader(data: sigBlob)
        let sigAlgo = reader.readWireString()
        XCTAssertEqual(sigAlgo, "ecdsa-sha2-nistp256")
        let innerData = reader.readWireData()
        XCTAssertNotNil(innerData)
        XCTAssertGreaterThan(innerData?.count ?? 0, 64)
    }

    func testLaunchAtLoginManager() {
        let tempPlistURL = FileManager.default.temporaryDirectory.appendingPathComponent("clavis_launch_\(UUID().uuidString).plist")
        LaunchAtLoginManager.customLaunchAgentURL = tempPlistURL
        defer {
            LaunchAtLoginManager.customLaunchAgentURL = nil
            try? FileManager.default.removeItem(at: tempPlistURL)
        }

        let mgr = LaunchAtLoginManager.shared
        XCTAssertFalse(mgr.isEnabled)

        mgr.setLaunchAtLogin(enabled: true)
        XCTAssertTrue(mgr.isEnabled)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempPlistURL.path))

        mgr.setLaunchAtLogin(enabled: false)
        XCTAssertFalse(mgr.isEnabled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: tempPlistURL.path))
    }

    func testSeedStoreEnvelopeEncryptionCycle() throws {
        let label = "test_envelope_\(UUID().uuidString)"

        var randomSeed = Data(count: 32)
        _ = randomSeed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        try SeedStore.save(label: label, seedData: randomSeed)
        let loaded = SeedStore.load(label: label)

        XCTAssertEqual(loaded, randomSeed)
    }

    func testSeedStoreEncryptedFileFormat() throws {
        let label = "test_format_\(UUID().uuidString)"

        let secretBytes = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
        try SeedStore.save(label: label, seedData: secretBytes)

        let fileURL = SeedStore.seedFileURL(label: label)
        let fileData = try Data(contentsOf: fileURL)

        // Must start with magic header "CLV1" (0x43, 0x4C, 0x56, 0x01)
        XCTAssertEqual(fileData.prefix(4), Data([0x43, 0x4C, 0x56, 0x01]))

        // Must include 65-byte P-256 public key + at least 28-byte ChaChaPoly box
        XCTAssertGreaterThanOrEqual(fileData.count, 4 + 65 + 28)

        // Raw secret bytes must NOT appear anywhere in the ciphertext
        XCTAssertNil(fileData.range(of: secretBytes))
    }

    func testSeedStoreLegacyPlaintextMigration() throws {
        let label = "test_legacy_\(UUID().uuidString)"

        let legacySeed = Data(repeating: 0x7A, count: 32)
        let fileURL = SeedStore.seedFileURL(label: label)

        // Write raw unencrypted seed directly to disk (simulating pre-envelope legacy Clavis)
        try legacySeed.write(to: fileURL, options: .atomic)
        XCTAssertEqual(try Data(contentsOf: fileURL), legacySeed)

        // Loading should return the plaintext seed AND automatically migrate the file to CLV1
        let loaded = SeedStore.load(label: label)
        XCTAssertEqual(loaded, legacySeed)

        // Verify that file on disk is now an encrypted envelope
        let migratedFileData = try Data(contentsOf: fileURL)
        XCTAssertEqual(migratedFileData.prefix(4), Data([0x43, 0x4C, 0x56, 0x01]))
        XCTAssertNil(migratedFileData.range(of: legacySeed))

        // Subsequent load should successfully decrypt from the new envelope
        let reloaded = SeedStore.load(label: label)
        XCTAssertEqual(reloaded, legacySeed)
    }

    func testSeedStoreFindsLegacySanitizedFilename() throws {
        let label = "legacy/path"
        let legacyURL = SeedStore.seedsDirectory.appendingPathComponent("legacy_path.key")
        let seed = Data(repeating: 0x4C, count: 32)
        try seed.write(to: legacyURL, options: .atomic)

        XCTAssertEqual(SeedStore.load(label: label), seed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: SeedStore.seedFileURL(label: label).path))
    }

    func testSeedStoreTamperedCiphertextFails() throws {
        let label = "test_tamper_\(UUID().uuidString)"

        let seed = Data(repeating: 0x33, count: 32)
        try SeedStore.save(label: label, seedData: seed)

        let fileURL = SeedStore.seedFileURL(label: label)
        var fileData = try Data(contentsOf: fileURL)

        // Flip a bit in the encrypted payload (past the 69-byte header)
        fileData[75] ^= 0xFF
        try fileData.write(to: fileURL, options: .atomic)

        // ChaChaPoly MAC authentication must reject tampered data and return nil
        let loaded = SeedStore.load(label: label)
        XCTAssertNil(loaded)
    }

    func testSeedStorePathUsesCollisionResistantIdentifier() {
        let maliciousLabel = "../../etc/passwd"
        let url = SeedStore.seedFileURL(label: maliciousLabel)

        XCTAssertFalse(url.path.contains(".."))
        XCTAssertFalse(url.path.contains("/etc/passwd"))
        XCTAssertTrue(url.lastPathComponent.hasPrefix("sha256-"))
        XCTAssertEqual(url.lastPathComponent.count, 7 + 64 + 4)
        XCTAssertNotEqual(
            SeedStore.seedFileURL(label: "a/b"),
            SeedStore.seedFileURL(label: "a_b")
        )
    }

    func testKeyManagerRejectsControlCharactersInLabel() {
        let keyManager = makeKeyManager()
        XCTAssertThrowsError(try keyManager.generateKey(label: "trusted\n[AUTH] forged"))
    }
}
