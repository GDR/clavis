import XCTest
import CryptoKit
@testable import ClavisCore

final class ClavisTests: XCTestCase {

    // MARK: - 1. Key Info & OpenSSH Wire Serialization Tests

    func testEd25519KeyInfoAndWireSerialization() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let keyInfo = try KeychainManager.shared.makeKeyInfo(label: "test-github-key", privateKey: privateKey)

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
        let cache = SessionCacheManager.shared
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
        let cache = SessionCacheManager.shared
        cache.clearCache()
        cache.currentTimeout = .never // Cache off

        let key = Curve25519.Signing.PrivateKey()
        cache.set(label: "uncached-key", key: key)

        XCTAssertNil(cache.get(label: "uncached-key"))
        XCTAssertEqual(cache.cachedCount, 0)
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
        let cache = SessionCacheManager.shared
        cache.clearCache()
        cache.currentTimeout = .fiveMinutes
        cache.set(label: "flush-test", key: Curve25519.Signing.PrivateKey())
        XCTAssertEqual(cache.cachedCount, 1)

        // Changing timeout flushes cache
        cache.currentTimeout = .never
        XCTAssertEqual(cache.cachedCount, 0)
    }

    func testSSHAgentServerLifecycle() throws {
        let tmpDir = NSTemporaryDirectory()
        let testSockPath = (tmpDir as NSString).appendingPathComponent("clavis-unittest.sock")
        let server = SSHAgentServer(socketPath: testSockPath)

        XCTAssertFalse(server.isSocketActive)
        try server.start()
        XCTAssertTrue(server.isSocketActive)
        XCTAssertTrue(FileManager.default.fileExists(atPath: testSockPath))

        server.stop()
        XCTAssertFalse(server.isSocketActive)
    }

    // MARK: - 7. Milestone 1 Expanded Unit Tests

    func testSessionCacheTimeoutChangePurgesCache() {
        let cache = SessionCacheManager.shared
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
        let cache = SessionCacheManager.shared
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
        let keys = try KeychainManager.shared.listKeys()
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
}
