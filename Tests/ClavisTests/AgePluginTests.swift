import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class AgePluginTests: ClavisBaseTestCase {

    func testDirectAgeFileKeyUnwrap() throws {
        let keyManager = makeKeyManager()
        let label = "age-direct-\(UUID().uuidString)"
        let keyInfo = try keyManager.generateKey(label: label)

        let originalFileKey = Data((0..<32).map { UInt8($0) })
        let (epkB64, wrappedKey) = try AgePluginCrypto.wrapFileKey(
            fileKey: originalFileKey,
            recipientString: keyInfo.ageRecipient
        )

        let unwrapped = try keyManager.unwrapAgeFileKey(
            label: label,
            prompt: "Unwrap age file key",
            wrappedKey: wrappedKey,
            epkB64: epkB64
        )

        XCTAssertEqual(unwrapped, originalFileKey)
    }


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


    func testAgePluginRejectsOversizedIPCLine() {
        let inputs = [
            "-> wrap-file-key",
            String(repeating: "A", count: AgePluginClavis.maximumIPCLineBytes + 1)
        ]
        var index = 0
        var outputs: [String] = []

        AgePluginClavis.handleRecipientV1(
            inputProvider: {
                guard index < inputs.count else { return nil }
                defer { index += 1 }
                return inputs[index]
            },
            outputHandler: { outputs.append($0) }
        )

        XCTAssertEqual(outputs, ["-> error protocol IPC input limit exceeded"])
    }


    func testAgePluginRejectsExcessiveIPCItems() {
        var inputs = (0...AgePluginClavis.maximumIPCItems).map {
            "-> add-recipient invalid-recipient-\($0)"
        }
        inputs.append("-> done")
        var index = 0
        var outputs: [String] = []

        AgePluginClavis.handleRecipientV1(
            inputProvider: {
                guard index < inputs.count else { return nil }
                defer { index += 1 }
                return inputs[index]
            },
            outputHandler: { outputs.append($0) }
        )

        XCTAssertEqual(outputs, ["-> error protocol IPC input limit exceeded"])
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
            unwrapKey: { _, _, wrappedKey, epkB64 in
                try AgePluginCrypto.unwrapFileKey(wrappedKey: wrappedKey, epkB64: epkB64, ed25519Seed: edPriv.rawRepresentation)
            }
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
            unwrapKey: { label, _, _, _ in
                requestedKeys.append(label)
                return Data()
            }
        )

        // Neither the P256 key (incompatible) nor the mismatched Ed key should have prompted Touch ID
        XCTAssertTrue(requestedKeys.isEmpty, "Incompatible or mismatched keys must not trigger Touch ID prompts")
        XCTAssertTrue(outputs.contains { $0.contains("No matching age-compatible keys") || $0.contains("Failed to unwrap stanza") })
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


}
