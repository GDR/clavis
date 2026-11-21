import Foundation
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct KeyAccessProfileTests {
    private func record(
        version: Int = StoredPrivateKeyRecord.currentVersion,
        purpose: KeyPurpose = .general,
        profile: KeyAccessProfile? = nil
    ) -> StoredPrivateKeyRecord {
        StoredPrivateKeyRecord(
            version: version, label: "migration", algorithm: .ecdsaP256,
            storageType: .secureEnclave, biometricPolicy: .userPresence,
            keyPurpose: purpose, accessProfile: profile,
            keyData: Data([0x42, 0x24]), createdAt: Date(timeIntervalSince1970: 123)
        )
    }

    @Test(arguments: KeyPurpose.allCases)
    func legacyMigrationPreservesRestrictions(_ purpose: KeyPurpose) throws {
        // A v2 envelope has no profile bytes. Decode without rewriting key material.
        let legacy = record(version: 2, purpose: purpose)
        let bytes = try legacy.encode()
        #expect(bytes[8] == 2)
        let decoded = try StoredPrivateKeyRecord.decode(from: bytes)
        #expect(decoded.keyData == legacy.keyData)
        #expect(decoded.createdAt == legacy.createdAt)
        #expect(decoded.biometricPolicy == legacy.biometricPolicy)
        #expect(decoded.accessProfile.type == (purpose == .agent ? .bot : .personal))
        #expect(decoded.accessProfile.capabilities.ssh == (purpose != .gitSigningOnly))
        #expect(decoded.accessProfile.capabilities.signature == (purpose != .agent))
        #expect(try decoded.encode() == bytes)
    }

    @Test(arguments: [false, true], [false, true])
    func independentCapabilitiesRoundTrip(ssh: Bool, signature: Bool) throws {
        for type in KeyType.allCases {
            let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: ssh, signature: signature))
            let original = record(profile: profile)
            let decoded = try StoredPrivateKeyRecord.decode(from: original.encode())
            #expect(decoded == original)
            #expect(decoded.accessProfile == profile)
            #expect(profile.capabilities.permits(.ssh) == ssh)
            #expect(profile.capabilities.permits(.signature) == signature)
            #expect(try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: JSONEncoder().encode(original)) == original)
        }
    }

    @Test func invalidProfileBytesAndTruncationFailClosed() throws {
        let valid = try record().encode()
        for offset in [13, 14] {
            var invalid = valid
            invalid[offset] = 0xff
            #expect(throws: (any Error).self) { try StoredPrivateKeyRecord.decode(from: invalid) }
        }
        for end in 0..<valid.count {
            #expect(throws: (any Error).self) {
                try StoredPrivateKeyRecord.decode(from: Data(valid.prefix(end)))
            }
        }
    }

    @Test func legacyEncodingCannotSilentlyDropPolicy() {
        let narrowed = KeyAccessProfile(type: .personal, capabilities: .init(ssh: false, signature: false))
        #expect(throws: KeyAccessError.legacyEncodingWouldLosePolicy) {
            try record(version: 2, profile: narrowed).encode()
        }
    }

    @Test func currentJSONRequiresProfileRatherThanDefaultingToBroadAccess() throws {
        let bytes = try JSONEncoder().encode(record())
        var json = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        json.removeValue(forKey: "accessProfile")
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: JSONSerialization.data(withJSONObject: json))
        }
        json["version"] = 2
        let legacy = try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(legacy.accessProfile == KeyAccessProfile(legacyPurpose: .general))
    }

    @Test func oldPublicCacheGetsConservativeProfile() throws {
        let key = SSHKeyInfo(label: "old", publicKeyOpenSSH: "pub", publicKeyBlob: Data(), fingerprint: "fp", keyPurpose: .gitSigningOnly)
        let decoded = try JSONDecoder().decode(SSHKeyInfo.self, from: JSONEncoder().encode(key))
        #expect(decoded.effectiveAccessProfile.type == .personal)
        #expect(!decoded.effectiveAccessProfile.capabilities.ssh)
        #expect(decoded.effectiveAccessProfile.capabilities.signature)
    }

    @Test func disabledOperationAndTamperedCacheCannotSign() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), privateKeyStore: store)
            let key = try manager.generateKey(label: "restricted")
            let raw = try #require(try store.load(label: key.label, context: LAContext(), prompt: "Load"))
            var stored = try StoredPrivateKeyRecord.decode(from: raw)
            defer { stored.wipe() }
            let profile = KeyAccessProfile(type: .personal, capabilities: .init(ssh: false, signature: true))
            let restricted = StoredPrivateKeyRecord(
                label: stored.label, algorithm: stored.algorithm, storageType: stored.storageType,
                biometricPolicy: stored.biometricPolicy, keyPurpose: stored.keyPurpose,
                accessProfile: profile, keyData: stored.keyData, createdAt: stored.createdAt
            )
            try store.save(label: key.label, data: restricted.encode(), accessControlFlags: [])
            // A stale cache still advertises SSH; the authoritative record refuses it.
            #expect(throws: KeyAccessError.profileMismatch) {
                try manager.signSSH(key: key, data: Data("ssh".utf8), prompt: "Sign")
            }
            let matching = SSHKeyInfo(
                label: key.label, publicKeyOpenSSH: key.publicKeyOpenSSH, publicKeyBlob: key.publicKeyBlob,
                fingerprint: key.fingerprint, biometricPolicy: key.biometricPolicy, accessProfile: profile
            )
            #expect(throws: KeyAccessError.operationDisabled(.ssh)) {
                try manager.signSSH(key: matching, data: Data("ssh".utf8), prompt: "Sign")
            }
        }
    }

    @Test func typeChangePreservesDisabledCapabilities() {
        let profile = KeyAccessProfile(type: .personal, capabilities: .init(ssh: false, signature: true))
        let bot = profile.changingType(to: .bot)
        #expect(bot.type == .bot)
        #expect(bot.capabilities == profile.capabilities)
    }

    @Test(arguments: KeyGracePeriod.allCases)
    func unlockedTimeoutRoundTripsInV4BinaryAndJSON(_ period: KeyGracePeriod) throws {
        let original = StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: "timeout-\(period.rawValue)",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            accessProfile: KeyAccessProfile(legacyPurpose: .general),
            unlockedTimeout: period,
            keyData: Data([0x42, 0x24]),
            createdAt: Date(timeIntervalSince1970: 456)
        )
        let bytes = try original.encode()
        #expect(bytes[8] == 4)
        let decoded = try StoredPrivateKeyRecord.decode(from: bytes)
        #expect(decoded == original)
        #expect(decoded.unlockedTimeout == period)

        let jsonDecoded = try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: JSONEncoder().encode(original))
        #expect(jsonDecoded == original)
        #expect(jsonDecoded.unlockedTimeout == period)
    }

    @Test func v3BinaryAndInvalidTimeoutByteFailClosed() throws {
        let legacyV3 = StoredPrivateKeyRecord(
            version: 3,
            label: "v3",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            accessProfile: KeyAccessProfile(legacyPurpose: .general),
            unlockedTimeout: nil,
            keyData: Data([0x01, 0x02]),
            createdAt: Date(timeIntervalSince1970: 789)
        )
        let v3Bytes = try legacyV3.encode()
        #expect(v3Bytes[8] == 3)
        let decodedV3 = try StoredPrivateKeyRecord.decode(from: v3Bytes)
        #expect(decodedV3.version == 3)
        #expect(decodedV3.unlockedTimeout == nil)
        #expect(try decodedV3.encode() == v3Bytes)

        #expect(throws: KeyAccessError.legacyEncodingWouldLosePolicy) {
            try StoredPrivateKeyRecord(
                version: 3,
                label: "v3-loss",
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .general,
                unlockedTimeout: .always,
                keyData: Data([0x01])
            ).encode()
        }

        let v4Bytes = try record(unlockedTimeout: .session).encode()
        var invalidTimeout = v4Bytes
        invalidTimeout[15] = 0xfe
        #expect(throws: (any Error).self) {
            try StoredPrivateKeyRecord.decode(from: invalidTimeout)
        }
    }

    private func record(unlockedTimeout: KeyGracePeriod?) -> StoredPrivateKeyRecord {
        StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: "timeout-helper",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            unlockedTimeout: unlockedTimeout,
            keyData: Data([0x42, 0x24]),
            createdAt: Date(timeIntervalSince1970: 123)
        )
    }

    @Test func tamperedPublicUnlockedTimeoutRefusedOnSign() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator())
            let key = try manager.generateKey(label: "tamper-timeout", unlockedTimeout: .always)
            let tampered = SSHKeyInfo(
                label: key.label,
                publicKeyOpenSSH: key.publicKeyOpenSSH,
                publicKeyBlob: key.publicKeyBlob,
                fingerprint: key.fingerprint,
                createdAt: key.createdAt,
                algorithmName: key.algorithmName,
                storage: key.storage,
                biometricPolicy: key.biometricPolicy,
                keyPurpose: key.keyPurpose,
                accessProfile: key.effectiveAccessProfile,
                unlockedTimeout: .session
            )
            #expect(throws: PrivateKeyRecordError.metadataMismatch(
                field: "unlockedTimeout",
                expected: KeyGracePeriod.session.rawValue,
                actual: KeyGracePeriod.always.rawValue
            )) {
                try manager.signSSH(key: tampered, data: Data("ssh".utf8), prompt: "Sign")
            }
        }
    }
}
