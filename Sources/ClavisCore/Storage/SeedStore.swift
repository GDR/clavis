import Foundation
import CryptoKit

public struct SeedStore {
    public static var customSeedsDirectory: URL? = nil
    public static var customMasterKEKURL: URL? = nil

    public static var seedsDirectory: URL {
        if let custom = customSeedsDirectory { return custom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis/seeds", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }

    public static var masterKEKURL: URL {
        if let custom = customMasterKEKURL { return custom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("master.kek")
    }

    public static func seedFileURL(label: String) -> URL {
        let safeLabel = label
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "__")
        return seedsDirectory.appendingPathComponent("\(safeLabel).key")
    }

    public static func hasSeedFile(label: String) -> Bool {
        FileManager.default.fileExists(atPath: seedFileURL(label: label).path)
    }

    // MARK: - Master KEK Management

    private enum MasterKey {
        case secureEnclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case software(P256.KeyAgreement.PrivateKey)

        var publicKey: P256.KeyAgreement.PublicKey {
            switch self {
            case .secureEnclave(let key):
                return key.publicKey
            case .software(let key):
                return key.publicKey
            }
        }

        func sharedSecret(with peerPublicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
            switch self {
            case .secureEnclave(let key):
                return try key.sharedSecretFromKeyAgreement(with: peerPublicKey)
            case .software(let key):
                return try key.sharedSecretFromKeyAgreement(with: peerPublicKey)
            }
        }
    }

    private static let masterKeyLock = NSLock()
    private static var cachedMasterKey: MasterKey? = nil

    public static func resetMasterKeyCacheForTesting() {
        masterKeyLock.lock()
        defer { masterKeyLock.unlock() }
        cachedMasterKey = nil
    }

    private static func getOrCreateMasterKey() throws -> MasterKey {
        masterKeyLock.lock()
        defer { masterKeyLock.unlock() }

        if let existing = cachedMasterKey {
            return existing
        }

        let kekURL = masterKEKURL
        let fileManager = FileManager.default

        if fileManager.fileExists(atPath: kekURL.path),
           let kekFileData = try? Data(contentsOf: kekURL),
           !kekFileData.isEmpty {
            let tag = kekFileData[0]
            let payload = Data(kekFileData.dropFirst())

            if tag == 0x01 {
                if SecureEnclave.isAvailable,
                   let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: payload) {
                    let master = MasterKey.secureEnclave(key)
                    cachedMasterKey = master
                    return master
                }
            } else if tag == 0x02 {
                if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: payload) {
                    let master = MasterKey.software(key)
                    cachedMasterKey = master
                    return master
                }
            }
        }

        // Create new Master KEK
        let master: MasterKey
        var fileData = Data()

        if SecureEnclave.isAvailable {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            master = .secureEnclave(seKey)
            fileData.append(0x01)
            fileData.append(seKey.dataRepresentation)
            ClavisLogger.log("SEED_STORE", "Generated new hardware Master KEK inside Apple Secure Enclave.")
        } else {
            let swKey = P256.KeyAgreement.PrivateKey()
            master = .software(swKey)
            fileData.append(0x02)
            fileData.append(swKey.rawRepresentation)
            ClavisLogger.log("SEED_STORE", "Generated software Master KEK (Secure Enclave unavailable).")
        }

        let parentDir = kekURL.deletingLastPathComponent()
        try? fileManager.createDirectory(at: parentDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try fileData.write(to: kekURL, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: kekURL.path)

        cachedMasterKey = master
        return master
    }

    // MARK: - Envelope Encryption & Decryption

    private static let envelopeMagic: [UInt8] = [0x43, 0x4C, 0x56, 0x01] // "CLV\1"
    private static let kdfSalt = Data("clavis-seed-envelope-v1".utf8)
    private static let kdfInfo = Data("clavis-seed-encryption".utf8)

    public static func encryptSeed(_ seedData: Data) throws -> Data {
        let master = try getOrCreateMasterKey()
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: master.publicKey)

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: kdfSalt,
            sharedInfo: kdfInfo,
            outputByteCount: 32
        )

        let sealedBox = try ChaChaPoly.seal(seedData, using: symmetricKey)
        var envelope = Data()
        envelope.append(contentsOf: envelopeMagic)
        envelope.append(ephemeralKey.publicKey.x963Representation)
        envelope.append(sealedBox.combined)
        return envelope
    }

    public static func decryptSeed(_ envelopeData: Data) throws -> Data {
        guard envelopeData.count >= 4 + 65 + 28,
              envelopeData.prefix(4).elementsEqual(envelopeMagic) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid encrypted seed format or missing CLV1 header"])
        }

        let pubKeyData = envelopeData.subdata(in: 4..<69)
        let sealedBoxData = envelopeData.subdata(in: 69..<envelopeData.count)

        let peerPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: pubKeyData)
        let master = try getOrCreateMasterKey()
        let sharedSecret = try master.sharedSecret(with: peerPublicKey)

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: kdfSalt,
            sharedInfo: kdfInfo,
            outputByteCount: 32
        )

        let sealedBox = try ChaChaPoly.SealedBox(combined: sealedBoxData)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }

    // MARK: - Public Storage API

    public static func save(label: String, seedData: Data) throws {
        let encryptedData = try encryptSeed(seedData)
        let url = seedFileURL(label: label)
        try encryptedData.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        ClavisLogger.log("SEED_STORE", "Saved encrypted seed (Secure Enclave Envelope) for '\(label)' to \(url.path) (POSIX 0600)")
    }

    public static func load(label: String) -> Data? {
        let url = seedFileURL(label: label)
        guard let fileData = try? Data(contentsOf: url) else { return nil }

        if fileData.count >= 4 && fileData.prefix(4).elementsEqual(envelopeMagic) {
            do {
                let decrypted = try decryptSeed(fileData)
                ClavisLogger.log("SEED_STORE", "Decrypted seed for '\(label)' via Master KEK.")
                return decrypted
            } catch {
                ClavisLogger.log("SEED_STORE", "Failed to decrypt seed for '\(label)': \(error.localizedDescription)")
                return nil
            }
        } else {
            // Legacy plaintext seed! Migrate automatically to encrypted envelope.
            ClavisLogger.log("SEED_STORE", "Found legacy unencrypted seed for '\(label)'. Migrating to Secure Enclave envelope...")
            do {
                try save(label: label, seedData: fileData)
                ClavisLogger.log("SEED_STORE", "Successfully migrated seed for '\(label)' to Secure Enclave envelope.")
            } catch {
                ClavisLogger.log("SEED_STORE", "Failed to auto-migrate legacy seed for '\(label)': \(error.localizedDescription)")
            }
            return fileData
        }
    }

    public static func remove(label: String) {
        let url = seedFileURL(label: label)
        try? FileManager.default.removeItem(at: url)
        ClavisLogger.log("SEED_STORE", "Removed seed file for '\(label)' at \(url.path)")
    }

    public static func removeMasterKeyIfUnused() {
        let fileManager = FileManager.default
        let remainingSeedFiles = (try? fileManager.contentsOfDirectory(
            at: seedsDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ))?.contains(where: { $0.pathExtension == "key" }) ?? false

        guard !remainingSeedFiles else { return }

        masterKeyLock.lock()
        cachedMasterKey = nil
        masterKeyLock.unlock()
        try? fileManager.removeItem(at: masterKEKURL)
        ClavisLogger.log("SEED_STORE", "Removed legacy Master KEK after the last seed migrated to Keychain.")
    }
}
