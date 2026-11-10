import Foundation
import Security
import CryptoKit
import LocalAuthentication
import ObjectiveC.runtime

// MARK: - Access Control Presets for Secure Enclave Keys

public enum SEPKeyAccessPreset: String, CaseIterable, Codable, Identifiable, Sendable {
    case userPresence               = "userPresence"
    case biometryAny                = "biometryAny"
    case biometryCurrentSet         = "biometryCurrentSet"
    case devicePasscode             = "devicePasscode"
    case applicationPassword        = "applicationPassword"
    case userPresenceAndAppPassword = "userPresence+applicationPassword"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .userPresence:
            return ".userPresence (Touch ID / Watch / System Password)"
        case .biometryAny:
            return ".biometryAny (Touch ID only, any enrolled finger)"
        case .biometryCurrentSet:
            return ".biometryCurrentSet (Touch ID only, current enrollment)"
        case .devicePasscode:
            return ".devicePasscode (macOS User Password)"
        case .applicationPassword:
            return ".applicationPassword (SEP hardware passphrase-wrapped)"
        case .userPresenceAndAppPassword:
            return "[.userPresence, .applicationPassword] (Touch ID + Passphrase AND-gate)"
        }
    }

    public var flags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence:
            return [.privateKeyUsage, .userPresence]
        case .biometryAny:
            return [.privateKeyUsage, .biometryAny]
        case .biometryCurrentSet:
            return [.privateKeyUsage, .biometryCurrentSet]
        case .devicePasscode:
            return [.privateKeyUsage, .devicePasscode]
        case .applicationPassword:
            return [.privateKeyUsage, .applicationPassword]
        case .userPresenceAndAppPassword:
            return [.privateKeyUsage, .userPresence, .applicationPassword]
        }
    }

    public var requiresApplicationPasswordAtCreation: Bool {
        switch self {
        case .applicationPassword, .userPresenceAndAppPassword:
            return true
        default:
            return false
        }
    }

    public func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            let cfErr = error?.takeRetainedValue()
            throw cfErr as Error? ?? NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(errSecParam),
                userInfo: [NSLocalizedDescriptionKey: "SecAccessControlCreateWithFlags failed"]
            )
        }
        return ac
    }
}

// MARK: - Persisted Secure Enclave Key Record

public struct PersistedSEPKeyRecord: Codable, Equatable, Sendable {
    public let keyId: String
    public let profileName: String
    public let createdAt: Date
    public let preset: SEPKeyAccessPreset
    /// 427-byte `com.apple.setoken` object identifier (`"toid"` attribute from `SecKeyCopyAttributes`).
    /// This blob is encrypted to the Secure Enclave hardware UID + SEP access control policy;
    /// it contains no exportable private scalar and enforces its `SecAccessControlRef` inside SEP.
    public let tokenOID: Data
    public let publicKeyX963: Data
    public let publicKeyFingerprint: String
    public let hardwareACLDescription: String
}

// MARK: - Hardware Authentication Environment Snapshot

public struct HardwareAuthEnvironment: Equatable, Sendable {
    public let secureEnclaveAvailable: Bool
    public let biometrySummary: String
    public let biometryUsable: Bool
    public let companionSummary: String
    public let companionUsable: Bool
    public let passwordUsable: Bool
    public let canEvaluateDeviceOwnerAuth: Bool
    public let canEvaluateBiometrics: Bool

    public static func inspect() -> HardwareAuthEnvironment {
        let seAvailable = SecureEnclave.isAvailable
        let probeCtx = LAContext()
        var ownerErr: NSError?
        let canOwner = probeCtx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &ownerErr)
        var bioErr: NSError?
        let canBio = probeCtx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &bioErr)

        if #available(macOS 15.0, *) {
            let state = LAEnvironment.currentUser.state
            let bio = state.biometry
            let bioText: String
            if let bio {
                var flags: [String] = []
                flags.append(bio.isEnrolled ? "enrolled" : "not-enrolled")
                flags.append(bio.isUsable ? "usable" : "not-usable")
                if bio.isLockedOut { flags.append("LOCKED-OUT") }
                if bio.builtInSensorInaccessible { flags.append("CLAMSHELL-INACCESSIBLE") }
                bioText = "\(bio.localizedName) (\(flags.joined(separator: ", ")))"
            } else {
                bioText = "None (\(bioErr?.localizedDescription ?? "unavailable"))"
            }

            let companions = state.companions
            let usableCompanions = companions.filter(\.isUsable)
            let compText: String
            if companions.isEmpty {
                compText = "No paired Watch"
            } else {
                let names = companions.map { "\($0.localizedName): \($0.isUsable ? "usable" : "unreachable")" }
                compText = names.joined(separator: ", ")
            }

            let pwdUsable = state.userPassword?.isUsable ?? canOwner
            return HardwareAuthEnvironment(
                secureEnclaveAvailable: seAvailable,
                biometrySummary: bioText,
                biometryUsable: bio?.isUsable ?? canBio,
                companionSummary: compText,
                companionUsable: !usableCompanions.isEmpty,
                passwordUsable: pwdUsable,
                canEvaluateDeviceOwnerAuth: canOwner,
                canEvaluateBiometrics: canBio
            )
        } else {
            return HardwareAuthEnvironment(
                secureEnclaveAvailable: seAvailable,
                biometrySummary: canBio ? "Touch ID available" : "Touch ID unavailable (\(bioErr?.localizedDescription ?? "n/a"))",
                biometryUsable: canBio,
                companionSummary: "Requires macOS 15+ LAEnvironment",
                companionUsable: false,
                passwordUsable: canOwner,
                canEvaluateDeviceOwnerAuth: canOwner,
                canEvaluateBiometrics: canBio
            )
        }
    }
}

// MARK: - Secure Enclave Key Manager (SecKey + SecKeyCreateSignature)

public enum SecureEnclaveKeyError: LocalizedError {
    case missingTokenOID
    case publicKeyExtractionFailed
    case keyReconstitutionFailed(String)
    case signatureVerificationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .missingTokenOID:
            return "SecKeyCopyAttributes did not return a 'toid' Secure Enclave token object ID."
        case .publicKeyExtractionFailed:
            return "Failed to extract uncompressed X9.63 public key from Secure Enclave SecKey."
        case .keyReconstitutionFailed(let details):
            return "Failed to reconstitute Secure Enclave SecKey from tokenOID: \(details)"
        case .signatureVerificationFailed(let details):
            return "SecKeyVerifySignature rejected the produced signature: \(details)"
        }
    }
}

public final class SecureEnclaveKeyManager: Sendable {
    public let profileName: String
    public let storageURL: URL

    public init(profileName: String) {
        self.profileName = profileName
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = appSupport.appendingPathComponent("ClavisAuthLab", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.storageURL = dir.appendingPathComponent("\(profileName)-sep-key.json")
    }

    public func loadPersistedKey() -> PersistedSEPKeyRecord? {
        guard let data = try? Data(contentsOf: storageURL) else { return nil }
        return try? JSONDecoder().decode(PersistedSEPKeyRecord.self, from: data)
    }

    public func deletePersistedKey() throws {
        if FileManager.default.fileExists(atPath: storageURL.path) {
            try FileManager.default.removeItem(at: storageURL)
        }
    }

    /// Generates a hardware-bound P-256 key inside the Secure Enclave using `SecKeyCreateRandomKey`.
    ///
    /// Note on `kSecAttrIsPermanent: false`:
    /// On macOS, `kSecAttrIsPermanent: true` attempts to store the token reference in the iOS-style
    /// Data Protection Keychain, which fails with `errSecMissingEntitlement (-34018)` unless the binary
    /// carries a provisioning profile (`com.apple.application-identifier`). Creating the SEP key with
    /// `kSecAttrIsPermanent: false` still creates a genuine `com.apple.setoken` hardware key whose
    /// 427-byte `"toid"` blob is sealed by the Secure Enclave with the specified `SecAccessControlRef`.
    /// Persisting `"toid"` to disk allows testing key survival across app restarts and helper processes.
    public func generateKey(
        preset: SEPKeyAccessPreset,
        creationContext: LAContext? = nil
    ) throws -> PersistedSEPKeyRecord {
        let accessControl = try preset.makeAccessControl()
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: accessControl
            ]
        ]
        if let creationContext {
            attrs[kSecUseAuthenticationContext as String] = creationContext
        }

        var cfError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
            throw cfError!.takeRetainedValue() as Error
        }

        guard let keyAttrs = SecKeyCopyAttributes(secKey) as? [String: Any],
              let tokenOID = keyAttrs["toid"] as? Data else {
            throw SecureEnclaveKeyError.missingTokenOID
        }

        let aclString: String
        if let accc = keyAttrs[kSecAttrAccessControl as String] {
            aclString = String(describing: accc)
        } else {
            aclString = String(describing: accessControl)
        }

        guard let pubKey = SecKeyCopyPublicKey(secKey),
              let pubData = SecKeyCopyExternalRepresentation(pubKey, &cfError) as Data? else {
            throw SecureEnclaveKeyError.publicKeyExtractionFailed
        }

        let digest = SHA256.hash(data: pubData)
        let fingerprint = "SHA256:" + Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        let shortId = digest.prefix(4).map { String(format: "%02x", $0) }.joined()

        let record = PersistedSEPKeyRecord(
            keyId: "sepk-\(shortId)",
            profileName: profileName,
            createdAt: Date(),
            preset: preset,
            tokenOID: tokenOID,
            publicKeyX963: pubData,
            publicKeyFingerprint: fingerprint,
            hardwareACLDescription: aclString
        )

        let encoded = try JSONEncoder().encode(record)
        try encoded.write(to: storageURL, options: .atomic)
        return record
    }

    /// Reconstitutes a `SecKey` handle bound to the provided `LAContext`.
    public func reconstitutePrivateKey(
        from record: PersistedSEPKeyRecord,
        context: LAContext
    ) throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            "toid": record.tokenOID,
            kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        var cfError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
            let err = cfError?.takeRetainedValue() as Error?
            throw err ?? SecureEnclaveKeyError.keyReconstitutionFailed("Unknown SecKeyCreateRandomKey(toid) failure")
        }
        return secKey
    }

    /// Performs `SecKeyCreateSignature` on the Secure Enclave key and verifies the DER signature with `SecKeyVerifySignature`.
    public func sign(
        challengeData: Data,
        using record: PersistedSEPKeyRecord,
        context: LAContext
    ) throws -> (signatureDER: Data, verified: Bool) {
        let privateKey = try reconstitutePrivateKey(from: record, context: context)

        var signError: Unmanaged<CFError>?
        guard let sigCF = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            challengeData as CFData,
            &signError
        ) else {
            throw signError!.takeRetainedValue() as Error
        }
        let signatureDER = sigCF as Data

        let verified = try verifySignature(
            signatureDER: signatureDER,
            challengeData: challengeData,
            publicKeyX963: record.publicKeyX963
        )
        return (signatureDER, verified)
    }

    public func verifySignature(
        signatureDER: Data,
        challengeData: Data,
        publicKeyX963: Data
    ) throws -> Bool {
        let pubAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var pubErr: Unmanaged<CFError>?
        guard let pubKey = SecKeyCreateWithData(publicKeyX963 as CFData, pubAttrs as CFDictionary, &pubErr) else {
            throw SecureEnclaveKeyError.publicKeyExtractionFailed
        }
        var verifyErr: Unmanaged<CFError>?
        let ok = SecKeyVerifySignature(
            pubKey,
            .ecdsaSignatureMessageX962SHA256,
            challengeData as CFData,
            signatureDER as CFData,
            &verifyErr
        )
        if !ok, let err = verifyErr?.takeRetainedValue() {
            throw SecureEnclaveKeyError.signatureVerificationFailed(err.localizedDescription)
        }
        return ok
    }

    // MARK: - LAContext Externalization for Cross-Process Agent Handoff (Test #8)

    /// Extracts the 16-byte `externalizedContext` token from an `LAContext` via the ObjC runtime.
    /// On macOS, `LocalAuthentication.framework` implements `-[LAContext externalizedContext]` and
    /// `-[LAContext initWithExternalizedContext:]` to reference a `coreauthd` context across IPC.
    public static func extractExternalizedContext(_ context: LAContext) -> Data? {
        let sel = NSSelectorFromString("externalizedContext")
        guard context.responds(to: sel),
              let unmanaged = context.perform(sel),
              let data = unmanaged.takeUnretainedValue() as? Data else {
            return nil
        }
        return data
    }

    public static func makeContext(fromExternalizedContext data: Data) -> LAContext? {
        typealias InitExtIMP = @convention(c) (AnyObject, Selector, NSData) -> Unmanaged<LAContext>?
        let allocSel = NSSelectorFromString("alloc")
        let initSel = NSSelectorFromString("initWithExternalizedContext:")
        guard LAContext.instancesRespond(to: initSel),
              let allocated = (LAContext.self as AnyObject).perform(allocSel)?.takeUnretainedValue(),
              let imp = class_getMethodImplementation(LAContext.self, initSel) else {
            return nil
        }
        let fn = unsafeBitCast(imp, to: InitExtIMP.self)
        return fn(allocated, initSel, data as NSData)?.takeRetainedValue()
    }
}

// MARK: - Cross-Process Agent Worker (Test #8: Agent and GUI in Different Processes)

public struct AgentWorkerResponse: Codable, Sendable {
    public let agentPID: Int32
    public let mode: String
    public let succeeded: Bool
    public let signatureDERBase64: String?
    public let signatureVerified: Bool
    public let elapsedMs: Double
    public let errorDescription: String?
}

public enum CrossProcessAgentRunner {
    /// Checks if the current process was launched as a background agent worker (`--agent-worker <mode> <profile> <challengeB64> [extContextB64]`).
    /// If so, executes the requested SEP operation in this separate OS process, prints JSON to stdout, and exits immediately.
    public static func handleAgentCommandLineIfPresent() {
        let args = CommandLine.arguments
        guard args.count >= 5, args[1] == "--agent-worker" else {
            return
        }

        let mode = args[2]
        let profileName = args[3]
        let challengeData = Data(base64Encoded: args[4]) ?? Data("agent-challenge".utf8)
        let extContextData: Data? = args.count >= 6 ? Data(base64Encoded: args[5]) : nil
        let appPasswordData: Data? = args.count >= 7 ? Data(base64Encoded: args[6]) : nil

        let start = DispatchTime.now()
        let keyManager = SecureEnclaveKeyManager(profileName: profileName)
        let pid = ProcessInfo.processInfo.processIdentifier

        let response: AgentWorkerResponse
        do {
            guard let record = keyManager.loadPersistedKey() else {
                throw SecureEnclaveKeyError.keyReconstitutionFailed("No persisted key found at \(keyManager.storageURL.path)")
            }

            let context: LAContext
            switch mode {
            case "with-externalized-context":
                guard let extContextData,
                      let imported = SecureEnclaveKeyManager.makeContext(fromExternalizedContext: extContextData) else {
                    throw SecureEnclaveKeyError.keyReconstitutionFailed("Failed to reconstitute LAContext(externalizedContext:) in agent process")
                }
                imported.interactionNotAllowed = true
                context = imported

            case "unauthenticated-bypass":
                let unauth = LAContext()
                unauth.interactionNotAllowed = true
                context = unauth

            case "agent-direct-prompt":
                let interactive = LAContext()
                interactive.interactionNotAllowed = false
                interactive.localizedReason = "sign challenge from background agent process (PID \(pid))"
                if let appPasswordData, !appPasswordData.isEmpty {
                    _ = interactive.setCredential(appPasswordData, type: .applicationPassword)
                }
                context = interactive

            default:
                throw SecureEnclaveKeyError.keyReconstitutionFailed("Unknown agent mode: \(mode)")
            }

            let (sig, verified) = try keyManager.sign(
                challengeData: challengeData,
                using: record,
                context: context
            )
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
            response = AgentWorkerResponse(
                agentPID: pid,
                mode: mode,
                succeeded: true,
                signatureDERBase64: sig.base64EncodedString(),
                signatureVerified: verified,
                elapsedMs: elapsed,
                errorDescription: nil
            )
        } catch {
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
            response = AgentWorkerResponse(
                agentPID: pid,
                mode: mode,
                succeeded: false,
                signatureDERBase64: nil,
                signatureVerified: false,
                elapsedMs: elapsed,
                errorDescription: AuthErrorInspector.describe(error)
            )
        }

        if let json = try? JSONEncoder().encode(response),
           let str = String(data: json, encoding: .utf8) {
            print(str)
            fflush(stdout)
        }
        exit(0)
    }

    /// Spawns a separate child OS process running the current executable in `--agent-worker` mode.
    public static func spawnAgentSign(
        mode: String,
        profileName: String,
        challengeData: Data,
        externalizedContext: Data? = nil,
        appPassword: Data? = nil
    ) async throws -> AgentWorkerResponse {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
                var args = [
                    "--agent-worker",
                    mode,
                    profileName,
                    challengeData.base64EncodedString()
                ]
                if let externalizedContext {
                    args.append(externalizedContext.base64EncodedString())
                } else {
                    args.append("")
                }
                if let appPassword {
                    args.append(appPassword.base64EncodedString())
                }
                process.arguments = args

                let outPipe = Pipe()
                let errPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = errPipe

                do {
                    try process.run()
                    process.waitUntilExit()
                    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
                    if let decoded = try? JSONDecoder().decode(AgentWorkerResponse.self, from: outData) {
                        continuation.resume(returning: decoded)
                    } else {
                        let outStr = String(data: outData, encoding: .utf8) ?? ""
                        let errStr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                        continuation.resume(returning: AgentWorkerResponse(
                            agentPID: process.processIdentifier,
                            mode: mode,
                            succeeded: false,
                            signatureDERBase64: nil,
                            signatureVerified: false,
                            elapsedMs: 0,
                            errorDescription: "Non-JSON agent output (exit \(process.terminationStatus)): stdout='\(outStr)' stderr='\(errStr)'"
                        ))
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
