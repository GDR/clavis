import Foundation

/// Inspection summary returned by the daemon when preparing a `clavis vault repair` confirmation.
public struct VaultMasterKeyInspection: Codable, Equatable, Sendable {
    public let fingerprint: String
    public let createdAtISO8601: String?
    public let existingPin: Data?
    public let expectedPin: Data

    public init(
        fingerprint: String,
        createdAtISO8601: String?,
        existingPin: Data?,
        expectedPin: Data
    ) {
        self.fingerprint = fingerprint
        self.createdAtISO8601 = createdAtISO8601
        self.existingPin = existingPin
        self.expectedPin = expectedPin
    }
}

/// JSON-encoded CLI control request sent over `SSHAgentServer.cliControlRequest` (opcode 252).
public enum CLIControlRequest: Codable, Equatable {
    case listKeys
    case generateKey(
        label: String,
        algorithm: String,
        storageType: KeyStorageType,
        biometricPolicy: BiometricPolicy?,
        keyPurpose: KeyPurpose
    )
    case changeKind(label: String, newPurpose: KeyPurpose)
    case deleteKey(label: String)
    case inspectVaultMasterKey
    case saveVaultMasterKeyPin(
        expectedPin: Data,
        replacePin: Bool
    )
}

/// JSON-encoded CLI control response wrapped in `Data([6]) + wireData(json)`.
public enum CLIControlResponse: Codable, Equatable {
    case keys([SSHKeyInfo])
    case key(SSHKeyInfo)
    case vaultInspection(VaultMasterKeyInspection)
    case ok
    case failure(message: String)
}
