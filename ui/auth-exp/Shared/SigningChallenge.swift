import Foundation
import CryptoKit

// MARK: - Signing Challenge Model

public struct SigningChallengePreset: Identifiable, Hashable, Sendable {
    public let id: String
    public let title: String
    public let clientProcess: String
    public let operationSummary: String
    public let payloadTemplate: String

    public static let presets: [SigningChallengePreset] = [
        SigningChallengePreset(
            id: "ssh-github",
            title: "SSH Auth -> github.com",
            clientProcess: "/usr/bin/ssh (PID 48210)",
            operationSummary: "Authenticate SSH session to git@github.com (ecdsa-sha2-nistp256)",
            payloadTemplate: "ssh-connection|session-bind@openssh.com|host=github.com|user=git"
        ),
        SigningChallengePreset(
            id: "git-commit",
            title: "Git Commit Signature",
            clientProcess: "/usr/bin/git (PID 51092)",
            operationSummary: "Sign Git commit object on branch main",
            payloadTemplate: "tree 9c3b8a1f\nauthor Developer <dev@clavis.local>\n\nfeat(auth): verify SEP key authorization"
        ),
        SigningChallengePreset(
            id: "ssh-bastion",
            title: "SSH Prod Bastion",
            clientProcess: "/usr/bin/ssh (PID 60411)",
            operationSummary: "Authenticate privileged SSH jump to root@prod-bastion.internal",
            payloadTemplate: "ssh-connection|publickey|host=prod-bastion.internal|user=root"
        ),
        SigningChallengePreset(
            id: "vault-rotation",
            title: "Vault Key Rotation",
            clientProcess: "clavis-cli (PID 73105)",
            operationSummary: "Authorize destructive master key rotation",
            payloadTemplate: "clavis-vault-v2|rotate-master-key|epoch=2026-10"
        )
    ]
}

public struct SigningChallenge: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let sequenceNumber: Int
    public let createdAt: Date
    public var clientProcess: String
    public var operationSummary: String
    public var payloadText: String
    public var nonceHex: String

    public init(
        id: UUID = UUID(),
        sequenceNumber: Int = 1,
        createdAt: Date = Date(),
        clientProcess: String,
        operationSummary: String,
        payloadText: String,
        nonceHex: String? = nil
    ) {
        self.id = id
        self.sequenceNumber = sequenceNumber
        self.createdAt = createdAt
        self.clientProcess = clientProcess
        self.operationSummary = operationSummary
        self.payloadText = payloadText
        self.nonceHex = nonceHex ?? Self.randomNonceHex()
    }

    public static func fromPreset(_ preset: SigningChallengePreset, sequenceNumber: Int = 1) -> SigningChallenge {
        SigningChallenge(
            sequenceNumber: sequenceNumber,
            clientProcess: preset.clientProcess,
            operationSummary: preset.operationSummary,
            payloadText: preset.payloadTemplate
        )
    }

    public var rawChallengeData: Data {
        Data("\(payloadText)|nonce=\(nonceHex)|seq=\(sequenceNumber)".utf8)
    }

    public var sha256DigestHex: String {
        let digest = SHA256.hash(data: rawChallengeData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public mutating func regenerateNonce(nextSequence: Int? = nil) {
        nonceHex = Self.randomNonceHex()
        if let nextSequence {
            self = SigningChallenge(
                sequenceNumber: nextSequence,
                clientProcess: clientProcess,
                operationSummary: operationSummary,
                payloadText: payloadText,
                nonceHex: nonceHex
            )
        }
    }

    public static func randomNonceHex(byteCount: Int = 8) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Signing Result Record

public struct SigningAttemptOutcome: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let challengeSequence: Int
    public let challengeDigestHex: String
    public let mechanismLabel: String
    public let succeeded: Bool
    public let signatureDER: Data?
    public let signatureVerifiedWithPublicKey: Bool
    public let elapsedMilliseconds: Double
    public let wasContextReused: Bool
    public let wasBypassAttempt: Bool
    public let errorSummary: String?
    public let errorSymbolicDetails: String?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        challengeSequence: Int,
        challengeDigestHex: String,
        mechanismLabel: String,
        succeeded: Bool,
        signatureDER: Data?,
        signatureVerifiedWithPublicKey: Bool,
        elapsedMilliseconds: Double,
        wasContextReused: Bool = false,
        wasBypassAttempt: Bool = false,
        errorSummary: String? = nil,
        errorSymbolicDetails: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.challengeSequence = challengeSequence
        self.challengeDigestHex = challengeDigestHex
        self.mechanismLabel = mechanismLabel
        self.succeeded = succeeded
        self.signatureDER = signatureDER
        self.signatureVerifiedWithPublicKey = signatureVerifiedWithPublicKey
        self.elapsedMilliseconds = elapsedMilliseconds
        self.wasContextReused = wasContextReused
        self.wasBypassAttempt = wasBypassAttempt
        self.errorSummary = errorSummary
        self.errorSymbolicDetails = errorSymbolicDetails
    }

    public var signatureHexPreview: String {
        guard let sig = signatureDER else { return "—" }
        let hex = sig.map { String(format: "%02x", $0) }.joined()
        if hex.count > 48 {
            return "\(hex.prefix(24))…\(hex.suffix(24)) (\(sig.count) B DER)"
        }
        return "\(hex) (\(sig.count) B DER)"
    }
}
