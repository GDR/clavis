import Foundation
import LocalAuthentication
import Security

public enum ApplicationClassification: String, Codable, CaseIterable, Sendable {
    case personal
    case bot
    case block

    public var title: String { rawValue.capitalized }

    public func permits(_ type: KeyType) -> Bool {
        switch self {
        case .personal: return true
        case .bot: return type == .bot
        case .block: return false
        }
    }
}

/// Identity evidence is compared with a running process by the daemon.
/// A display name, executable path, socket, or environment variable is not identity.
public struct ApplicationIdentity: Codable, Equatable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case designatedRequirement
        case executableSHA256
    }
    public let kind: Kind
    public let value: String

    public init(kind: Kind, value: String) throws {
        guard !value.isEmpty, value.utf8.count <= 16_384,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw ApplicationRegistryError.invalidIdentity
        }
        if kind == .executableSHA256 {
            guard value.count == 64, value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw ApplicationRegistryError.invalidIdentity
            }
        }
        self.kind = kind
        self.value = value
    }

    private enum CodingKeys: CodingKey { case kind, value }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(kind: values.decode(Kind.self, forKey: .kind), value: values.decode(String.self, forKey: .value))
    }
}

public struct RegisteredApplication: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let identity: ApplicationIdentity
    public var name: String
    public var path: String
    public var classification: ApplicationClassification
    public var removed: Bool

    public init(
        id: UUID = UUID(), identity: ApplicationIdentity, name: String, path: String,
        classification: ApplicationClassification, removed: Bool = false
    ) {
        self.id = id
        self.identity = identity
        self.name = name
        self.path = path
        self.classification = classification
        self.removed = removed
    }
}

public struct ApplicationRegistrySnapshot: Codable, Equatable, Sendable {
    public let version: Int
    public let revision: UUID
    public var applications: [RegisteredApplication]
    public let requestsPaused: Bool?
    public var isPaused: Bool { requestsPaused ?? false }

    public init(revision: UUID = UUID(), applications: [RegisteredApplication] = [], requestsPaused: Bool = false) {
        version = 1
        self.revision = revision
        self.applications = applications
        self.requestsPaused = requestsPaused
    }

    public func validate() throws {
        guard version == 1, applications.count <= 512,
              Set(applications.map(\.id)).count == applications.count,
              Set(applications.map(\.identity)).count == applications.count else {
            throw ApplicationRegistryError.corrupt
        }
        for app in applications {
            guard !app.name.isEmpty, app.name.utf8.count <= 1_024,
                  app.path.hasPrefix("/"), app.path.utf8.count <= 4_096,
                  !app.name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  !app.removed || app.classification == .block else {
                throw ApplicationRegistryError.corrupt
            }
        }
    }

    public func classification(for verifiedIdentity: ApplicationIdentity?) -> ApplicationClassification? {
        guard let verifiedIdentity else { return nil }
        return applications.first { $0.identity == verifiedIdentity }?.classification
    }
}

public enum ApplicationEligibility: Equatable, Sendable {
    case eligible(ApplicationClassification)
    case authenticatedOnceOnly
    case denied

    public static func evaluate(
        profile: KeyAccessProfile, operation: KeyOperation,
        classification: ApplicationClassification?, restrictedBotEndpoint: Bool
    ) -> ApplicationEligibility {
        guard profile.capabilities.permits(operation),
              !restrictedBotEndpoint || profile.type == .bot else { return .denied }
        guard let classification else { return .authenticatedOnceOnly }
        return classification.permits(profile.type) ? .eligible(classification) : .denied
    }
}

public protocol ApplicationRegistryStoring: Sendable {
    func load() throws -> ApplicationRegistrySnapshot
    /// Compare-and-save prevents a policy prompt from overwriting a newer decision.
    func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws
}

public enum ApplicationRegistryError: Error, Equatable {
    case invalidIdentity
    case corrupt
    case staleRevision
    case persistence(OSStatus)
}

/// Invoked on the authoritative control path, never as a UI-only permission check.
/// It intentionally has no "already authenticated" shortcut.
public final class AuthenticatedApplicationRegistry {
    private let store: ApplicationRegistryStoring
    private let authenticator: UserAuthenticating
    private let invalidateApprovals: () throws -> Void

    public init(
        store: ApplicationRegistryStoring,
        authenticator: UserAuthenticating,
        invalidateApprovals: @escaping () throws -> Void
    ) {
        self.store = store
        self.authenticator = authenticator
        self.invalidateApprovals = invalidateApprovals
    }

    public func set(_ application: RegisteredApplication) throws {
        try commit(application, replacing: store.load())
    }

    private func commit(_ application: RegisteredApplication, replacing old: ApplicationRegistrySnapshot) throws {
        var entries = old.applications.filter { $0.identity != application.identity }
        entries.append(application)
        let updated = ApplicationRegistrySnapshot(applications: entries, requestsPaused: old.isPaused)
        try updated.validate()
        let context = try authenticator.authenticate(
            reason: "Change access for \(application.name) to \(application.classification.title)",
            policy: .deviceOwnerAuthentication
        )
        defer { context.invalidate() }
        // Revoke first. A persistence failure may revoke approvals but never grants
        // broader access; authentication failure leaves both policy and grants alone.
        try invalidateApprovals()
        try store.save(updated, replacing: old.revision)
    }

    /// Pausing stops requests without waiting for authentication. Resuming is
    /// authenticated and never recreates revoked approvals.
    public func setPaused(_ paused: Bool) throws {
        let old = try store.load()
        if !paused {
            let context = try authenticator.authenticate(reason: "Resume Clavis requests", policy: .deviceOwnerAuthentication)
            context.invalidate()
        }
        try invalidateApprovals()
        let updated = ApplicationRegistrySnapshot(applications: old.applications, requestsPaused: paused)
        try store.save(updated, replacing: old.revision)
    }

    public func remove(identity: ApplicationIdentity) throws {
        let old = try store.load()
        guard var app = old.applications.first(where: { $0.identity == identity }) else {
            throw ApplicationRegistryError.invalidIdentity
        }
        app.classification = .block
        app.removed = true
        try commit(app, replacing: old)
    }
}
