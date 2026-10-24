import Foundation
import Darwin

public struct ApplicationRequestLease: Equatable, Sendable {
    public let eligibility: ApplicationEligibility
    public let revision: UUID
    public let caller: VerifiedApplicationCaller?
    public init(eligibility: ApplicationEligibility, revision: UUID, caller: VerifiedApplicationCaller?) {
        self.eligibility = eligibility; self.revision = revision; self.caller = caller
    }
    public var approvalIdentity: String? {
        caller.map { "\($0.identity.kind.rawValue):\($0.identity.value)" }
    }
}

public protocol ApplicationRequestAuthorizing {
    func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease
    func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool
}

public final class ApplicationRequestAuthorization: ApplicationRequestAuthorizing {
    private let store: ApplicationRegistryStoring
    private let resolver: ApplicationCallerResolver
    public init(store: ApplicationRegistryStoring = KeychainApplicationRegistry.shared, resolver: ApplicationCallerResolver = .init()) {
        self.store = store; self.resolver = resolver
    }

    public func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease {
        let snapshot = try store.load()
        let caller = resolver.resolve(peerPID: pid, peerPath: path, peerStart: start, registry: snapshot)
        let eligibility = ApplicationEligibility.evaluate(
            profile: key.effectiveAccessProfile, operation: operation,
            classification: caller?.application.classification, restrictedBotEndpoint: role == .agent
        )
        return ApplicationRequestLease(eligibility: eligibility, revision: snapshot.revision, caller: caller)
    }

    public func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool {
        let snapshot = try store.load()
        guard snapshot.revision == lease.revision else { return false }
        let caller = resolver.resolve(peerPID: pid, peerPath: path, peerStart: start, registry: snapshot)
        return caller == lease.caller
    }
}
