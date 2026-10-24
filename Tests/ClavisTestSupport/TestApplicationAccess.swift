import Foundation
import ClavisCore

/// Existing protocol tests exercise their original socket/session policy in
/// isolation. Application authorization has separate integration coverage.
struct TestApplicationAccess: ApplicationRequestAuthorizing {
    private let revision = UUID()
    func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease {
        let legacyAllowed = role == .agent ? key.purpose == .agent : key.purpose != .agent
        let result: ApplicationEligibility = legacyAllowed && key.effectiveAccessProfile.capabilities.permits(operation) ? .eligible(.personal) : .denied
        return .init(eligibility: result, revision: revision, caller: nil)
    }
    func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool { true }
}
