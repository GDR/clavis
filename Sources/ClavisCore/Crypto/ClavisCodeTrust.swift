import Foundation
import Security

/// Shared code-signing trust anchor for every Clavis component.
///
/// Trust is derived from the running process's own signature: a binary is a
/// "Clavis binary" only if it carries the shared Code Signing Identifier **and**
/// was signed by the same Apple team as the running process. An identifier on its
/// own is attacker-controlled (`codesign -s - -i Clavis`) and must never be
/// treated as proof of origin.
enum ClavisCodeTrust {
    static let sharedIdentifier = "Clavis"

    /// Requirement built from the running process's team identifier, or `nil`
    /// when the process is unsigned or ad-hoc signed (no team identifier).
    static let requirement: SecRequirement? = {
        guard let team = currentTeamIdentifier() else { return nil }
        return makeRequirement(teamIdentifier: team)
    }()

    static func makeRequirement(teamIdentifier team: String) -> SecRequirement? {
        // Team identifiers are exactly 10 uppercase alphanumerics. Validate before
        // interpolating so a malformed value can never alter the requirement.
        guard isWellFormedTeamIdentifier(team) else { return nil }
        let text = "identifier \"\(sharedIdentifier)\" and anchor apple generic "
            + "and certificate leaf[subject.OU] = \"\(team)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }

    static func isWellFormedTeamIdentifier(_ team: String) -> Bool {
        team.utf8.count == 10 && team.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) }
    }

    /// Returns `true` only if the process on the other end of a connected AF_UNIX
    /// socket is a Clavis binary (see the type documentation).
    ///
    /// Identity comes from `LOCAL_PEERTOKEN` (the peer's audit token, which includes
    /// the PID version), so it cannot be confused by PID reuse, and a peer that
    /// `exec`ed after connecting no longer resolves to a valid guest. A forwarded
    /// agent connection (`ssh -A`) is relayed by `/usr/bin/ssh` and is therefore
    /// never a Clavis peer.
    static func isTrustedPeer(socket fd: Int32) -> Bool {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
              length == socklen_t(MemoryLayout<audit_token_t>.size) else {
            return false
        }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest else {
            return false
        }
        return isTrusted(guest: guest, requirement: requirement, allowIdentifierOnlyDevelopmentFallback: allowsDevelopmentFallback)
    }

    #if DEBUG
    static let allowsDevelopmentFallback = true
    #else
    static let allowsDevelopmentFallback = false
    #endif

    static func isTrusted(
        guest: SecCode,
        requirement: SecRequirement?,
        allowIdentifierOnlyDevelopmentFallback: Bool
    ) -> Bool {
        if let requirement {
            return SecCodeCheckValidity(guest, [], requirement) == errSecSuccess
        }
        guard allowIdentifierOnlyDevelopmentFallback,
              SecCodeCheckValidity(guest, [], nil) == errSecSuccess else {
            return false
        }
        var staticGuest: SecStaticCode?
        guard SecCodeCopyStaticCode(guest, [], &staticGuest) == errSecSuccess, let staticGuest else {
            return false
        }
        return signingIdentifier(of: staticGuest) == sharedIdentifier
    }

    static func currentTeamIdentifier() -> String? {
        var selfCode: SecCode?
        var staticSelf: SecStaticCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode,
              SecCodeCopyStaticCode(selfCode, [], &staticSelf) == errSecSuccess, let staticSelf else {
            return nil
        }
        return signingInformation(of: staticSelf)?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    static func signingIdentifier(of code: SecStaticCode) -> String? {
        signingInformation(of: code)?[kSecCodeInfoIdentifier as String] as? String
    }

    private static func signingInformation(of code: SecStaticCode) -> [String: Any]? {
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess else { return nil }
        return info as? [String: Any]
    }
}
