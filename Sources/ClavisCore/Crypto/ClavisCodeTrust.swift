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
