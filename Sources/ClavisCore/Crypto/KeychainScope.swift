import Foundation
import Security

/// Keychain storage partition for Clavis items.
///
/// Signed builds carrying a valid `<TEAMID>.com.clavis.shared` keychain-access-group
/// entitlement use the macOS Data Protection Keychain so GUI, CLI, and agent
/// executables share items without legacy SecAccess ACL prompts. Unsigned or
/// ad-hoc builds (and test runners) use the legacy login keychain partition.
public enum KeychainScope: Equatable, Sendable {
    case dataProtection(accessGroup: String)
    case legacyLogin

    public static let sharedGroupSuffix = ".com.clavis.shared"

    public static let processDefault: KeychainScope = {
        if ClavisEnvironment.isTesting {
            return .legacyLogin
        }
        var selfCode: SecCode?
        var staticSelf: SecStaticCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode,
              SecCodeCopyStaticCode(selfCode, [], &staticSelf) == errSecSuccess, let staticSelf else {
            return .legacyLogin
        }
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticSelf, flags, &info) == errSecSuccess,
              let infoDict = info as? [String: Any] else {
            return .legacyLogin
        }
        let entitlements = infoDict[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        return resolve(fromEntitlements: entitlements)
    }()

    public static func resolve(fromEntitlements entitlements: [String: Any]?) -> KeychainScope {
        guard let groups = entitlements?["keychain-access-groups"] as? [String] else {
            return .legacyLogin
        }
        guard let matched = groups.first(where: { group in
            guard group.hasSuffix(sharedGroupSuffix) else { return false }
            let teamID = String(group.dropLast(sharedGroupSuffix.count))
            return ClavisCodeTrust.isWellFormedTeamIdentifier(teamID)
        }) else {
            return .legacyLogin
        }
        return .dataProtection(accessGroup: matched)
    }

    /// Applies Data Protection Keychain scoping to search/add/delete queries.
    /// Never apply this to the `attributesToUpdate` (second) dictionary of `SecItemUpdate`.
    public func apply(to query: inout [String: Any]) {
        switch self {
        case .dataProtection(let accessGroup):
            query[kSecUseDataProtectionKeychain as String] = true
            query[kSecAttrAccessGroup as String] = accessGroup
        case .legacyLogin:
            break
        }
    }

    /// Returns a copy of `query` with Data Protection Keychain scoping applied when needed.
    /// Never use on the `attributesToUpdate` (second) dictionary of `SecItemUpdate`.
    public func applying(to query: [String: Any]) -> [String: Any] {
        var result = query
        apply(to: &result)
        return result
    }
}
