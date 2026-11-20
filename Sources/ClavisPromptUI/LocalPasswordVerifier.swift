import Foundation
import OpenDirectory

/// Shared local OpenDirectory password verification helper used by both `Clavis` and `ClavisPromptUI`.
public enum LocalPasswordVerifier {
    /// Verifies the current macOS user's login password against local OpenDirectory without storing it.
    @Sendable public static func verifyLocalAccountPassword(_ password: String) -> Bool {
        guard !password.isEmpty else { return false }
        do {
            let session = ODSession.default()
            let node = try ODNode(session: session, type: ODNodeType(kODNodeTypeLocalNodes))
            let record = try node.record(
                withRecordType: kODRecordTypeUsers,
                name: NSUserName(),
                attributes: nil
            )
            try record.verifyPassword(password)
            return true
        } catch {
            return false
        }
    }
}
