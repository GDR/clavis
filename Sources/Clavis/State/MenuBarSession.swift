import Foundation
import ClavisCore

/// A signing authorization shown in the menu, rather than every stored identity.
struct MenuBarSession: Identifiable, Equatable {
    enum Target: Hashable {
        case git(keyLabel: String)
        case agent(sessionID: String)
    }

    var id: Target { target }
    let target: Target
    let keyLabel: String
    let purpose: KeyPurpose
    let expiresAt: Date
    let toolName: String?

    func remainingTime(at date: Date) -> String {
        let seconds = max(0, Int(ceil(expiresAt.timeIntervalSince(date))))
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    static func active(
        gitGraces: [ActiveGitGraceInfo],
        agentSessions: [AgentSessionSummary],
        keys: [SSHKeyInfo],
        at date: Date
    ) -> [Self] {
        let git = gitGraces.compactMap { grace -> Self? in
            guard grace.expiresAt > date, grace.remainingOperations > 0 else { return nil }
            return Self(
                target: .git(keyLabel: grace.keyLabel),
                keyLabel: grace.keyLabel,
                purpose: keys.first { $0.label == grace.keyLabel }?.purpose ?? .general,
                expiresAt: grace.expiresAt,
                toolName: nil
            )
        }
        let agents = agentSessions.compactMap { session -> Self? in
            guard session.expiresAt > date else { return nil }
            return Self(
                target: .agent(sessionID: session.id),
                keyLabel: session.keyLabel,
                purpose: keys.first { $0.fingerprint == session.keyFingerprint }?.purpose ?? .agent,
                expiresAt: session.expiresAt,
                toolName: session.toolName
            )
        }
        return (git + agents).sorted {
            let order = $0.keyLabel.localizedStandardCompare($1.keyLabel)
            if order != .orderedSame { return order == .orderedAscending }
            if $0.expiresAt != $1.expiresAt { return $0.expiresAt < $1.expiresAt }
            return String(describing: $0.target) < String(describing: $1.target)
        }
    }
}
