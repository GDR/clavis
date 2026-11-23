import Foundation
import ClavisCore

/// A signing authorization shown in the S-01 Menu Bar, paired with key metadata.
struct MenuBarSession: Identifiable, Equatable {
    enum Target: Hashable {
        case git(keyLabel: String)
        case agent(sessionID: String)
    }

    var id: Target { target }
    let target: Target
    let keyLabel: String
    let keyFingerprint: String?
    let publicKeyOpenSSH: String?
    let purpose: KeyPurpose
    let accessProfile: KeyAccessProfile
    let expiresAt: Date
    let endsAtLock: Bool
    let callerName: String?

    var toolName: String? { callerName }
    var isAgentKey: Bool { accessProfile.type == .bot }
    var iconSystemName: String { isAgentKey ? "cpu" : "person.fill" }

    var subtitle: String {
        if let callerName = callerName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !callerName.isEmpty {
            return callerName
        }
        return LibraryKeyPresentation(profile: accessProfile).purposeSummary
    }

    func isExpiringSoon(at date: Date) -> Bool {
        !endsAtLock && expiresAt.timeIntervalSince(date) <= 60
    }

    func remainingTime(at date: Date) -> String {
        if endsAtLock {
            return ClavisUIStrings.MenuBar.endsOnLock
        }
        return Self.formatRemaining(expiresAt.timeIntervalSince(date))
    }

    static func formatRemaining(_ seconds: TimeInterval) -> String {
        let mins = max(1, Int(ceil(max(0, seconds) / 60.0)))
        if mins < 60 {
            return "\(mins)m left"
        }
        let hrs = Int((Double(mins) / 60.0).rounded())
        if hrs < 24 {
            return "\(hrs)h left"
        }
        let days = Int((Double(hrs) / 24.0).rounded())
        if days < 365 {
            return "\(days)d left"
        }
        let years = Int((Double(days) / 365.0).rounded())
        return "\(years)y left"
    }

    static func active(
        gitGraces: [ActiveGitGraceInfo],
        agentSessions: [AgentSessionSummary],
        keys: [SSHKeyInfo],
        at date: Date
    ) -> [Self] {
        var groupedGit: [String: [ActiveGitGraceInfo]] = [:]
        for grace in gitGraces where grace.expiresAt > date && grace.remainingOperations > 0 {
            groupedGit[grace.keyLabel, default: []].append(grace)
        }

        let git: [Self] = groupedGit.compactMap { label, grants in
            guard let maxExpiresAt = grants.map(\.expiresAt).max() else { return nil }
            let key = keys.first { $0.label == label }
            let purpose = key?.purpose ?? .general
            let accessProfile = key?.effectiveAccessProfile ?? KeyAccessProfile(legacyPurpose: purpose)
            let caller = grants
                .compactMap { $0.callerName?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .first { !$0.isEmpty }
            return Self(
                target: .git(keyLabel: label),
                keyLabel: label,
                keyFingerprint: key?.fingerprint,
                publicKeyOpenSSH: key?.publicKeyOpenSSH,
                purpose: purpose,
                accessProfile: accessProfile,
                expiresAt: maxExpiresAt,
                endsAtLock: grants.contains(where: \.endsAtLock),
                callerName: caller
            )
        }

        let agents = agentSessions.compactMap { session -> Self? in
            guard session.expiresAt > date else { return nil }
            let key = keys.first { $0.fingerprint == session.keyFingerprint }
                ?? keys.first { $0.label == session.keyLabel }
            let purpose = key?.purpose ?? .agent
            let accessProfile = key?.effectiveAccessProfile ?? KeyAccessProfile(legacyPurpose: purpose)
            let trimmedTool = session.toolName.trimmingCharacters(in: .whitespacesAndNewlines)
            return Self(
                target: .agent(sessionID: session.id),
                keyLabel: session.keyLabel,
                keyFingerprint: session.keyFingerprint,
                publicKeyOpenSSH: key?.publicKeyOpenSSH,
                purpose: purpose,
                accessProfile: accessProfile,
                expiresAt: session.expiresAt,
                endsAtLock: false,
                callerName: trimmedTool.isEmpty ? nil : trimmedTool
            )
        }

        return (git + agents).sorted {
            let order = $0.keyLabel.localizedStandardCompare($1.keyLabel)
            if order != .orderedSame { return order == .orderedAscending }
            if $0.expiresAt != $1.expiresAt { return $0.expiresAt < $1.expiresAt }
            return String(describing: $0.target) < String(describing: $1.target)
        }
    }

    static func inactiveKeys(from keys: [SSHKeyInfo], active: [Self]) -> [SSHKeyInfo] {
        let activeLabels = Set(active.map(\.keyLabel))
        let activeFingerprints = Set(active.compactMap { session -> String? in
            guard let fp = session.keyFingerprint, !fp.isEmpty else { return nil }
            return fp
        })
        return keys
            .filter { key in
                !activeLabels.contains(key.label) &&
                (key.fingerprint.isEmpty || !activeFingerprints.contains(key.fingerprint))
            }
            .sorted {
                $0.label.localizedStandardCompare($1.label) == .orderedAscending
            }
    }
}
