import SwiftUI
import AppKit
import ClavisCore

/// S-05 Connect & Test (F1): register the public key, point SSH/Git/the agent at Clavis,
/// then prove it works. Ported from `.ux` variant S-05; snippets use the app's real socket
/// paths (`~/.ssh/clavis*.sock`), matching `EmptyVaultOnboardingView`.
@MainActor
struct ConnectTestSheet: View {
    var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var history = HistoryViewModel()
    @State private var tab: String = "All SSH"
    @State private var routingAgent: String = "Claude Code"
    @State private var copiedSnippet: String? = nil

    private var key: SSHKeyInfo? { appState.connectTarget }
    private var isAgent: Bool { key?.effectiveAccessProfile.type == .bot }
    private var isGit: Bool { key?.purpose == .gitSigningOnly }
    private var tabs: [String] {
        var t = ["All SSH", "One host", "Git signing"]
        if isAgent { t.append("Agent routing") }
        return t
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if let key {
                stepOne(key)
                stepTwo(key)
                stepThree(key)
            } else {
                Text("No key selected.")
                    .font(.system(size: 12))
                    .foregroundStyle(DesignTokens.textSecondary)
            }
            footer
        }
        .padding(22)
        .frame(width: 620)
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear {
            tab = isAgent ? "Agent routing" : (isGit ? "Git signing" : "All SSH")
            history.updateKeys(appState.keys)
            history.reload()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Connect “\(key?.label ?? "key")”")
                .font(.system(size: 20, weight: .bold))
            Text("Three steps: register the public key, point your tools at Clavis, prove it works.")
                .font(.system(size: 12))
                .foregroundStyle(DesignTokens.textSecondary)
        }
    }

    private func stepBadge(_ n: Int) -> some View {
        Text("\(n)")
            .font(.system(size: 11, weight: .bold))
            .foregroundColor(.white)
            .frame(width: 20, height: 20)
            .background(Circle().fill(Color.accentColor))
    }

    private func stepOne(_ key: SSHKeyInfo) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                stepBadge(1)
                Text(isAgent ? "Register the public key" : "Add the public key to GitHub")
                    .font(.system(size: 13, weight: .semibold))
            }
            Text(isAgent
                 ? "As a deploy key, or on the agent's own GitHub account."
                 : (isGit ? "Add it as a signing key." : "Add it as an authentication key."))
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
            HStack(spacing: 8) {
                Button("Copy Public Key") { copy(key.publicKeyOpenSSH, id: "pub") }
                    .buttonStyle(.borderedProminent)
                Button("Open GitHub…") {
                    NSWorkspace.shared.open(URL(string: "https://github.com/settings/keys")!)
                }
            }
            .controlSize(.small)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .modifier(SettingsGroupCardModifier(cornerRadius: 10))
    }

    private func stepTwo(_ key: SSHKeyInfo) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                stepBadge(2)
                Text("Point \(isAgent ? "the agent" : (isGit ? "Git" : "SSH")) at Clavis")
                    .font(.system(size: 13, weight: .semibold))
            }
            Picker("Snippet", selection: $tab) {
                ForEach(tabs, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            snippetBlock(snippet(for: key))
            if tab == "Agent routing" { routingTable }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .modifier(SettingsGroupCardModifier(cornerRadius: 10))
    }

    private func snippet(for key: SSHKeyInfo) -> String {
        switch tab {
        case "One host":
            return """
            Host github.com
                IdentityAgent ~/.ssh/clavis.sock
                IdentitiesOnly yes
            """
        case "Git signing":
            return """
            git config gpg.format ssh
            git config user.signingkey ~/.ssh/\(key.label).pub
            git config commit.gpgsign true
            """
        case "Agent routing":
            return "CLAVIS_SOCK=~/.ssh/clavis-agent.sock"
        default:
            return EmptyVaultOnboardingView.sshAuthSockCommand
        }
    }

    private func snippetBlock(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(text)
                .font(.system(size: 11.5, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 8).fill(DesignTokens.settingsGroupFill))
            HStack {
                Text(tab == "All SSH"
                     ? "Add to ~/.zshenv (not .zshrc: agents run non-interactive shells). Clavis never edits your shell or SSH config."
                     : tab == "Git signing"
                     ? "Copy the public key into ~/.ssh/\(key?.label ?? "key").pub first (step 1), or add --global to sign everywhere."
                     : tab == "Agent routing"
                     ? "Set in the agent's environment/config. Routing, not enforcement — the agent can undo it."
                     : "Add to ~/.ssh/config to use this key for one host only.")
                    .font(.system(size: 11))
                    .foregroundStyle(DesignTokens.textTertiary)
                Spacer()
                Button(copiedSnippet == tab ? "Copied ✓" : "Copy") { copy(snippet(for: key!), id: tab) }
                    .controlSize(.small)
            }
        }
    }

    private var routingTable: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker("Agent", selection: $routingAgent) {
                ForEach(["Claude Code", "Codex", "Antigravity"], id: \.self) { Text($0).tag($0) }
            }
            .labelsHidden()
            .frame(width: 180)
            if routingAgent == "Codex" {
                Text("Codex in sandbox mode can't reach Clavis at all. Use full-access mode to sign.")
                    .font(.system(size: 11))
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(DesignTokens.accentOrange.opacity(0.14)))
            }
            ForEach([
                ("R1", "Self-routing snippet", "Agents that run git without a shell"),
                ("R2", "Per-agent config", "Other agents"),
                ("R3", "Per-repo Git config", "Other repos"),
                ("R4", "Host alias", "Default remotes"),
                ("R5", "Identity fallback", "First use")
            ], id: \.0) { row in
                HStack(alignment: .top, spacing: 8) {
                    Text(row.0).font(.system(size: 11, weight: .bold)).frame(width: 22, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(row.1).font(.system(size: 11.5, weight: .semibold))
                        Text("Covers: \(row.2)").font(.system(size: 10.5)).foregroundStyle(DesignTokens.textTertiary)
                    }
                }
            }
        }
    }

    private func stepThree(_ key: SSHKeyInfo) -> some View {
        let used = history.records.first(where: { (r: AuditRecord) -> Bool in
            r.event.sensitive.keyLabel == key.label && r.event.result == .allowed
        })
        let test = isGit ? "git commit --allow-empty -S -m \"Clavis test\"" : "ssh -T git@github.com"
        let callerPath = used?.event.sensitive.processChain.first?.executablePath
        let caller: String = callerPath.map { ($0 as NSString).lastPathComponent } ?? "your tool"
        let statusText: String = used == nil
            ? "Waiting for first use…"
            : "✓ It works. Used by \(caller)."
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                stepBadge(3)
                Text("Test it").font(.system(size: 13, weight: .semibold))
            }
            Text(isAgent ? "Ask the agent to push or commit, or run in its shell:" : "Run in Terminal:")
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
            snippetBlock(test)
            HStack(spacing: 6) {
                if used != nil {
                    Text(statusText)
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(DesignTokens.accentGreen)
                } else {
                    Text(statusText)
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                Spacer()
                Button("Show All History") {
                    appState.activeMainPane = .history
                    dismiss()
                }
                .controlSize(.small)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .modifier(SettingsGroupCardModifier(cornerRadius: 10))
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Finish Later") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
    }

    private func copy(_ text: String, id: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copiedSnippet = id
    }
}
