import AppKit
import SwiftUI
import ClavisCore

/// Presentation mirrors key metadata; private records remain authoritative.
/// This does not grant access or alter the daemon's authorization decisions.
struct LibraryKeyPresentation: Equatable {
    let keyType: KeyType
    let typeTitle: String
    let symbol: String
    let tileSymbol: String
    let capabilities: [String]
    let purposeSummary: String
    let isDisabled: Bool

    init(purpose: KeyPurpose) {
        self.init(profile: KeyAccessProfile(legacyPurpose: purpose))
    }

    init(profile: KeyAccessProfile) {
        keyType = profile.type
        typeTitle = profile.type.title
        symbol = profile.type == .bot ? "desktopcomputer" : "person"
        tileSymbol = profile.type == .bot ? "cpu" : "person.fill"
        capabilities = profile.capabilities.titles
        isDisabled = !profile.capabilities.ssh && !profile.capabilities.signature

        if profile.capabilities.ssh && profile.capabilities.signature {
            purposeSummary = "SSH & Git signing"
        } else if profile.capabilities.ssh {
            purposeSummary = "SSH authentication"
        } else if profile.capabilities.signature {
            purposeSummary = "Git signing"
        } else {
            purposeSummary = "Disabled"
        }
    }

    var accessibilitySummary: String {
        ([typeTitle] + capabilities).joined(separator: ", ")
    }
}

struct SidebarHeaderPillButton: View {
    let icon: String
    var isActive: Bool = false
    let helpText: String
    var accessibilityLabelText: String? = nil
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(isActive ? DesignTokens.accentBlue : .primary)
                .frame(width: 30, height: 24)
                .background(
                    Capsule()
                        .fill(
                            isActive
                                ? DesignTokens.accentBlue.opacity(0.16)
                                : (isHovered ? Color.primary.opacity(0.07) : Color.clear)
                        )
                )
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(helpText)
        .accessibilityLabel(accessibilityLabelText ?? helpText)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.10)) {
                isHovered = hovering
            }
        }
    }
}

struct LibraryMetadataBadge: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.system(size: 9, weight: .medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
            .fixedSize()
    }
}

/// NSSearchField owns editing, the clear button, and native focus-ring rendering.
struct LibrarySearchField: NSViewRepresentable {
    @Binding var text: String
    @Binding var focused: Bool

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = "Search keys"
        field.setAccessibilityLabel("Search keys")
        field.controlSize = .regular
        field.sendsSearchStringImmediately = true
        field.sendsWholeSearchString = false
        field.delegate = context.coordinator
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.stringValue = text }
        guard focused, !context.coordinator.focusScheduled else { return }
        guard field.currentEditor() == nil else { return }
        context.coordinator.focusScheduled = true
        DispatchQueue.main.async { [weak field, weak coordinator = context.coordinator] in
            defer { coordinator?.focusScheduled = false }
            guard let field, coordinator?.parent.focused == true else { return }
            field.window?.makeFirstResponder(field)
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: LibrarySearchField
        var focusScheduled = false

        init(_ parent: LibrarySearchField) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            parent.text = field.stringValue
        }

        func controlTextDidBeginEditing(_ notification: Notification) {
            parent.focused = true
        }

        func controlTextDidEndEditing(_ notification: Notification) {
            parent.focused = false
        }

        func control(
            _ control: NSControl,
            textView: NSTextView,
            doCommandBy commandSelector: Selector
        ) -> Bool {
            guard commandSelector == #selector(NSResponder.cancelOperation(_:)) else { return false }
            if !parent.text.isEmpty {
                parent.text = ""
            } else {
                parent.focused = false
                control.window?.makeFirstResponder(nil)
            }
            return true
        }
    }
}

struct LibraryAgentStatus: View {
    let active: Bool
    var requestState: RequestPauseModel.State = .accepting
    var isBusy: Bool = false
    var onTogglePause: (() -> Void)? = nil
    var onLock: (() -> Void)? = nil
    var onOpenSettings: (() -> Void)? = nil

    var statusLabel: String {
        if !active {
            return "Agent offline"
        }
        switch requestState {
        case .paused:
            return "Clavis paused"
        case .unknown:
            return "Agent status unavailable"
        case .accepting:
            return "Clavis active"
        }
    }

    var dotColor: Color {
        guard active else { return Color.secondary }
        switch requestState {
        case .accepting:
            return DesignTokens.accentGreen
        case .paused:
            return DesignTokens.accentOrange
        case .unknown:
            return Color.secondary
        }
    }

    @State private var isStatusHovered = false
    @State private var isSettingsHovered = false

    var body: some View {
        HStack(spacing: 8) {
            if onTogglePause != nil || onLock != nil {
                Menu {
                    if let onTogglePause {
                        Button(role: requestState == .paused ? nil : .destructive, action: onTogglePause) {
                            Label(
                                requestState == .paused ? "Resume Requests…" : "Pause Requests…",
                                systemImage: requestState == .paused ? "play.circle" : "pause.circle"
                            )
                        }
                        .disabled(isBusy)
                    }
                    if let onLock {
                        Divider()
                        Button(action: onLock) {
                            Label("Lock Clavis", systemImage: "lock")
                        }
                    }
                } label: {
                    statusPillContent
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(isStatusHovered ? Color.primary.opacity(0.06) : Color.clear)
                )
                .onHover { isStatusHovered = $0 }
                .help(statusLabel)
                .accessibilityLabel("Clavis status: \(statusLabel)")
            } else {
                statusPillContent
                    .accessibilityElement(children: .combine)
            }

            Spacer(minLength: 4)

            if let onOpenSettings {
                Button(action: onOpenSettings) {
                    Image(systemName: "gearshape")
                        .font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(isSettingsHovered ? .primary : DesignTokens.textSecondary)
                        .frame(width: 28, height: 28)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(isSettingsHovered ? Color.primary.opacity(0.07) : Color.clear)
                        )
                        .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
                .buttonStyle(.plain)
                .onHover { isSettingsHovered = $0 }
                .help("Settings (⌘,)")
                .accessibilityLabel("Settings")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private var statusPillContent: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(dotColor)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(statusLabel)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(DesignTokens.textSecondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .frame(height: 26)
    }
}

/// A standard menu provides native selection, dismissal, and keyboard behavior.
struct LibraryMoreMenu: View {
    let history: () -> Void
    let settings: () -> Void
    let lock: () -> Void
    let revoke: () -> Void
    var paused = false
    var busy = false

    var body: some View {
        Menu {
            Button(action: history) {
                Label("Signing History", systemImage: "clock.arrow.circlepath")
            }
            Button(action: settings) {
                Label("Settings…", systemImage: "gearshape")
            }
            Divider()
            Button(action: lock) {
                Label("Lock Clavis", systemImage: "lock")
            }
            Button(role: .destructive, action: revoke) {
                Label(paused ? "Resume Requests…" : "Activate Kill Switch…", systemImage: paused ? "play.circle" : "stop.circle")
            }
            .disabled(busy)
            Divider()
            Link(destination: URL(string: "https://github.com/GDR/clavis#readme")!) {
                Label("Help & Documentation", systemImage: "questionmark.circle")
            }
        } label: {
            Image(systemName: "ellipsis")
                .font(.system(size: 15, weight: .medium))
                .frame(width: 33, height: 33)
                .contentShape(Circle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .liquidGlassCapsuleControl()
        .help("More")
        .accessibilityLabel("More")
    }
}
