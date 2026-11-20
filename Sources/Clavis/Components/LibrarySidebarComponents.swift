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
        // D-32 glossary: Personal / Agent (never "Bot"), independent of the legacy model title.
        typeTitle = profile.type == .bot ? "Agent" : "Personal"
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

/// One icon button inside the sidebar toolbar pill (S02.toolbar-pill): 36×30 hit area,
/// 16.5pt glyph, hover/active tint only — the surrounding capsule supplies the glass.
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
                .font(.system(size: 16.5, weight: .regular))
                .foregroundStyle(isActive ? Color.accentColor : .primary)
                .frame(width: 36, height: 30)
                .background(
                    Capsule()
                        .fill(
                            isActive
                                ? Color.accentColor.opacity(0.16)
                                : (isHovered ? Color.primary.opacity(0.07) : Color.clear)
                        )
                )
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(helpText)
        .accessibilityLabel(accessibilityLabelText ?? helpText)
        .accessibilityAddTraits(isActive ? [.isSelected] : [])
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.10)) {
                isHovered = hovering
            }
        }
    }
}

/// S02.toolbar-pill: one 36pt Liquid Glass capsule cluster (New Key · History · Lock) on the
/// shared traffic-light midline, mirroring the prototype's `#hdb` pill.
struct SidebarToolbarPill: View {
    var isHistoryActive: Bool = false
    var isCreateSheetActive: Bool = false
    let onNewKey: () -> Void
    let onToggleHistory: () -> Void
    let onLock: () -> Void

    var body: some View {
        HStack(spacing: 2) {
            SidebarHeaderPillButton(
                icon: "plus",
                isActive: isCreateSheetActive,
                helpText: "New Key (⌘N)",
                accessibilityLabelText: ClavisUIStrings.Accessibility.addKey,
                action: onNewKey
            )
            SidebarHeaderPillButton(
                icon: "clock.arrow.circlepath",
                isActive: isHistoryActive,
                helpText: "History (⇧⌘H)",
                accessibilityLabelText: "History",
                action: onToggleHistory
            )
            SidebarHeaderPillButton(
                icon: "lock",
                helpText: "Lock Now (⌘L)",
                accessibilityLabelText: "Lock Clavis",
                action: onLock
            )
        }
        .padding(3)
        .frame(height: KeyListView.actionControlHeight)
        .modifier(CapsuleGlassBackground(isActive: false, isHovered: false, reduceTransparency: reduceTransparency))
        .fixedSize()
    }

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
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
        field.placeholderString = "Search keys, apps…"
        field.setAccessibilityLabel("Search keys")
        field.controlSize = .regular
        // The SwiftUI host supplies the single Liquid Glass capsule; the native field must not
        // paint its own opaque inset bezel over it. Editing, Clear and the search glyph stay native.
        field.isBezeled = false
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        // Without a bezel the cell no longer reserves room for its own glyph (it overdrew the text),
        // so the host draws the magnifier and the cell keeps only text editing and the native Clear button.
        (field.cell as? NSSearchFieldCell)?.searchButtonCell = nil
        field.font = .systemFont(ofSize: 13)
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

/// Sidebar bottom-bar status: passive dot + label (D-38). The request-pause state model is
/// still reflected in the label, but pause/resume controls are gone.
struct LibraryAgentStatus: View {
    let active: Bool
    var requestState: RequestPauseModel.State = .accepting
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

    /// S02.footer-status: passive plain text (dot + label). No button, no chevron, no menu,
    /// no hover capsule (D-38 removed the pause/resume surface; the state model stays).
    var body: some View {
        HStack(spacing: 8) {
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
            .padding(.horizontal, 4)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Clavis status: \(statusLabel)")

            Spacer(minLength: 4)

            if let onOpenSettings {
                // S02.footer-settings: 36pt circular glass button, same sizing as toolbar controls.
                CircularGlassIconButton(
                    icon: "gearshape",
                    size: DesignTokens.footerGearSize,
                    iconSize: 16.5,
                    helpText: "Settings (⌘,)",
                    accessibilityLabel: ClavisUIStrings.Accessibility.settings,
                    action: onOpenSettings
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
    }
}


