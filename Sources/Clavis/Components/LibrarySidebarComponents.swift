import AppKit
import SwiftUI
import ClavisCore

/// Presentation mirrors key metadata; private records remain authoritative.
/// This does not grant access or alter the daemon's authorization decisions.
struct LibraryKeyPresentation: Equatable {
    let typeTitle: String
    let symbol: String
    let capabilities: [String]

    init(purpose: KeyPurpose) {
        self.init(profile: KeyAccessProfile(legacyPurpose: purpose))
    }

    init(profile: KeyAccessProfile) {
        typeTitle = profile.type.title
        symbol = profile.type == .bot ? "desktopcomputer" : "person"
        capabilities = profile.capabilities.titles
    }

    var accessibilitySummary: String {
        ([typeTitle] + capabilities).joined(separator: ", ")
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

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(active && requestState == .accepting ? Color.green : Color.secondary)
                .frame(width: 6, height: 6)
                .accessibilityHidden(true)
            Text(!active ? "Agent unavailable" : requestState == .paused ? "Requests paused" : requestState == .unknown ? "Agent status unavailable" : "Agent active")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
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
