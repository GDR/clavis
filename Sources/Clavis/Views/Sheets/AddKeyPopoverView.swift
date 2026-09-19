import SwiftUI
import ClavisCore

public struct AddKeyPopoverView: View {
    public var onNewKey: () -> Void
    public var onImportKey: () -> Void

    public init(onNewKey: @escaping () -> Void, onImportKey: @escaping () -> Void) {
        self.onNewKey = onNewKey
        self.onImportKey = onImportKey
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("ADD KEY")
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(DesignTokens.textTertiary)
                .padding(.horizontal, 10)
                .padding(.top, 8)
                .padding(.bottom, 2)

            AddKeyPopoverRow(
                icon: "plus",
                title: "New Key…",
                shortcut: "⌘N",
                subtitle: "Generate a new cryptographic identity",
                action: onNewKey
            )

            AddKeyPopoverRow(
                icon: "arrow.down",
                title: "Import Key…",
                shortcut: "⇧⌘I",
                subtitle: "Store an existing private key securely",
                action: onImportKey
            )
        }
        .padding(6)
        .frame(width: 290)
    }
}

private struct AddKeyPopoverRow: View {
    let icon: String
    let title: String
    let shortcut: String
    let subtitle: String
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color.white.opacity(0.10))
                        .frame(width: 28, height: 28)
                    Image(systemName: icon)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.white)
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(title)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.primary)
                        Spacer()
                        Text(shortcut)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(DesignTokens.textTertiary)
                    }
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(isHovered ? Color.white.opacity(0.08) : Color.clear)
            )
            .contentShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }
}
