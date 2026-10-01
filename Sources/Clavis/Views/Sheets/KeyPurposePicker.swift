import SwiftUI
import ClavisCore

/// Shared key-purpose selector (domain isolation) used by the create and import sheets.
struct KeyPurposePicker: View {
    @Binding var selection: KeyPurpose
    let accent: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(ClavisUIStrings.CreateKey.purposeLabel)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(DesignTokens.textSecondary)

            HStack(spacing: 10) {
                ForEach(KeyPurpose.allCases) { purpose in
                    Button(action: {
                        selection = purpose
                    }) {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: purpose == .gitSigningOnly ? "arrow.triangle.branch" : "network")
                                    .foregroundColor(selection == purpose ? accent : .secondary)
                                Spacer()
                                if selection == purpose {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(accent)
                                        .font(.caption)
                                }
                            }
                            Text(purpose.title)
                                .font(.subheadline)
                                .fontWeight(.medium)
                            Text(purpose.subtitle)
                                .font(.caption2)
                                .foregroundColor(DesignTokens.textSecondary)
                                .lineLimit(2)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, minHeight: 64, alignment: .topLeading)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(selection == purpose ? accent.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(selection == purpose ? accent : DesignTokens.cardBorder, lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}
