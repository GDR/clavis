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
                                Image(systemName: icon(for: purpose))
                                    .foregroundColor(selection == purpose ? accent : .secondary)
                                Spacer()
                                if selection == purpose {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(accent)
                                        .font(.caption)
                                }
                            }
                            Text(purpose.title)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.primary)
                            Text(purpose.subtitle)
                                .font(.system(size: 11))
                                .foregroundColor(DesignTokens.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, minHeight: 74, alignment: .topLeading)
                        .liquidGlassControl(cornerRadius: 9, isSelected: selection == purpose)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(selection == purpose ? [.isSelected] : [])
                }
            }
        }
    }

    private func icon(for purpose: KeyPurpose) -> String {
        switch purpose {
        case .general:
            return "network"
        case .gitSigningOnly:
            return "arrow.triangle.branch"
        case .agent:
            return "cpu"
        }
    }
}
