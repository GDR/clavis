import SwiftUI
import AppKit
import ClavisCore
import CryptoKit

public enum KeyTypePreset: String, CaseIterable, Identifiable {
    case hardware = "hardware"

    public var id: String { rawValue }

    public var title: String {
        ClavisUIStrings.CreateKey.hardwareTitle
    }

    public var badge: String {
        ClavisUIStrings.CreateKey.hardwareBadge
    }

    public var subtitle: String {
        ClavisUIStrings.CreateKey.hardwareSubtitle
    }

    public var icon: String {
        "cpu"
    }

    public var storageType: KeyStorageType {
        .secureEnclave
    }

    public var algorithm: KeyAlgorithm {
        .ecdsaP256
    }
}

// MARK: - Reference help popover content (S-04)

struct CreateKeyReferenceRow: Equatable {
    let label: String
    let detail: String
}

enum CreateKeyReferenceContent {
    static let title = "New Key Reference"
    static let rows: [CreateKeyReferenceRow] = [
        CreateKeyReferenceRow(label: "Type", detail: "Fixed at creation. Agents only prompt for Agent keys."),
        CreateKeyReferenceRow(label: "Strict Biometrics", detail: "Touch ID only + password fallback; invalidated if fingerprints change."),
        CreateKeyReferenceRow(label: "User Presence", detail: "Touch ID, Apple Watch, or Mac login password."),
        CreateKeyReferenceRow(label: "Password", detail: "Mac login password only. Biometric keys need Rotate to downgrade."),
        CreateKeyReferenceRow(label: "Timeout", detail: "Session per key + app; Agent sessions survive lock."),
        CreateKeyReferenceRow(label: "Storage", detail: "NIST P-256 hardware key; private key cannot be exported."),
    ]
}

public struct CreateKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    public static let defaultBiometricPolicy: BiometricPolicy = .userPresence
    public static let defaultPurpose: KeyPurpose = .general
    public static let sheetTitle = "New Key"
    public static let namePlaceholderText = "GitHub SSH"
    public static let storageFootnoteText = "Stored in Apple Secure Enclave (P-256). Non-exportable."

    /// D-40: the three creation-time policies. Legacy `.biometryCurrentSet` keys exist only before this model.
    static let creationPolicies: [BiometricPolicy] = [.biometryOrPasscode, .userPresence, .devicePasscode]

    /// D-40 unlocked timeout menu: Once · 15 min · 8 hours · Until Lock · 1 Day.
    /// `.always` maps to "Once" and `.session` (8 h) maps to "8 hours".
    static let unlockedTimeoutOptions: [(period: KeyGracePeriod, title: String)] = [
        (.always, "Once"),
        (.fifteenMinutes, "15 min"),
        (.session, "8 hours"),
        (.untilLock, "Until Lock"),
        (.oneDay, "1 Day"),
    ]
    static let defaultUnlockedTimeout: KeyGracePeriod = .fifteenMinutes

    // MARK: - Appearance tokens (compact FormStyle.grouped sheet)

    private enum Palette {
        static let sheetPanel = dynamicColor(
            dark: NSColor(calibratedRed: 0.157, green: 0.157, blue: 0.169, alpha: 1),
            light: NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 1)
        )
        static let insetPanel = dynamicColor(
            dark: NSColor(calibratedRed: 0.137, green: 0.137, blue: 0.149, alpha: 1),
            light: NSColor(calibratedRed: 0.949, green: 0.949, blue: 0.961, alpha: 1)
        )
        static let inputFill = dynamicColor(
            dark: NSColor(calibratedRed: 0.110, green: 0.110, blue: 0.118, alpha: 1),
            light: NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 1)
        )
        static let inputBorder = dynamicColor(
            dark: NSColor(calibratedWhite: 1, alpha: 0.15),
            light: NSColor(calibratedWhite: 0, alpha: 0.15)
        )
        static let separator = dynamicColor(
            dark: NSColor(calibratedWhite: 1, alpha: 0.075),
            light: NSColor(calibratedWhite: 0, alpha: 0.075)
        )
        static let controlFill = dynamicColor(
            dark: NSColor(calibratedRed: 0.220, green: 0.220, blue: 0.235, alpha: 1),
            light: NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 1)
        )
        static let controlBorder = dynamicColor(
            dark: NSColor(calibratedWhite: 1, alpha: 0.13),
            light: NSColor(calibratedWhite: 0, alpha: 0.14)
        )
        static let segmentTrack = dynamicColor(
            dark: NSColor(calibratedWhite: 1, alpha: 0.08),
            light: NSColor(calibratedWhite: 0, alpha: 0.055)
        )
        static let subtleHover = dynamicColor(
            dark: NSColor(calibratedWhite: 1, alpha: 0.06),
            light: NSColor(calibratedWhite: 0, alpha: 0.045)
        )

        private static func dynamicColor(dark: NSColor, light: NSColor) -> Color {
            Color(nsColor: NSColor(name: nil) { appearance in
                appearance.isDarkMode ? dark : light
            })
        }
    }

    @FocusState private var isLabelFocused: Bool
    @State private var keyName: String = ""
    @State private var selectedPreset: KeyTypePreset = .hardware
    @State private var selectedBiometricPolicy: BiometricPolicy = Self.defaultBiometricPolicy
    @State private var selectedType: KeyType = .personal
    @State private var sshEnabled = true
    @State private var signatureEnabled = true
    @State private var selectedTimeout: KeyGracePeriod = CreateKeySheet.defaultUnlockedTimeout
    @State private var isCreating = false
    @State private var errorMessage: String? = nil
    @State private var isShowingReference = false

    public init(appState: AppState) {
        self.appState = appState
    }

    public var isGenerateDisabled: Bool {
        Self.isGenerateDisabled(
            name: keyName,
            sshEnabled: sshEnabled,
            signatureEnabled: signatureEnabled,
            isCreating: isCreating
        )
    }

    /// Generate stays disabled until the name is non-empty AND at least one capability is on.
    static func isGenerateDisabled(name: String, sshEnabled: Bool, signatureEnabled: Bool, isCreating: Bool) -> Bool {
        name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (!sshEnabled && !signatureEnabled) || isCreating
    }

    public static func typeFootnote(for type: KeyType) -> String {
        switch type {
        case .personal:
            return "Personal keys never appear on the agent socket."
        case .bot:
            return "For AI agents. Each app is approved on first use."
        }
    }

    public static func confirmationFootnote(policy: BiometricPolicy, timeout: KeyGracePeriod) -> String {
        let policyHint: String
        switch policy {
        case .biometryOrPasscode, .biometryCurrentSet:
            policyHint = "Touch ID (invalidated if fingerprints change)."
        case .userPresence:
            policyHint = "Touch ID, Apple Watch, or password."
        case .devicePasscode:
            policyHint = "Mac login password only."
        }

        let timeoutTitle = unlockedTimeoutOptions.first(where: { $0.period == timeout })?.title ?? timeout.title
        let timeoutHint: String
        switch timeout {
        case .always:
            timeoutHint = "Prompts on every request."
        case .untilLock:
            timeoutHint = "Stays unlocked until lock per app."
        default:
            timeoutHint = "Unlocks \(timeoutTitle) per app."
        }
        return "\(policyHint) \(timeoutHint)"
    }

    private var selectedTimeoutTitle: String {
        Self.unlockedTimeoutOptions.first(where: { $0.period == selectedTimeout })?.title ?? selectedTimeout.title
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(Self.sheetTitle)
                .font(.system(size: 16, weight: .semibold))
                .padding(.bottom, 14)

            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                    Spacer()
                }
                .padding(8)
                .background(Color.red.opacity(0.12))
                .cornerRadius(6)
                .padding(.bottom, 12)
            }

            // Group 1: Name + Type
            groupedCard {
                groupedRow {
                    Text(ClavisUIStrings.CreateKey.nameLabel == "Key Name" ? "Name" : ClavisUIStrings.CreateKey.nameLabel)
                        .font(.system(size: 13))
                } control: {
                    TextField(Self.namePlaceholderText, text: $keyName)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                        .focused($isLabelFocused)
                        .focusEffectDisabled()
                        .onSubmit {
                            if !isGenerateDisabled {
                                createKey()
                            }
                        }
                        .padding(.horizontal, 9)
                        .frame(width: 230, height: 26)
                        .background(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .fill(Palette.inputFill)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .strokeBorder(
                                    isLabelFocused ? Color.accentColor : Palette.inputBorder,
                                    lineWidth: 1
                                )
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .stroke(
                                    Color.accentColor.opacity(isLabelFocused ? 0.26 : 0),
                                    lineWidth: 3
                                )
                                .padding(-1.5)
                        )
                        .contentShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                        .onTapGesture {
                            isLabelFocused = true
                        }
                        .accessibilityLabel("Name")
                }

                groupedDivider

                groupedRow {
                    Text("Type")
                        .font(.system(size: 13))
                } control: {
                    OwnerSegmentedControl(
                        selection: $selectedType,
                        personalTitle: "Personal",
                        agentTitle: "Agent",
                        trackFill: Palette.segmentTrack,
                        trackBorder: Palette.separator,
                        selectedFill: Palette.controlFill,
                        selectedBorder: Palette.inputBorder
                    )
                }
            }

            footnoteText(Self.typeFootnote(for: selectedType))

            // Group 2: Confirmation + Unlocked timeout
            groupedCard {
                groupedRow {
                    Text("Confirmation")
                        .font(.system(size: 13))
                } control: {
                    popupControl(label: selectedBiometricPolicy.title, accessibilityLabel: "Confirmation policy") {
                        ForEach(Self.creationPolicies) { policy in
                            Button {
                                selectedBiometricPolicy = policy
                            } label: {
                                if selectedBiometricPolicy == policy {
                                    Label(policy.title, systemImage: "checkmark")
                                } else {
                                    Text(policy.title)
                                }
                            }
                        }
                    }
                }

                groupedDivider

                groupedRow {
                    Text("Unlocked timeout")
                        .font(.system(size: 13))
                } control: {
                    popupControl(label: selectedTimeoutTitle, accessibilityLabel: "Unlocked timeout") {
                        ForEach(Self.unlockedTimeoutOptions, id: \.period) { option in
                            Button {
                                selectedTimeout = option.period
                            } label: {
                                if selectedTimeout == option.period {
                                    Label(option.title, systemImage: "checkmark")
                                } else {
                                    Text(option.title)
                                }
                            }
                        }
                    }
                }
            }
            .padding(.top, 12)

            footnoteText(Self.confirmationFootnote(policy: selectedBiometricPolicy, timeout: selectedTimeout))

            // Group 3: Capabilities
            groupedCard {
                groupedRow {
                    Text("SSH authentication")
                        .font(.system(size: 13))
                } control: {
                    Toggle("", isOn: $sshEnabled)
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .tint(.accentColor)
                        .accessibilityLabel("SSH authentication")
                }

                groupedDivider

                groupedRow {
                    Text("Git commit signing")
                        .font(.system(size: 13))
                } control: {
                    Toggle("", isOn: $signatureEnabled)
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .tint(.accentColor)
                        .accessibilityLabel("Git commit signing")
                }
            }
            .padding(.top, 12)

            footnoteText(SecureEnclave.isAvailable ? Self.storageFootnoteText : ClavisUIStrings.CreateKey.enclaveUnavailable)

            // Footer: single "?" reference trigger left, standard 28pt capsule actions right.
            HStack(spacing: 8) {
                Button {
                    isShowingReference.toggle()
                } label: {
                    Text("?")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(isShowingReference ? Color.accentColor : DesignTokens.textSecondary)
                        .frame(width: 24, height: 24)
                        .background(Circle().fill(Palette.controlFill))
                        .overlay(
                            Circle().strokeBorder(
                                isShowingReference ? Color.accentColor : Palette.controlBorder,
                                lineWidth: 1
                            )
                        )
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help("About key options")
                .accessibilityLabel("About key options")
                .popover(isPresented: $isShowingReference, arrowEdge: .top) {
                    CreateKeyReferencePopover { isShowingReference = false }
                }

                Spacer()

                Button(ClavisUIStrings.Common.cancel) {
                    dismiss()
                }
                .liquidGlassButton(prominent: false)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
                .keyboardShortcut(.cancelAction)

                Button(ClavisUIStrings.CreateKey.generateButton) {
                    createKey()
                }
                .liquidGlassButton(prominent: true)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .disabled(isGenerateDisabled)
            }
            .padding(.top, 18)
        }
        .padding(EdgeInsets(top: 20, leading: 22, bottom: 20, trailing: 22))
        .frame(width: 460)
        .background(Palette.sheetPanel)
        .onAppear {
            isLabelFocused = true
            ClavisLogger.promptDebug("calvis-ui", "CreateKeySheet: presenting compact create key sheet")
        }
    }

    private func groupedCard<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: 0) {
            content()
        }
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Palette.insetPanel)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Palette.separator, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var groupedDivider: some View {
        Rectangle()
            .fill(Palette.separator)
            .frame(height: 1)
            .padding(.horizontal, 14)
    }

    private func groupedRow<Leading: View, Control: View>(
        @ViewBuilder leading: () -> Leading,
        @ViewBuilder control: () -> Control
    ) -> some View {
        HStack(spacing: 12) {
            leading()
            Spacer(minLength: 12)
            control()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .frame(minHeight: 38)
    }

    private func footnoteText(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11.5))
            .foregroundStyle(DesignTokens.textSecondary)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 4)
            .padding(.top, 5)
    }

    private func popupControl<MenuItems: View>(
        label: String,
        accessibilityLabel: String,
        @ViewBuilder items: @escaping () -> MenuItems
    ) -> some View {
        Menu {
            items()
        } label: {
            HStack(spacing: 8) {
                Text(label)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.primary)
                Spacer(minLength: 4)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(DesignTokens.textSecondary)
            }
            .padding(.leading, 10)
            .padding(.trailing, 8)
            .frame(minWidth: 168)
            .frame(height: 26)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Palette.controlFill)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(Palette.controlBorder, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel(accessibilityLabel)
    }

    // MARK: - Creation plumbing (unchanged auth path)

    private func createKey() {
        let label = keyName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !label.isEmpty, sshEnabled || signatureEnabled else { return }
        ClavisLogger.promptDebug("calvis-ui", "CreateKeySheet: submitting create key for '\(label)' (preset: \(selectedPreset.rawValue), type: \(selectedType.rawValue))")

        isCreating = true
        errorMessage = nil

        do {
            let info = try appState.generateKey(
                label: label,
                algorithm: selectedPreset.algorithm.rawValue,
                storageType: selectedPreset.storageType,
                biometricPolicy: selectedPreset == .hardware ? selectedBiometricPolicy : nil,
                accessProfile: KeyAccessProfile(type: selectedType,
                    capabilities: KeyCapabilities(ssh: sshEnabled, signature: signatureEnabled)),
                unlockedTimeout: selectedTimeout
            )
            // Keep UserDefaults mirror aligned with the key's authoritative unlockedTimeout.
            appState.setGracePeriod(selectedTimeout, for: info)
            // F1: create → connect & test, one guided flow.
            appState.connectTarget = info
            appState.activeSheet = .connect
        } catch {
            errorMessage = error.localizedDescription
            isCreating = false
        }
    }
}

// MARK: - Segmented Owner Control (.ck-seg: neutral raised capsule inside recessed track)

private struct OwnerSegmentedControl: View {
    @Binding var selection: KeyType
    let personalTitle: String
    let agentTitle: String
    let trackFill: Color
    let trackBorder: Color
    let selectedFill: Color
    let selectedBorder: Color

    var body: some View {
        HStack(spacing: 1) {
            segmentButton(title: personalTitle, value: .personal)
            segmentButton(title: agentTitle, value: .bot)
        }
        .padding(2)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(trackFill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(trackBorder, lineWidth: 0.5)
        )
        .fixedSize()
    }

    private func segmentButton(title: String, value: KeyType) -> some View {
        let isSelected = selection == value
        let segmentShape = RoundedRectangle(cornerRadius: 6, style: .continuous)
        return Button {
            selection = value
        } label: {
            Text(title)
                .font(.system(size: 12, weight: isSelected ? .semibold : .medium))
                .foregroundColor(isSelected ? .primary : DesignTokens.textSecondary)
                .padding(.horizontal, 12)
                .frame(height: 24)
                .background(
                    segmentShape.fill(isSelected ? selectedFill : Color.clear)
                )
                .overlay(
                    segmentShape.strokeBorder(
                        isSelected ? selectedBorder : Color.clear,
                        lineWidth: 0.5
                    )
                )
                .shadow(
                    color: isSelected ? Color.black.opacity(0.14) : .clear,
                    radius: 1.5,
                    x: 0,
                    y: 1
                )
                .contentShape(segmentShape)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
    }
}

// MARK: - Single reference popover ("?" footer button)

struct CreateKeyReferencePopover: View {
    let onClose: () -> Void

    private static let popoverBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.157, green: 0.157, blue: 0.169, alpha: 1)
            : NSColor(calibratedRed: 1, green: 1, blue: 1, alpha: 1)
    })

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                Text(CreateKeyReferenceContent.title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.primary)
                Spacer(minLength: 8)
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundColor(DesignTokens.textSecondary)
                        .frame(width: 20, height: 20)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Close")
            }

            VStack(spacing: 0) {
                ForEach(Array(CreateKeyReferenceContent.rows.enumerated()), id: \.offset) { index, row in
                    if index > 0 {
                        Divider()
                    }
                    HStack(alignment: .top, spacing: 8) {
                        Text(row.label)
                            .font(.system(size: 11.5, weight: .semibold))
                            .foregroundColor(.primary)
                            .frame(width: 108, alignment: .leading)
                        Text(row.detail)
                            .font(.system(size: 11.5))
                            .foregroundColor(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 5)
                }
            }
        }
        .padding(EdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 16))
        .frame(width: 360, alignment: .leading)
        .background(Self.popoverBackground)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("About key options")
    }
}
