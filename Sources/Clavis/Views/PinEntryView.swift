import SwiftUI
import LocalAuthentication
import ClavisCore

@MainActor
public struct PinEntryView: View {
    @ObservedObject var lock: PanelLockController
    var isInlineBanner: Bool
    var onUnlockSuccess: ((LAContext?) -> Void)?

    @State private var pin: String = ""
    @State private var isPinVisible: Bool = false
    @State private var outcome: PinUnlockService.Outcome?
    @State private var waitRemaining: Int = 0
    @State private var waitTimer: Timer?
    @State private var isSubmitting: Bool = false

    /// Returns a bullet-masked representation of the given PIN.
    public static func maskPIN(_ pin: String) -> String {
        String(repeating: "•", count: pin.count)
    }

    /// Bullet-masked string of the currently entered PIN digits.
    public var maskedPin: String {
        Self.maskPIN(pin)
    }

    public init(
        isInlineBanner: Bool = false,
        onUnlockSuccess: ((LAContext?) -> Void)? = nil
    ) {
        self.init(lock: .shared, isInlineBanner: isInlineBanner, onUnlockSuccess: onUnlockSuccess)
    }

    public init(
        lock: PanelLockController,
        isInlineBanner: Bool = false,
        onUnlockSuccess: ((LAContext?) -> Void)? = nil
    ) {
        self.lock = lock
        self.isInlineBanner = isInlineBanner
        self.onUnlockSuccess = onUnlockSuccess
    }

    public var body: some View {
        VStack(spacing: isInlineBanner ? 8 : 10) {
            if isInlineBanner {
                HStack(spacing: 8) {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(.accentColor)
                    Text(ClavisUIStrings.PinUnlock.historyBanner)
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }
            }

            if isInlineBanner {
                HStack(spacing: 8) {
                    pinInputField
                        .frame(maxWidth: 180)
                    unlockButton
                    if lock.currentMode == .biometryOrPIN {
                        touchIdButton
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text(ClavisUIStrings.PinUnlock.pinLabel)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(DesignTokens.textSecondary)
                    pinInputField
                }
                .frame(maxWidth: .infinity)

                unlockButton
                    .frame(maxWidth: .infinity)

                if lock.currentMode == .biometryOrPIN {
                    touchIdButton
                        .frame(maxWidth: .infinity)
                }
            }

            if waitRemaining > 0 {
                Text(ClavisUIStrings.PinUnlock.waitFormat(waitRemaining))
                    .font(.system(size: 11))
                    .foregroundColor(.orange)
            } else if outcome == .wrongPIN {
                Text(ClavisUIStrings.PinUnlock.wrongPIN)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            } else if outcome == .passwordRequired {
                Text(ClavisUIStrings.PinUnlock.passwordRequired)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            }

            if !isInlineBanner {
                Button(action: submitPassword) {
                    Text(ClavisUIStrings.PinUnlock.usePassword)
                        .font(.system(size: 11))
                        .foregroundColor(.accentColor)
                }
                .buttonStyle(.link)
                .disabled(isSubmitting)
                .padding(.top, 2)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(isInlineBanner ? ClavisUIStrings.PinUnlock.historyBanner : ClavisUIStrings.PinUnlock.pinLabel)
        .onDisappear {
            waitTimer?.invalidate()
            waitTimer = nil
        }
    }

    @ViewBuilder
    private var pinInputField: some View {
        HStack(spacing: 6) {
            Group {
                if isPinVisible {
                    TextField(ClavisUIStrings.PinUnlock.pinPlaceholder, text: $pin)
                } else {
                    SecureField(ClavisUIStrings.PinUnlock.pinPlaceholder, text: $pin)
                }
            }
            .textFieldStyle(.plain)
            .font(.system(size: 12))
            .disabled(waitRemaining > 0 || isSubmitting)
            .accessibilityLabel(ClavisUIStrings.PinUnlock.pinLabel)
            .accessibilityValue(maskedPin)
            .onSubmit {
                submitPIN()
            }

            Button(action: { isPinVisible.toggle() }) {
                Image(systemName: isPinVisible ? "eye.slash" : "eye")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(DesignTokens.textSecondary)
                    .frame(width: 24, height: 24)
            }
            .buttonStyle(.plain)
            .help(isPinVisible ? "Hide PIN" : "Show PIN")
            .accessibilityLabel(isPinVisible ? "Hide PIN" : "Show PIN")
        }
        .padding(.horizontal, 10)
        .frame(height: 34)
        .liquidGlassControl(cornerRadius: 9)
    }

    private var unlockButton: some View {
        Button(action: submitPIN) {
            HStack(spacing: 6) {
                if isSubmitting {
                    ProgressView()
                        .controlSize(.small)
                }
                Text(ClavisUIStrings.PinUnlock.unlock)
                    .frame(maxWidth: isInlineBanner ? nil : .infinity)
            }
        }
        .liquidGlassButton(prominent: true)
        .controlSize(.large)
        .keyboardShortcut(.defaultAction)
        .disabled(pin.count < 6 || waitRemaining > 0 || isSubmitting)
    }

    private var touchIdButton: some View {
        Button(action: submitTouchID) {
            HStack(spacing: 6) {
                Image(systemName: "touchid")
                Text("Unlock with Touch ID")
                    .frame(maxWidth: isInlineBanner ? nil : .infinity)
            }
        }
        .liquidGlassButton(prominent: false)
        .controlSize(.large)
        .disabled(isSubmitting)
    }

    private func submitPIN() {
        guard pin.count >= 6, waitRemaining == 0, !isSubmitting else { return }
        ClavisLogger.promptDebug("calvis-ui", "PinEntryView: user submitted PIN")
        isSubmitting = true
        let enteredPIN = pin
        Task {
            let res = await lock.unlockWithPIN(enteredPIN)
            isSubmitting = false
            handleOutcome(res)
        }
    }

    private func submitTouchID() {
        guard !isSubmitting else { return }
        ClavisLogger.promptDebug("calvis-ui", "PinEntryView: user submitted Touch ID unlock")
        isSubmitting = true
        Task {
            let res = await lock.unlockWithPIN(nil)
            isSubmitting = false
            handleOutcome(res)
        }
    }

    private func submitPassword() {
        guard !isSubmitting else { return }
        ClavisLogger.promptDebug("calvis-ui", "PinEntryView: user submitted device password unlock")
        isSubmitting = true
        Task {
            let res = await lock.unlockWithPassword()
            isSubmitting = false
            handleOutcome(res)
        }
    }

    private func handleOutcome(_ res: PinUnlockService.Outcome) {
        outcome = res
        switch res {
        case .unlocked:
            pin = ""
            waitRemaining = 0
            waitTimer?.invalidate()
            waitTimer = nil
            onUnlockSuccess?(lock.unlockContext)
        case .wait(let seconds):
            startWaitTimer(seconds: Int(ceil(seconds)))
        case .wrongPIN, .passwordRequired, .cancelled:
            break
        }
    }

    private func startWaitTimer(seconds: Int) {
        waitRemaining = max(1, seconds)
        waitTimer?.invalidate()
        waitTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { timer in
            Task { @MainActor in
                if self.waitRemaining > 1 {
                    self.waitRemaining -= 1
                } else {
                    self.waitRemaining = 0
                    self.outcome = nil
                    timer.invalidate()
                    self.waitTimer = nil
                }
            }
        }
    }
}
