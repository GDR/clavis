import SwiftUI
import LocalAuthentication
import ClavisCore

@MainActor
public struct PinEntryView: View {
    @ObservedObject var lock: PanelLockController
    var isInlineBanner: Bool
    var onUnlockSuccess: ((LAContext?) -> Void)?

    @State private var pin: String = ""
    @State private var outcome: PinUnlockService.Outcome?
    @State private var waitRemaining: Int = 0
    @State private var waitTimer: Timer?
    @State private var isSubmitting: Bool = false

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
        VStack(spacing: isInlineBanner ? 8 : 14) {
            if isInlineBanner {
                HStack(spacing: 8) {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(.accentColor)
                    Text(ClavisUIStrings.PinUnlock.historyBanner)
                        .font(.system(size: 13, weight: .medium))
                    Spacer()
                }
            }

            HStack(spacing: 8) {
                SecureField(ClavisUIStrings.PinUnlock.pinPlaceholder, text: $pin)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: isInlineBanner ? 160 : 200)
                    .disabled(waitRemaining > 0 || isSubmitting)
                    .onSubmit {
                        submitPIN()
                    }

                Button(action: submitPIN) {
                    HStack(spacing: 4) {
                        if isSubmitting {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "lock.open.fill")
                        }
                        Text(ClavisUIStrings.PinUnlock.unlock)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .disabled(pin.count < 6 || waitRemaining > 0 || isSubmitting)

                if lock.currentMode == .biometryOrPIN {
                    Button(action: submitTouchID) {
                        HStack(spacing: 4) {
                            Image(systemName: "touchid")
                            Text(ClavisUIStrings.PinUnlock.useTouchID)
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .disabled(isSubmitting)
                }
            }

            if waitRemaining > 0 {
                Text(ClavisUIStrings.PinUnlock.waitFormat(waitRemaining))
                    .font(.system(size: 12))
                    .foregroundColor(.orange)
            } else if outcome == .wrongPIN {
                Text(ClavisUIStrings.PinUnlock.wrongPIN)
                    .font(.system(size: 12))
                    .foregroundColor(.red)
            } else if outcome == .passwordRequired {
                Text(ClavisUIStrings.PinUnlock.passwordRequired)
                    .font(.system(size: 12))
                    .foregroundColor(.red)
            }

            if !isInlineBanner {
                Button(action: submitPassword) {
                    Text(ClavisUIStrings.PinUnlock.usePassword)
                        .font(.system(size: 12))
                        .foregroundColor(.accentColor)
                }
                .buttonStyle(.link)
                .disabled(isSubmitting)
            }
        }
        .onDisappear {
            waitTimer?.invalidate()
            waitTimer = nil
        }
    }

    private func submitPIN() {
        guard pin.count >= 6, waitRemaining == 0, !isSubmitting else { return }
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
        isSubmitting = true
        Task {
            let res = await lock.unlockWithPIN(nil)
            isSubmitting = false
            handleOutcome(res)
        }
    }

    private func submitPassword() {
        guard !isSubmitting else { return }
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
