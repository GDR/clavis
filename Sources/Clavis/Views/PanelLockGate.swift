import SwiftUI
import ClavisCore

@MainActor
public struct LockedPlaceholderView: View {
    @ObservedObject var lock: PanelLockController

    public init() {
        self.init(lock: .shared)
    }

    public init(lock: PanelLockController) {
        self.lock = lock
    }

    public var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text(ClavisUIStrings.PanelLock.title)
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(.primary)

            if lock.currentMode.requiresPIN {
                PinEntryView(lock: lock)
            } else {
                Button(action: {
                    Task {
                        await lock.unlock()
                    }
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.open.fill")
                        Text(ClavisUIStrings.PanelLock.unlock)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .disabled(lock.isUnlocking)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            if !lock.currentMode.requiresPIN {
                await lock.unlock()
            }
        }
    }
}

@MainActor
public struct PanelLockGate<Content: View>: View {
    @ObservedObject var lock: PanelLockController
    private let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.init(lock: .shared, content: content)
    }

    public init(
        lock: PanelLockController,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.lock = lock
        self.content = content
    }

    public var body: some View {
        if lock.isLocked {
            LockedPlaceholderView(lock: lock)
        } else {
            content()
        }
    }
}
