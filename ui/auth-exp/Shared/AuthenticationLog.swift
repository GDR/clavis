import Foundation
import AppKit
import LocalAuthentication
import Security

// MARK: - Structured Authentication & Security Telemetry Log

public enum AuthLogCategory: String, CaseIterable, Sendable {
    case keygen      = "KEYGEN"
    case auth        = "AUTH"
    case sepSign     = "SEP_SIGN"
    case bypassTest  = "BYPASS_TEST"
    case reuseTest   = "REUSE_TEST"
    case concurrency = "CONCURRENCY"
    case ipcAgent    = "IPC_AGENT"
    case lifecycle   = "LIFECYCLE"
    case keychain    = "KEYCHAIN"
}

public enum AuthLogOutcome: String, Sendable {
    case success      = "SUCCESS"
    case denied       = "DENIED"
    case error        = "ERROR"
    case securityPass = "SECURITY_PASS"
    case securityFail = "SECURITY_FAIL"
    case info         = "INFO"
}

public struct AuthLogEntry: Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let category: AuthLogCategory
    public let outcome: AuthLogOutcome
    public let title: String
    public let details: String
    public let elapsedMs: Double?
    public let errorBreakdown: String?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        category: AuthLogCategory,
        outcome: AuthLogOutcome,
        title: String,
        details: String,
        elapsedMs: Double? = nil,
        errorBreakdown: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.category = category
        self.outcome = outcome
        self.title = title
        self.details = details
        self.elapsedMs = elapsedMs
        self.errorBreakdown = errorBreakdown
    }
}

// MARK: - Error Code Decoder (LocalAuthentication + Security + CryptoTokenKit/SEP)

public enum AuthErrorInspector {
    public static func describe(_ error: Error) -> String {
        let nsError = error as NSError
        var parts: [String] = []
        parts.append("domain=\(nsError.domain) code=\(nsError.code)")

        if nsError.domain == LAErrorDomain, let laCode = LAError.Code(rawValue: nsError.code) {
            parts.append("LAError=\(symbolicLAErrorName(laCode))")
        } else if nsError.domain == NSOSStatusErrorDomain {
            let status = OSStatus(nsError.code)
            if let secMsg = SecCopyErrorMessageString(status, nil) as String? {
                parts.append("OSStatus=\(symbolicOSStatusName(status)) (\"\(secMsg)\")")
            } else {
                parts.append("OSStatus=\(symbolicOSStatusName(status))")
            }
        }

        if let aksErr = nsError.userInfo["AKSError"] {
            parts.append("AKSError=\(aksErr) (SEP AppleKeyStore hardware rejection)")
        }
        if let debugDesc = nsError.userInfo[NSDebugDescriptionErrorKey] as? String,
           debugDesc != nsError.localizedDescription {
            parts.append("debug=\"\(debugDesc)\"")
        }
        parts.append("msg=\"\(nsError.localizedDescription)\"")

        if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? Error {
            parts.append("underlying=[\(describe(underlying))]")
        }
        return parts.joined(separator: " | ")
    }

    public static func symbolicLAErrorName(_ code: LAError.Code) -> String {
        switch code {
        case .authenticationFailed: return ".authenticationFailed (-1)"
        case .userCancel:           return ".userCancel (-2)"
        case .userFallback:         return ".userFallback (-3)"
        case .systemCancel:         return ".systemCancel (-4)"
        case .passcodeNotSet:       return ".passcodeNotSet (-5)"
        case .biometryNotAvailable: return ".biometryNotAvailable (-6)"
        case .biometryNotEnrolled:  return ".biometryNotEnrolled (-7)"
        case .biometryLockout:      return ".biometryLockout (-8)"
        case .appCancel:            return ".appCancel (-9)"
        case .invalidContext:       return ".invalidContext (-10)"
        case .notInteractive:       return ".notInteractive / interactionNotAllowed (-1004)"
        case .watchNotAvailable:    return ".companionNotAvailable (-11)"
        case .biometryNotPaired:    return ".biometryNotPaired (-12)"
        case .biometryDisconnected: return ".biometryDisconnected (-13)"
        case .invalidDimensions:    return ".invalidDimensions (-14)"
        @unknown default:           return "unknown(\(code.rawValue))"
        }
    }

    public static func symbolicOSStatusName(_ status: OSStatus) -> String {
        switch status {
        case errSecSuccess:               return "errSecSuccess (0)"
        case errSecUserCanceled:          return "errSecUserCanceled (-128)"
        case errSecAuthFailed:            return "errSecAuthFailed (-25293)"
        case errSecItemNotFound:          return "errSecItemNotFound (-25300)"
        case errSecInteractionNotAllowed: return "errSecInteractionNotAllowed (-25308)"
        case errSecMissingEntitlement:    return "errSecMissingEntitlement (-34018)"
        default:                          return "\(status)"
        }
    }
}

// MARK: - Observable Log Store + Screen Lock Lifecycle Monitor

@MainActor
public final class AuthenticationLog: ObservableObject {
    @Published public private(set) var entries: [AuthLogEntry] = []
    @Published public private(set) var screenLockCount: Int = 0
    @Published public private(set) var screenUnlockCount: Int = 0
    @Published public private(set) var lastLockStateChange: String = "Unlocked (initial)"

    private var lockObserver: NSObjectProtocol?
    private var unlockObserver: NSObjectProtocol?
    private let onScreenLockedCallback: (@MainActor () -> Void)?

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()

    public init(onScreenLocked: (@MainActor () -> Void)? = nil) {
        self.onScreenLockedCallback = onScreenLocked
        installScreenLockObservers()
    }

    deinit {
        let dnc = DistributedNotificationCenter.default()
        if let lockObserver { dnc.removeObserver(lockObserver) }
        if let unlockObserver { dnc.removeObserver(unlockObserver) }
    }

    private func installScreenLockObservers() {
        let dnc = DistributedNotificationCenter.default()
        lockObserver = dnc.addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.screenLockCount += 1
                self.lastLockStateChange = "Locked at \(Self.formatTimestamp(Date()))"
                self.record(
                    category: .lifecycle,
                    outcome: .info,
                    title: "macOS Screen Locked (com.apple.screenIsLocked)",
                    details: "Lock count=\(self.screenLockCount). Test signing with cached LAContext after unlock to check SEP session revocation."
                )
                self.onScreenLockedCallback?()
            }
        }

        unlockObserver = dnc.addObserver(
            forName: NSNotification.Name("com.apple.screenIsUnlocked"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.screenUnlockCount += 1
                self.lastLockStateChange = "Unlocked at \(Self.formatTimestamp(Date()))"
                self.record(
                    category: .lifecycle,
                    outcome: .info,
                    title: "macOS Screen Unlocked (com.apple.screenIsUnlocked)",
                    details: "Unlock count=\(self.screenUnlockCount). Ready to test post-unlock LAContext reuse vs fresh prompt."
                )
            }
        }
    }

    public func record(
        category: AuthLogCategory,
        outcome: AuthLogOutcome,
        title: String,
        details: String,
        elapsedMs: Double? = nil,
        error: Error? = nil
    ) {
        let breakdown = error.map { AuthErrorInspector.describe($0) }
        let entry = AuthLogEntry(
            category: category,
            outcome: outcome,
            title: title,
            details: details,
            elapsedMs: elapsedMs,
            errorBreakdown: breakdown
        )
        entries.insert(entry, at: 0)
    }

    public func clear() {
        entries.removeAll()
    }

    public static func formatTimestamp(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    public func copyMarkdownReport(experimentTitle: String) {
        var lines: [String] = []
        lines.append("# Clavis Auth Lab Report — \(experimentTitle)")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("Screen Lock/Unlock Events: locked=\(screenLockCount), unlocked=\(screenUnlockCount)")
        lines.append("")
        lines.append("| Time | Category | Outcome | Latency | Event | Details / Error |")
        lines.append("| --- | --- | --- | --- | --- | --- |")

        for entry in entries.reversed() {
            let time = Self.formatTimestamp(entry.timestamp)
            let latency = entry.elapsedMs.map { String(format: "%.1f ms", $0) } ?? "—"
            let errSuffix = entry.errorBreakdown.map { " (`\($0)`)" } ?? ""
            let detailText = (entry.details + errSuffix).replacingOccurrences(of: "\n", with: " ")
            lines.append("| `\(time)` | `\(entry.category.rawValue)` | **\(entry.outcome.rawValue)** | \(latency) | \(entry.title) | \(detailText) |")
        }

        let markdown = lines.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(markdown, forType: .string)
    }
}
