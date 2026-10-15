import Foundation
import UserNotifications

/// UNUserNotificationCenterDelegate implementation ensuring notifications are presented
/// as foreground banners with sound even when Clavis is the active foreground application.
public final class ClavisNotificationCenterDelegate: NSObject, UNUserNotificationCenterDelegate, Sendable {
    public static let shared = ClavisNotificationCenterDelegate()

    public override init() {
        super.init()
    }

    public func foregroundPresentationOptions() -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Return banner and sound presentation options so notifications display
        // reliably even when Clavis is the foreground application.
        completionHandler(foregroundPresentationOptions())
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }
}
