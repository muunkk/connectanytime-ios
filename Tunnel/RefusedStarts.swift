import Foundation
import UserNotifications

/// A run of automatic starts refused for want of a session to rejoin (see startTunnel).
/// Stay Connected keeps starting the VPN, several times a second, and only the app can
/// turn that off; logging each start pushed everything before them out of the Activity
/// log. So the first is logged, with a notification that opens the app (which turns the
/// retries off), then a count every half hour, and the total once a start goes ahead.
/// Kept in the extension's defaults, since each start may be a new process.
enum RefusedStarts {
    private static let defaults = UserDefaults.standard
    private static let sinceKey = "refusedStartsSince"
    private static let countKey = "refusedStartsCount"
    private static let loggedKey = "refusedStartsLogged"
    private static let notificationID = "session-ended"
    private static let summaryEvery: TimeInterval = 30 * 60

    static func note(_ refusal: String, log: (String) -> Void) {
        let now = Date()
        let count = defaults.integer(forKey: countKey) + 1
        defaults.set(count, forKey: countKey)
        guard let since = defaults.object(forKey: sinceKey) as? Date else {
            defaults.set(now, forKey: sinceKey)
            defaults.set(now, forKey: loggedKey)
            log(AppConfig.buildDescription)
            log("Stay Connected started the VPN, but there's no session to rejoin. \(refusal)"
                + " Further automatic starts are counted, not logged, until one goes ahead.")
            ActivityLog.flush() // iOS ends this process right after
            notify(refusal)
            return
        }
        let logged = defaults.object(forKey: loggedKey) as? Date ?? since
        guard now.timeIntervalSince(logged) >= summaryEvery else { return }
        defaults.set(now, forKey: loggedKey)
        log("Still no session to rejoin: \(count) automatic starts refused since \(time(since))")
        ActivityLog.flush()
    }

    /// A start is going ahead: say how many were refused before it, if any.
    static func end(log: (String) -> Void) {
        guard let since = defaults.object(forKey: sinceKey) as? Date else { return }
        let count = defaults.integer(forKey: countKey)
        defaults.removeObject(forKey: sinceKey)
        defaults.removeObject(forKey: countKey)
        defaults.removeObject(forKey: loggedKey)
        log("\(count) automatic start\(count == 1 ? " was" : "s were") refused from \(time(since)) to \(time(Date())), with no session to rejoin")
    }

    static func clearNotification() {
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [notificationID])
    }

    private static func notify(_ refusal: String) {
        let content = UNMutableNotificationContent()
        content.title = "VPN session ended"
        content.body = refusal
        content.sound = .default
        let request = UNNotificationRequest(identifier: notificationID, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private static func time(_ date: Date) -> String {
        date.formatted(.dateTime.month(.twoDigits).day(.twoDigits).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
    }
}
