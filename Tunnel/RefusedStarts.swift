import Foundation
import UserNotifications

/// A run of automatic starts refused for want of a session to rejoin (see startTunnel).
/// Stay Connected keeps starting the VPN, several times a second, and only the app can
/// turn that off; logging each start pushed everything before them out of the Activity
/// log. So the first is logged, with a notification that opens the app (which turns the
/// retries off), then a count every half hour, and the total once a start goes ahead.
/// Kept in the extension's defaults, since each start may be a new process.
enum RefusedStarts {
    private static let sinceKey = "refusedStartsSince"
    private static let countKey = "refusedStartsCount"
    private static let loggedKey = "refusedStartsLogged"
    private static let lastKey = "refusedStartsLast"
    private static let notificationID = "session-ended"
    private static let summaryEvery: TimeInterval = 30 * 60

    /// What a refused start adds to the log: the first of a run, a count so far, or nothing.
    enum Entry: Equatable { case first, summary(count: Int, since: Date), nothing }

    /// Counts a refused start. The store and the clock are passed in so this can be tested.
    static func record(at now: Date, in defaults: UserDefaults) -> Entry {
        let count = defaults.integer(forKey: countKey) + 1
        defaults.set(count, forKey: countKey)
        defaults.set(now, forKey: lastKey)
        guard let since = defaults.object(forKey: sinceKey) as? Date else {
            defaults.set(now, forKey: sinceKey)
            defaults.set(now, forKey: loggedKey)
            return .first
        }
        let logged = defaults.object(forKey: loggedKey) as? Date ?? since
        guard now.timeIntervalSince(logged) >= summaryEvery else { return .nothing }
        defaults.set(now, forKey: loggedKey)
        return .summary(count: count, since: since)
    }

    /// Ends the run of refused starts, if there is one: how many, and when the first and
    /// the last were. Not when the next start goes ahead, which can be hours after they
    /// stopped (opening the app stops them; the next Connect may come much later).
    static func finish(at now: Date, in defaults: UserDefaults) -> (count: Int, since: Date, last: Date)? {
        guard let since = defaults.object(forKey: sinceKey) as? Date else { return nil }
        let count = defaults.integer(forKey: countKey)
        let last = defaults.object(forKey: lastKey) as? Date ?? now // a run counted by 0.1.2 (3)
        defaults.removeObject(forKey: sinceKey)
        defaults.removeObject(forKey: countKey)
        defaults.removeObject(forKey: loggedKey)
        defaults.removeObject(forKey: lastKey)
        return (count, since, last)
    }

    static func note(_ refusal: String, log: (String) -> Void) {
        switch record(at: Date(), in: .standard) {
        case .first:
            log(AppConfig.buildDescription)
            log("Stay Connected started the VPN, but there's no session to rejoin. \(refusal)"
                + " Further automatic starts are counted, not logged, until one goes ahead.")
            ActivityLog.flush() // iOS ends this process right after
            notify(refusal)
        case let .summary(count, since):
            log("Still no session to rejoin: \(count) automatic starts refused since \(time(since))")
            ActivityLog.flush()
        case .nothing:
            break
        }
    }

    /// A start is going ahead: say how many were refused before it, if any.
    static func end(log: (String) -> Void) {
        guard let (count, since, last) = finish(at: Date(), in: .standard) else { return }
        log("\(count) automatic start\(count == 1 ? " was" : "s were") refused from \(time(since)) to \(time(last)), with no session to rejoin")
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
        // iOS ends this process right after the refused start: wait until the request
        // has been handed over, or the notification may never appear.
        let added = DispatchSemaphore(value: 0)
        UNUserNotificationCenter.current().add(request) { _ in added.signal() }
        _ = added.wait(timeout: .now() + 1)
    }

    private static func time(_ date: Date) -> String {
        date.formatted(.dateTime.month(.twoDigits).day(.twoDigits).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits))
    }
}
