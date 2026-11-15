import Foundation

/// What rejoining the last session takes: the server's address after any redirects,
/// and its session cookie. In the Keychain, on this device only, since the cookie
/// works like a password until the session ends. Cleared on logout and once the
/// server ends the session.
struct SavedSession: Codable, Equatable {
    let server, user, url: String
    /// Carries the key the server last accepted for the session (OpenConnect's STRAP
    /// key). Every connection hands the server a new one, the first right after the
    /// login, so the session is saved again in each reconnect: the server refuses a
    /// cookie whose key it no longer holds.
    let cookie: String
    let dnsName, ip: String? // the server's name and the address the session is on
    /// The cookie with a newer key, which a reconnect has presented and the server
    /// hasn't answered with a 200: it holds one of the two. Saved before that request
    /// goes out, since the extension may not live to see the answer; gone again once
    /// the 200 puts that key in `cookie`. Nil when there's none, and in a session saved
    /// before this field existed.
    let candidate: String?
}

extension SavedSession {
    /// As kept in the Keychain. Fields are only ever added, and optional, so each build
    /// reads what another saved: one without `candidate` simply ignores it.
    init?(json: String) {
        guard let session = try? JSONDecoder().decode(SavedSession.self, from: Data(json.utf8)) else { return nil }
        self = session
    }

    var json: String? {
        (try? JSONEncoder().encode(self)).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Rejoins the session. `attempt` presents one cookie to the server and returns what
    /// came of it; `refused` tells whether that was the server saying the session is
    /// over. The cookie goes first. Only if the server refuses it, and there's a
    /// candidate, that's tried, once: one more request, never a password or Duo. The
    /// result is the last attempt's, so a refused candidate reads like a refused cookie
    /// always has: the session has ended.
    func rejoin<Result>(refused: (Result) -> Bool,
                        attempt: (_ cookie: String, _ isCandidate: Bool) -> Result) -> Result {
        let first = attempt(cookie, false)
        guard refused(first), let candidate, !candidate.isEmpty, candidate != cookie else { return first }
        return attempt(candidate, true)
    }
}

/// Where the saved session is kept, and the only thing that writes or deletes it. Saves
/// come from two threads (the tunnel's queue, and OpenConnect's own just before it hands
/// the server a new key), and a Disconnect's logout from a third, so each is one step
/// under one lock:
/// - a save reads the session and writes it in the same step, so a later save can never
///   leave an older session in place of a newer one;
/// - once `logOut` returns, the session is gone and no save puts it back, including one
///   that was already under way. Nothing has to run after the tunnel has stopped.
/// The Keychain itself is passed in, so this can be tested without one.
final class SessionStore {
    enum Saved: Equatable {
        case written
        case unchanged  // what's there already
        case loggedOut  // after a Disconnect: nothing is kept
        case nothing    // no session to save
        /// The Keychain refused it. `first` is false while it keeps failing, so that's
        /// logged once.
        case failed(first: Bool)
    }

    private let lock = NSLock()
    private let read: () -> String?
    private let write: (String) -> Bool
    private let delete: () -> Void
    private var loggedOut = false
    private var written: SavedSession? // what the last save left there, to not write it again
    private var failing = false

    init(read: @escaping () -> String?, write: @escaping (String) -> Bool, delete: @escaping () -> Void) {
        self.read = read
        self.write = write
        self.delete = delete
    }

    func load() -> SavedSession? { read().flatMap(SavedSession.init(json:)) }

    /// Saves the session `current` returns, unless the session has been logged out.
    /// `current` runs under the lock: read the session there, not before.
    @discardableResult
    func save(_ current: () -> SavedSession?) -> Saved {
        lock.withLock {
            guard !loggedOut else { return .loggedOut }
            guard let session = current(), let json = session.json else { return .nothing }
            guard session != written else { return .unchanged }
            guard write(json) else {
                defer { failing = true }
                return .failed(first: !failing)
            }
            written = session
            failing = false
            return .written
        }
    }

    /// The session is over, or isn't this NetID's: forget it. A later one is saved as usual.
    func clear() {
        lock.withLock {
            written = nil
            delete()
        }
    }

    /// You disconnected: forget the session, and keep nothing from here on.
    func logOut() {
        lock.withLock {
            loggedOut = true
            written = nil
            delete()
        }
    }
}
