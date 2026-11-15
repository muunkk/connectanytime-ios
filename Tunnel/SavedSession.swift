import Foundation

/// What rejoining the last session takes: the server's address after any redirects,
/// and its session cookie. In the Keychain, on this device only, since the cookie
/// works like a password until the session ends. Cleared on logout and once the
/// server ends the session.
struct SavedSession: Codable, Equatable {
    let server, user, url: String
    /// Carries the key the server last accepted for the session (OpenConnect's STRAP
    /// key). Every connection hands the server a new one, the first right after the
    /// login, so the session is saved again after each reconnect: the server refuses a
    /// cookie whose key it no longer holds.
    let cookie: String
    let dnsName, ip: String? // the server's name and the address the session is on
    /// The cookie with a newer key, which a reconnect presented without hearing back:
    /// the server holds one of the two. Nil when there's none, and in a session saved
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
