import XCTest

/// The saved session as the builds before `candidate` declared it.
private struct SessionBeforeCandidate: Codable {
    let server, user, url, cookie: String
    let dnsName, ip: String?
}

final class SavedSessionTests: XCTestCase {
    private let accepted = "openconnect_strapkey=QUNDRVBURUQ=; webvpn=SESSION"
    private let newer = "openconnect_strapkey=TkVXRVI=; webvpn=SESSION"

    private func session(candidate: String?) -> SavedSession {
        SavedSession(server: "vpn.example.edu", user: "abc123", url: "https://vpn.example.edu/",
                     cookie: accepted, dnsName: "vpn.example.edu", ip: "192.0.2.1", candidate: candidate)
    }

    // MARK: The Keychain format

    /// What a build before `candidate` saved, through its own encoder.
    func testReadsWhatTheBuildBeforeSaved() throws {
        let before = SessionBeforeCandidate(server: "vpn.example.edu", user: "abc123", url: "https://vpn.example.edu/",
                                            cookie: accepted, dnsName: "vpn.example.edu", ip: "192.0.2.1")
        let json = String(decoding: try JSONEncoder().encode(before), as: UTF8.self)
        XCTAssertEqual(SavedSession(json: json), session(candidate: nil))
    }

    /// The same, as it reads in the Keychain.
    func testReadsSessionSavedWithoutCandidate() throws {
        let json = #"{"server":"vpn.example.edu","user":"abc123","url":"https:\/\/vpn.example.edu\/","#
            + #""cookie":"openconnect_strapkey=QUNDRVBURUQ=; webvpn=SESSION","dnsName":"vpn.example.edu","ip":"192.0.2.1"}"#
        let saved = try XCTUnwrap(SavedSession(json: json))
        XCTAssertEqual(saved, session(candidate: nil))
        XCTAssertNil(saved.candidate)
    }

    /// As the first builds wrote it, before the server's name and address were kept.
    func testReadsSessionSavedWithoutAddress() throws {
        let json = #"{"server":"vpn.example.edu","user":"abc123","url":"https://vpn.example.edu/","cookie":"webvpn=SESSION"}"#
        let saved = try XCTUnwrap(SavedSession(json: json))
        XCTAssertEqual(saved.cookie, "webvpn=SESSION")
        XCTAssertNil(saved.dnsName)
        XCTAssertNil(saved.ip)
        XCTAssertNil(saved.candidate)
    }

    func testRoundTripWithCandidate() throws {
        let saved = session(candidate: newer)
        let json = try XCTUnwrap(saved.json)
        XCTAssertEqual(SavedSession(json: json), saved)
        XCTAssertEqual(SavedSession(json: json)?.candidate, newer)
    }

    func testRoundTripWithoutCandidate() throws {
        let saved = session(candidate: nil)
        let json = try XCTUnwrap(saved.json)
        XCTAssertEqual(SavedSession(json: json), saved)
        XCTAssertFalse(json.contains("candidate"), "no key is written for no candidate")
    }

    /// A build from before `candidate` (after a downgrade) reads what this one saved,
    /// and rejoins with the accepted cookie.
    func testOlderBuildReadsNewFormat() throws {
        let json = try XCTUnwrap(session(candidate: newer).json)
        let old = try JSONDecoder().decode(SessionBeforeCandidate.self, from: Data(json.utf8))
        XCTAssertEqual(old.cookie, accepted)
        XCTAssertEqual(old.url, "https://vpn.example.edu/")
        XCTAssertEqual(old.dnsName, "vpn.example.edu")
        XCTAssertEqual(old.ip, "192.0.2.1")
    }

    func testUnreadableIsNoSession() {
        XCTAssertNil(SavedSession(json: ""))
        XCTAssertNil(SavedSession(json: "not json"))
        XCTAssertNil(SavedSession(json: #"{"server":"vpn.example.edu","user":"abc123"}"#), "no address or cookie")
    }

    // MARK: Rejoining

    private enum Answer { case joined, sessionEnded, unreachable }

    /// Rejoins `saved` against a server that gives these answers in turn. Returns the
    /// result and the cookies presented.
    private func rejoin(_ saved: SavedSession, answers: [Answer]) -> (result: Answer, presented: [String]) {
        var presented: [String] = []
        var candidates: [Bool] = []
        let result = saved.rejoin(refused: { $0 == .sessionEnded }) { cookie, isCandidate -> Answer in
            presented.append(cookie)
            candidates.append(isCandidate)
            return answers[presented.count - 1]
        }
        XCTAssertEqual(candidates, Array([false, true].prefix(presented.count)), "the cookie first, then the candidate")
        return (result, presented)
    }

    func testAcceptedCookieJoins() {
        let (result, presented) = rejoin(session(candidate: newer), answers: [.joined])
        XCTAssertEqual(result, .joined)
        XCTAssertEqual(presented, [accepted], "the candidate isn't tried when the cookie works")
    }

    func testRefusedCookieThenCandidateJoins() {
        let (result, presented) = rejoin(session(candidate: newer), answers: [.sessionEnded, .joined])
        XCTAssertEqual(result, .joined)
        XCTAssertEqual(presented, [accepted, newer])
    }

    /// Both refused: the session has ended, after exactly one try of each.
    func testRefusedCookieAndCandidateEndTheSession() {
        let (result, presented) = rejoin(session(candidate: newer), answers: [.sessionEnded, .sessionEnded, .joined])
        XCTAssertEqual(result, .sessionEnded)
        XCTAssertEqual(presented, [accepted, newer], "the candidate is tried once, and nothing after it")
    }

    /// As before there were candidates: one refusal ends the session.
    func testRefusedCookieWithoutCandidateEndsTheSession() {
        for none in [nil, "", accepted] {
            let (result, presented) = rejoin(session(candidate: none), answers: [.sessionEnded, .joined])
            XCTAssertEqual(result, .sessionEnded, "candidate \(none ?? "nil")")
            XCTAssertEqual(presented, [accepted], "candidate \(none ?? "nil")")
        }
    }

    /// Not reaching the server says nothing about the cookie: the candidate waits.
    func testUnreachableDoesNotTryTheCandidate() {
        let (result, presented) = rejoin(session(candidate: newer), answers: [.unreachable, .joined])
        XCTAssertEqual(result, .unreachable)
        XCTAssertEqual(presented, [accepted])
    }

    /// The cookie was refused, but the candidate got no answer: not the session's end,
    /// so the session is kept and the next rejoin tries both again.
    func testUnreachableCandidateDoesNotEndTheSession() {
        let (result, presented) = rejoin(session(candidate: newer), answers: [.sessionEnded, .unreachable])
        XCTAssertEqual(result, .unreachable)
        XCTAssertEqual(presented, [accepted, newer])
    }
}
