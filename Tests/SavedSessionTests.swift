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

/// The store that keeps the saved session: what a Disconnect's logout and the saves from
/// the tunnel's threads do to one another.
final class SessionStoreTests: XCTestCase {
    /// The Keychain item, in memory, noting every write and delete in order.
    private final class Item {
        private let lock = NSLock()
        private var stored: String?
        private var events: [String] = []
        var failWrites = false
        /// Runs in the middle of a write, before the value is stored.
        var duringWrite: (() -> Void)?

        var value: String? { lock.withLock { stored } }
        var log: [String] { lock.withLock { events } }

        func write(_ value: String) -> Bool {
            duringWrite?()
            return lock.withLock {
                events.append(failWrites ? "write failed" : "write")
                if !failWrites { stored = value }
                return !failWrites
            }
        }

        func delete() {
            lock.withLock {
                events.append("delete")
                stored = nil
            }
        }
    }

    private func store(_ item: Item) -> SessionStore {
        SessionStore(read: { item.value }, write: item.write, delete: item.delete)
    }

    private func session(_ key: String, candidate: String? = nil) -> SavedSession {
        SavedSession(server: "vpn.example.edu", user: "abc123", url: "https://vpn.example.edu/",
                     cookie: "openconnect_strapkey=\(key); webvpn=SESSION", dnsName: "vpn.example.edu",
                     ip: "192.0.2.1", candidate: candidate.map { "openconnect_strapkey=\($0); webvpn=SESSION" })
    }

    func testSavesAndLoads() {
        let item = Item(), store = store(item)
        XCTAssertNil(store.load())
        XCTAssertEqual(store.save { self.session("A") }, .written)
        XCTAssertEqual(store.load(), session("A"))
        XCTAssertEqual(store.save { self.session("A", candidate: "B") }, .written)
        XCTAssertEqual(store.load(), session("A", candidate: "B"))
    }

    /// The same session, from the queue after OpenConnect's thread saved it: not written again.
    func testUnchangedSessionIsWrittenOnce() {
        let item = Item(), store = store(item)
        XCTAssertEqual(store.save { self.session("A") }, .written)
        XCTAssertEqual(store.save { self.session("A") }, .unchanged)
        XCTAssertEqual(item.log, ["write"])
    }

    func testNoSessionSavesNothing() {
        let item = Item(), store = store(item)
        XCTAssertEqual(store.save { nil }, .nothing)
        XCTAssertEqual(item.log, [])
    }

    /// Once the server has ended a session it's forgotten, and the next login's is saved,
    /// even one that reads the same.
    func testClearForgetsWhatWasWritten() {
        let item = Item(), store = store(item)
        store.save { self.session("A") }
        store.clear()
        XCTAssertNil(store.load())
        XCTAssertEqual(store.save { self.session("A") }, .written)
        XCTAssertEqual(store.load(), session("A"))
    }

    /// A write the Keychain refuses keeps what was there, is reported once, and the next
    /// save tries again.
    func testFailedWriteIsReportedOnceAndTriedAgain() {
        let item = Item(), store = store(item)
        store.save { self.session("A") }
        item.failWrites = true
        XCTAssertEqual(store.save { self.session("B") }, .failed(first: true))
        XCTAssertEqual(store.save { self.session("B") }, .failed(first: false))
        XCTAssertEqual(store.load(), session("A"))
        item.failWrites = false
        XCTAssertEqual(store.save { self.session("B") }, .written)
        XCTAssertEqual(store.load(), session("B"))
        item.failWrites = true
        XCTAssertEqual(store.save { self.session("C") }, .failed(first: true), "a new run of failures is reported again")
    }

    // MARK: Disconnect

    func testLogOutDeletesTheSession() {
        let item = Item(), store = store(item)
        store.save { self.session("A") }
        store.logOut()
        XCTAssertNil(item.value)
        XCTAssertNil(store.load())
    }

    /// After a Disconnect nothing is saved: not a reconnect's new key, not the end of the
    /// run, and the session isn't even read.
    func testNothingIsSavedAfterLogOut() {
        let item = Item(), store = store(item)
        store.save { self.session("A") }
        store.logOut()
        var read = false
        let saved = store.save {
            read = true
            return self.session("B")
        }
        XCTAssertEqual(saved, .loggedOut)
        XCTAssertFalse(read)
        XCTAssertNil(item.value)
        XCTAssertEqual(item.log, ["write", "delete"])
    }

    /// The interleaving that used to leave the session behind: a save has passed its
    /// logged-out check and is writing when the Disconnect comes. The Disconnect has to
    /// wait for that write and delete what it wrote, before it returns (and stopTunnel
    /// completes, after which iOS may end the process).
    func testLogOutWaitsForASaveUnderWayAndDeletesWhatItWrote() {
        let item = Item(), store = store(item)
        let writing = DispatchSemaphore(value: 0), finishWrite = DispatchSemaphore(value: 0)
        let saveDone = DispatchSemaphore(value: 0), logOutDone = DispatchSemaphore(value: 0)
        item.duringWrite = {
            writing.signal()
            finishWrite.wait()
        }
        var saved: SessionStore.Saved?
        Thread {
            saved = store.save { self.session("B") } // as OpenConnect's thread, before a CONNECT
            saveDone.signal()
        }.start()
        writing.wait() // past the check, in the middle of the Keychain write

        Thread {
            store.logOut() // as stopTunnel
            logOutDone.signal()
        }.start()
        XCTAssertEqual(logOutDone.wait(timeout: .now() + 0.5), .timedOut,
                       "the logout mustn't return while a save is still writing")
        XCTAssertNil(item.value, "nothing stored yet")

        finishWrite.signal()
        XCTAssertEqual(logOutDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(saveDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(saved, .written)
        XCTAssertEqual(item.log, ["write", "delete"], "the delete comes after the write")
        XCTAssertNil(item.value, "nothing survives the Disconnect")
        XCTAssertEqual(store.save { self.session("C") }, .loggedOut)
        XCTAssertNil(item.value)
    }

    /// The other way round: the Disconnect is deleting when a save arrives. It finds the
    /// session logged out and writes nothing.
    func testASaveThatArrivesDuringLogOutWritesNothing() {
        let item = Item()
        let deleting = DispatchSemaphore(value: 0), finishDelete = DispatchSemaphore(value: 0)
        let store = SessionStore(read: { item.value }, write: item.write, delete: {
            deleting.signal()
            finishDelete.wait()
            item.delete()
        })
        store.save { self.session("A") }
        let logOutDone = DispatchSemaphore(value: 0), saveDone = DispatchSemaphore(value: 0)
        Thread {
            store.logOut()
            logOutDone.signal()
        }.start()
        deleting.wait()
        var saved: SessionStore.Saved?
        Thread {
            saved = store.save { self.session("B") }
            saveDone.signal()
        }.start()
        XCTAssertEqual(saveDone.wait(timeout: .now() + 0.5), .timedOut, "the save waits for the logout")
        finishDelete.signal()
        XCTAssertEqual(logOutDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(saveDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(saved, .loggedOut)
        XCTAssertEqual(item.log, ["write", "delete"])
        XCTAssertNil(item.value)
    }

    // MARK: Two threads saving

    /// The tunnel's queue and OpenConnect's thread both save. Each reads the session
    /// inside the store, so whichever writes last read last: an older session never
    /// replaces a newer one.
    func testALaterSaveNeverLeavesAnOlderSession() {
        let item = Item(), store = store(item)
        let lock = NSLock()
        var current = session("A") // what OpenConnect holds: ocb_session_saved
        let writing = DispatchSemaphore(value: 0), finishWrite = DispatchSemaphore(value: 0)
        let firstDone = DispatchSemaphore(value: 0), secondDone = DispatchSemaphore(value: 0)
        var first = true
        item.duringWrite = {
            guard lock.withLock({ defer { first = false }; return first }) else { return }
            writing.signal()
            finishWrite.wait()
        }
        Thread {
            store.save { lock.withLock { current } } // reads A, and is slow to write it
            firstDone.signal()
        }.start()
        writing.wait()
        lock.withLock { current = session("A", candidate: "B") } // a reconnect presents a new key
        Thread {
            store.save { lock.withLock { current } }
            secondDone.signal()
        }.start()
        XCTAssertEqual(secondDone.wait(timeout: .now() + 0.5), .timedOut, "the second save waits its turn")
        finishWrite.signal()
        XCTAssertEqual(firstDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(secondDone.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(store.load(), session("A", candidate: "B"), "the newer session is the one left")
        XCTAssertEqual(item.log, ["write", "write"])
    }
}
