import XCTest

final class RefusedStartsTests: XCTestCase {
    private var suiteName: String!
    private var defaults: UserDefaults!
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    override func setUp() {
        super.setUp()
        suiteName = "RefusedStartsTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)!
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        defaults = nil
        suiteName = nil
        super.tearDown()
    }

    func testFirstRecord() {
        XCTAssertEqual(RefusedStarts.record(at: start, in: defaults), .first)
        XCTAssertEqual(defaults.integer(forKey: "refusedStartsCount"), 1)
        for key in ["refusedStartsSince", "refusedStartsLogged", "refusedStartsLast"] {
            XCTAssertEqual(defaults.object(forKey: key) as? Date, start, key)
        }
    }

    func testSummaryEveryHalfHour() {
        XCTAssertEqual(RefusedStarts.record(at: start, in: defaults), .first)
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(1799), in: defaults), .nothing)
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(1800), in: defaults),
                       .summary(count: 3, since: start))
        XCTAssertEqual(defaults.object(forKey: "refusedStartsLogged") as? Date, start.addingTimeInterval(1800))
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(3599), in: defaults), .nothing)
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(3601), in: defaults),
                       .summary(count: 5, since: start))
    }

    func testSummaryFallsBackToSince() {
        XCTAssertEqual(RefusedStarts.record(at: start, in: defaults), .first)
        defaults.removeObject(forKey: "refusedStartsLogged")
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(1799), in: defaults), .nothing)
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(1800), in: defaults),
                       .summary(count: 3, since: start))
    }

    func testFinishUsesLastRefusalAndClearsRun() throws {
        let last = start.addingTimeInterval(1900)
        XCTAssertEqual(RefusedStarts.record(at: start, in: defaults), .first)
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(1800), in: defaults),
                       .summary(count: 2, since: start))
        XCTAssertEqual(RefusedStarts.record(at: last, in: defaults), .nothing)
        let run = try XCTUnwrap(RefusedStarts.finish(at: start.addingTimeInterval(10_000), in: defaults))
        XCTAssertEqual(run.count, 3)
        XCTAssertEqual(run.since, start)
        XCTAssertEqual(run.last, last)
        for key in ["refusedStartsSince", "refusedStartsCount", "refusedStartsLogged", "refusedStartsLast"] {
            XCTAssertNil(defaults.object(forKey: key), key)
        }
        XCTAssertNil(RefusedStarts.finish(at: start.addingTimeInterval(10_001), in: defaults))
        XCTAssertEqual(RefusedStarts.record(at: start.addingTimeInterval(10_002), in: defaults), .first)
    }

    func testFinishWithoutRun() {
        XCTAssertNil(RefusedStarts.finish(at: start, in: defaults))
    }

    func testFinishOldRunFallsBackToNow() throws {
        defaults.set(start, forKey: "refusedStartsSince")
        defaults.set(4, forKey: "refusedStartsCount")
        defaults.set(start.addingTimeInterval(1800), forKey: "refusedStartsLogged")
        let now = start.addingTimeInterval(10_000)
        let run = try XCTUnwrap(RefusedStarts.finish(at: now, in: defaults))
        XCTAssertEqual(run.count, 4)
        XCTAssertEqual(run.since, start)
        XCTAssertEqual(run.last, now)
        for key in ["refusedStartsSince", "refusedStartsCount", "refusedStartsLogged", "refusedStartsLast"] {
            XCTAssertNil(defaults.object(forKey: key), key)
        }
    }
}
