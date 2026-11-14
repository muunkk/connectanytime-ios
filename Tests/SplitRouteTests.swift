import XCTest

final class SplitRouteTests: XCTestCase {
    func testPrefixMasks() {
        let masks = [
            (0, "0.0.0.0"),
            (1, "128.0.0.0"),
            (8, "255.0.0.0"),
            (24, "255.255.255.0"),
            (31, "255.255.255.254"),
            (32, "255.255.255.255"),
        ]
        for (prefix, mask) in masks {
            let route = SplitRoute.ipv4("10.0.0.0/\(prefix)")
            XCTAssertEqual(route?.address, "10.0.0.0", "prefix \(prefix)")
            XCTAssertEqual(route?.mask, mask, "prefix \(prefix)")
        }
    }

    func testDottedMaskPassesThrough() {
        let route = SplitRoute.ipv4("10.0.0.0/255.0.0.0")
        XCTAssertEqual(route?.address, "10.0.0.0")
        XCTAssertEqual(route?.mask, "255.0.0.0")
    }

    func testRejectedRoutes() {
        for route in ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/nope",
                      "10.0.0.0", "10.0.0.0/8/24", "", "2001:db8::/32"] {
            XCTAssertNil(SplitRoute.ipv4(route), route)
        }
    }

    func testEmptyPartsAreOmitted() {
        let route = SplitRoute.ipv4("/10.0.0.0//8/")
        XCTAssertEqual(route?.address, "10.0.0.0")
        XCTAssertEqual(route?.mask, "255.0.0.0")
    }

    func testDottedMaskIsNotValidated() {
        let route = SplitRoute.ipv4("10.0.0.0/not.a.mask")
        XCTAssertEqual(route?.address, "10.0.0.0")
        XCTAssertEqual(route?.mask, "not.a.mask")
    }
}
