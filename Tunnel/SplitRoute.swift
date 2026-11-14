import Foundation

/// Split routes sent by the server, before making the tunnel settings.
enum SplitRoute {
    /// "10.0.0.0/255.0.0.0" or "10.0.0.0/8" → the address and its dotted mask. IPv6 entries are skipped.
    static func ipv4(_ route: String) -> (address: String, mask: String)? {
        let parts = route.split(separator: "/").map(String.init)
        guard parts.count == 2, !parts[0].contains(":") else { return nil }
        if parts[1].contains(".") { return (parts[0], parts[1]) }
        guard let bits = Int(parts[1]), (0...32).contains(bits) else { return nil }
        let mask = bits == 0 ? 0 : UInt32.max << (32 - UInt32(bits))
        let dotted = [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xff) }.joined(separator: ".")
        return (parts[0], dotted)
    }
}
