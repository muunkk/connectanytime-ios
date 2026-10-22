import Foundation
import Security

enum AppConfig {
    static let defaultServer = "vpn.shanghai.nyu.edu"
    static let tunnelBundleID = "com.muunkk.connectanytime.tunnel"
    /// Answer to Cisco's "Second Password" prompt; sends a Duo push.
    static let duoSecondPassword = "push"
    /// Start-tunnel option set by the app for user-initiated connects.
    static let manualStartKey = "manual"
    /// Control Center toggle identifier.
    static let controlKind = "com.muunkk.connectanytime.vpn"
}

/// The NetID password, shared between the app and the tunnel extension.
/// Readable after first unlock so auto-connect works with the phone locked.
enum SharedKeychain {
    private static let service = "connectanytime"
    private static let account = "nyu"

    private static var accessGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "KeychainGroup") as? String ?? ""
    }

    private static var base: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
    }

    static func read() -> String? {
        var q = base
        q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    @discardableResult
    static func save(_ password: String) -> Bool {
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(password.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    static var hasPassword: Bool { read() != nil }
}
