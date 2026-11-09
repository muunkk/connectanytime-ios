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
    static func read() -> String? { KeychainItem.read("nyu") }
    @discardableResult
    static func save(_ password: String) -> Bool { KeychainItem.save(password, as: "nyu") }
    static var hasPassword: Bool { read() != nil }
}

/// Whether you last turned the VPN off, from the app or Control Center. Until you
/// connect again, nothing turns auto-connect back on. Shared so the app can't undo a
/// Control Center Disconnect (or the reverse); in the Keychain because there's no
/// shared app group.
enum ConnectIntent {
    static var disconnected: Bool { KeychainItem.read("disconnected") != nil }
    static func set(disconnected: Bool) {
        guard disconnected != self.disconnected else { return }
        if disconnected { KeychainItem.save("1", as: "disconnected") } else { KeychainItem.delete("disconnected") }
    }
}

/// The VPN session the tunnel can rejoin without logging in (written by the tunnel).
enum SavedSessionItem {
    static let account = "session"
    static var exists: Bool { KeychainItem.read(account) != nil }
}

/// Generic-password items in the Keychain group the app and its extensions share.
/// Readable after first unlock so auto-connect works with the phone locked.
enum KeychainItem {
    private static let service = "connectanytime"

    private static var accessGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "KeychainGroup") as? String ?? ""
    }

    private static func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
    }

    static func read(_ account: String) -> String? {
        var q = base(account)
        q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    /// Replaces the item in place, so a reader in another process never sees it missing
    /// (e.g. the app deciding there's no session to rejoin), and a failed write keeps
    /// the old value rather than losing it.
    @discardableResult
    static func save(_ value: String, as account: String) -> Bool {
        let data = Data(value.utf8)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updated = SecItemUpdate(base(account) as CFDictionary, attributes as CFDictionary)
        if updated == errSecSuccess { return true }
        guard updated == errSecItemNotFound else { return false }
        var add = base(account)
        add.merge(attributes) { $1 }
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    static func delete(_ account: String) {
        SecItemDelete(base(account) as CFDictionary)
    }

    /// Whether the Keychain can't be read yet because the iPhone hasn't been unlocked
    /// since it started (e.g. after an overnight update), as opposed to there being no
    /// such item. Items here are readable from the first unlock on.
    static func isLocked(_ account: String) -> Bool {
        var q = base(account)
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecInteractionNotAllowed
    }
}

/// The VPN's recent activity (connects, network changes, reconnects, and why it
/// stopped), written by the tunnel so the app can show why it dropped. In the Keychain
/// like the rest, since there's no shared app group. Holds OpenConnect's status lines
/// and our own, never the password or the session cookie.
enum ActivityLog {
    private static let account = "activity"
    private static let maxLines = 300
    private static let writes = DispatchQueue(label: "connectanytime.activity", qos: .utility)
    /// Lines not yet saved. Only touched on `writes`.
    nonisolated(unsafe) private static var pending: [String] = []

    /// Saved within a second, a burst of lines in one Keychain write.
    static func add(_ line: String) {
        let stamped = "\(Date().formatted(.dateTime.month(.twoDigits).day(.twoDigits).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))) \(line)"
        writes.async {
            pending.append(stamped)
            if pending.count == 1 { writes.asyncAfter(deadline: .now() + 1) { save() } }
        }
    }

    /// Saves now, e.g. before the tunnel stops.
    static func flush() { writes.sync { save() } }

    private static func save() {
        guard !pending.isEmpty else { return }
        let lines = read() + pending
        pending = []
        KeychainItem.save(lines.suffix(maxLines).joined(separator: "\n"), as: account)
    }

    static func read() -> [String] {
        (KeychainItem.read(account) ?? "").split(separator: "\n").map(String.init)
    }

    static func clear() { KeychainItem.delete(account) }
}
