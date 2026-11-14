import AppIntents
import SwiftUI

@main
struct ConnectAnytimeApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(VPNController.shared)
        }
    }
}

// MARK: - Shortcuts, Siri, Action button

/// Why Connect didn't go ahead. Otherwise Siri and Shortcuts report success, and the
/// reason only shows in the app.
struct ConnectFailed: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct ConnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        if let refusal = await VPNController.shared.connect() { throw ConnectFailed(message: refusal) }
        return .result()
    }
}

struct DisconnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        await VPNController.shared.disconnect()
        return .result()
    }
}

struct ToggleVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        if let refusal = await VPNController.shared.toggle() { throw ConnectFailed(message: refusal) }
        return .result()
    }
}

struct ConnectAnytimeShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: ToggleVPNIntent(), phrases: ["Toggle \(.applicationName)"],
                    shortTitle: "Toggle VPN", systemImageName: "network")
        AppShortcut(intent: ConnectVPNIntent(), phrases: ["Connect \(.applicationName)"],
                    shortTitle: "Connect VPN", systemImageName: "network")
        AppShortcut(intent: DisconnectVPNIntent(), phrases: ["Disconnect \(.applicationName)"],
                    shortTitle: "Disconnect VPN", systemImageName: "network.slash")
    }
}
