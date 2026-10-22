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

struct ConnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        await VPNController.shared.load()
        await VPNController.shared.connect()
        return .result()
    }
}

struct DisconnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        await VPNController.shared.load()
        await VPNController.shared.disconnect()
        return .result()
    }
}

struct ToggleVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle NYU VPN"
    // Require Face ID / passcode when run from the lock screen or Siri on a locked phone.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication
    func perform() async throws -> some IntentResult {
        await VPNController.shared.toggle()
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
