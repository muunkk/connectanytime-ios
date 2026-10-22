import Foundation
import NetworkExtension
import WidgetKit

/// Connect/disconnect using the VPN configuration the app already saved.
/// Used by the Control Center toggle, which runs outside the app.
enum VPNQuickControl {
    struct NotSetUp: LocalizedError {
        var errorDescription: String? { "Open ConnectAnytime to set up the VPN first." }
    }

    static func manager() async -> NETunnelProviderManager? {
        try? await NETunnelProviderManager.loadAllFromPreferences().first
    }

    /// On while connected or on the way there (e.g. waiting for Duo).
    static func isOn() async -> Bool {
        guard let m = await manager() else { return false }
        return [.connected, .connecting, .reasserting].contains(m.connection.status)
    }

    static func set(_ on: Bool) async throws {
        guard let m = await manager(), m.protocolConfiguration != nil else { throw NotSetUp() }
        if on {
            // Connecting re-arms auto-connect, matching the app's Connect button.
            if !(m.onDemandRules ?? []).isEmpty, !m.isOnDemandEnabled {
                m.isOnDemandEnabled = true
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            try (m.connection as? NETunnelProviderSession)?
                .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
        } else {
            // Pause auto-connect so iOS doesn't reconnect straight away.
            if m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                try await m.saveToPreferences()
            }
            m.connection.stopVPNTunnel()
        }
        reloadControl()
    }

    /// Ask Control Center to re-read the toggle's state.
    static func reloadControl() {
        ControlCenter.shared.reloadControls(ofKind: AppConfig.controlKind)
    }
}
