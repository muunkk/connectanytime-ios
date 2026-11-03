import Foundation
import NetworkExtension
import os
import WidgetKit

/// Connect/disconnect using the VPN configuration the app already saved.
/// Used by the Control Center toggle, which runs outside the app.
enum VPNQuickControl {
    private static let logger = Logger(subsystem: "com.muunkk.connectanytime", category: "control")

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
        let c = m.connection
        logger.log("Control set \(on ? "on" : "off", privacy: .public); status \(describe(c.status), privacy: .public)")
        defer { reloadControl() }
        if on {
            // iOS disables this configuration whenever another VPN is used. The app's
            // Connect re-enables it on every save; the toggle has to as well.
            if !m.isEnabled {
                m.isEnabled = true
                try await save(m, "re-enable the VPN")
            }
            // A start sent while the last session is still shutting down is ignored.
            await wait(c, whileIn: [.disconnecting])
            do {
                try (c as? NETunnelProviderSession)?
                    .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
            } catch {
                logger.error("Couldn't start the VPN: \(error.localizedDescription, privacy: .public)")
                throw error
            }
            // Re-arm auto-connect only after starting, matching the app's Connect button.
            // Re-arming first can make iOS start an automatic attempt that swallows this
            // manual one. Best effort: the VPN is already connecting.
            if !(m.onDemandRules ?? []).isEmpty, !m.isOnDemandEnabled {
                m.isOnDemandEnabled = true
                try? await save(m, "re-arm auto-connect")
            }
            await wait(c, whileIn: [.disconnected, .invalid])
        } else {
            // Pause auto-connect so iOS doesn't reconnect straight away. Best effort:
            // stopping matters more.
            if m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                try? await save(m, "pause auto-connect")
            }
            c.stopVPNTunnel()
            await wait(c, whileIn: [.connected, .connecting, .reasserting])
        }
    }

    private static func save(_ m: NETunnelProviderManager, _ what: String) async throws {
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
        } catch {
            logger.error("Couldn't \(what, privacy: .public): \(error.localizedDescription, privacy: .public)")
            try? await m.loadFromPreferences() // drop the unsaved change
            throw error
        }
    }

    /// Control Center re-reads the toggle as soon as the action returns. Wait briefly
    /// for the new state so it doesn't snap back to the old one.
    private static func wait(_ c: NEVPNConnection, whileIn states: Set<NEVPNStatus>) async {
        let deadline = Date().addingTimeInterval(2)
        while states.contains(c.status), Date() < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    private static func describe(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: "invalid"
        case .disconnected: "disconnected"
        case .connecting: "connecting"
        case .connected: "connected"
        case .reasserting: "reasserting"
        case .disconnecting: "disconnecting"
        @unknown default: "\(status.rawValue)"
        }
    }

    /// Ask Control Center to re-read the toggle's state.
    static func reloadControl() {
        ControlCenter.shared.reloadControls(ofKind: AppConfig.controlKind)
    }
}
