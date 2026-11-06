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
        ConnectIntent.set(disconnected: !on)
        if on {
            // iOS disables this configuration whenever another VPN is used. The app's
            // Connect re-enables it on every save; the toggle has to as well.
            // Auto-connect stays off while connecting: with it on, iOS can hold other
            // apps' traffic until the VPN is up, Duo's approval included. It's turned
            // back on below once the VPN is up, or by the app when it next sees it up.
            if !m.isEnabled || m.isOnDemandEnabled {
                m.isEnabled = true
                m.isOnDemandEnabled = false
                try await save(m, "prepare to connect")
            }
            // A start sent while another attempt is running or stopping is ignored.
            switch await settle(c) {
            case .connected, .reasserting: return await armIfConnected(m)
            case .disconnected, .invalid: break
            default: return logger.error("The last attempt is still stopping; not starting")
            }
            do {
                try (c as? NETunnelProviderSession)?
                    .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
            } catch {
                logger.error("Couldn't start the VPN: \(error.localizedDescription, privacy: .public)")
                throw error
            }
            await wait(c, whileIn: [.disconnected, .invalid])
            // Wait out the Duo approval, then turn Stay Connected on. If iOS ends this
            // action first, the app does it when it next sees the VPN up.
            await wait(c, whileIn: [.connecting], upTo: 90)
            await armIfConnected(m)
        } else {
            // Pause auto-connect so iOS doesn't reconnect straight away. Saved even if it
            // reads off, in case the app is turning it on right now. Best effort:
            // stopping matters more.
            m.isOnDemandEnabled = false
            try? await save(m, "pause auto-connect")
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

    /// Turns auto-connect (and so Stay Connected) back on once the VPN is up. Never
    /// while it's connecting: with on-demand on, iOS can hold other apps' traffic until
    /// the VPN is up, so Duo's approval would wait for the VPN that's waiting for it.
    /// Never after a Disconnect, from the app or Control Center, until the next connect.
    static func armIfConnected(_ m: NETunnelProviderManager) async {
        try? await m.loadFromPreferences()
        guard m.connection.status == .connected, !m.isOnDemandEnabled,
              !(m.onDemandRules ?? []).isEmpty, !ConnectIntent.disconnected else { return }
        m.isOnDemandEnabled = true
        guard (try? await m.saveToPreferences()) != nil else { return }
        // The app and Control Center run in different processes. If the other one
        // disconnected meanwhile, or a new login started, don't leave it on. (Rolling
        // back saves the configuration, so a login started in the same instant could
        // see one save mid-connect; that takes a tap within a moment of this one.)
        if ConnectIntent.disconnected || ![.connected, .reasserting].contains(m.connection.status) {
            logger.log("Disconnected while turning auto-connect on; turning it off again")
            try? await m.loadFromPreferences()
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
    }

    /// Lets an attempt already under way (iOS's automatic one) finish, for up to 10 s,
    /// then stops it. Call with on-demand saved off, so iOS doesn't start another, and
    /// never during a login of our own. Returns the status it ends in.
    static func settle(_ c: NEVPNConnection) async -> NEVPNStatus {
        await wait(c, whileIn: [.connecting], upTo: 10)
        if c.status == .connecting { c.stopVPNTunnel() }
        await wait(c, whileIn: [.connecting, .disconnecting], upTo: 5)
        return c.status
    }

    /// Waits up to `seconds` while the connection is in one of `states`. Control Center
    /// re-reads the toggle as soon as the action returns, so waiting briefly for the new
    /// state keeps it from snapping back to the old one.
    static func wait(_ c: NEVPNConnection, whileIn states: Set<NEVPNStatus>, upTo seconds: TimeInterval = 2) async {
        let deadline = Date().addingTimeInterval(seconds)
        while states.contains(c.status), Date() < deadline {
            do { try await Task.sleep(for: .milliseconds(100)) } catch { return } // cancelled
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
