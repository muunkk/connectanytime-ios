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

    /// On while connected or on the way there (e.g. waiting for Duo). Not for an
    /// automatic attempt with no session to rejoin, which can only fail, so a tap
    /// takes over and logs in instead of turning it off.
    static func isOn() async -> Bool {
        guard let m = await manager() else { return false }
        if isHopelessAutoAttempt(m) { return false }
        return [.connected, .connecting, .reasserting].contains(m.connection.status)
    }

    /// iOS's automatic attempt (manual logins save on-demand off first) with no saved
    /// session: it can only fail with "tap Connect to log in".
    static func isHopelessAutoAttempt(_ m: NETunnelProviderManager) -> Bool {
        m.connection.status == .connecting && m.isOnDemandEnabled && !SavedSessionItem.exists
    }

    static func set(_ on: Bool) async throws {
        guard let m = await manager(), m.protocolConfiguration != nil else { throw NotSetUp() }
        let c = m.connection
        logger.log("Control set \(on ? "on" : "off", privacy: .public); status \(describe(c.status), privacy: .public)")
        defer { reloadControl() }
        ConnectIntent.set(disconnected: !on)
        if on {
            // Our own login is already waiting for Duo (on-demand is off for those), or
            // iOS's automatic attempt is rejoining a session: leave it be. Stopping it would
            // mean a second push, or log out a session that's still there.
            if c.status == .connecting, !m.isOnDemandEnabled || SavedSessionItem.exists {
                await wait(c, whileIn: [.connecting], upTo: 90)
                return await armIfConnected(m)
            }
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
            guard !ConnectIntent.disconnected else { return } // turned off meanwhile
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
        guard mayArm(m.connection.status), !m.isOnDemandEnabled,
              !(m.onDemandRules ?? []).isEmpty, !ConnectIntent.disconnected else { return }
        m.isOnDemandEnabled = true
        guard (try? await m.saveToPreferences()) != nil else { return }
        // The app and Control Center run in different processes. If the other one
        // disconnected meanwhile, or a new login started, don't leave it on. (Rolling
        // back saves the configuration, so a login started in the same instant could
        // see one save mid-connect; that takes a tap within a moment of this one.)
        // Not just because the VPN dropped meanwhile: with a session to rejoin, that's
        // when it's needed, to bring it back. A new login only runs without one.
        let status = m.connection.status
        let newLogin = [.connecting, .disconnected, .invalid].contains(status) && !SavedSessionItem.exists
        if ConnectIntent.disconnected || newLogin {
            logger.log("Disconnected while turning auto-connect on; turning it off again")
            try? await m.loadFromPreferences()
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
    }

    /// Whether Stay Connected may be turned on in `status`: connected, or reconnecting a
    /// session it has (e.g. a Connect that came up on the last settings while the server
    /// can't be reached). Not while connecting: a login may be waiting for Duo.
    static func mayArm(_ status: NEVPNStatus) -> Bool {
        status == .connected || status == .reasserting && SavedSessionItem.exists
    }

    /// Lets an attempt already under way (iOS's automatic one) finish, for up to 10 s,
    /// then stops it. Call with on-demand saved off, so iOS doesn't start another, and
    /// never during a login of our own. Returns the status it ends in.
    /// Returns early after a Disconnect, which then does the stopping.
    static func settle(_ c: NEVPNConnection) async -> NEVPNStatus {
        await wait(c, whileIn: [.connecting], upTo: 10, untilDisconnected: true)
        if ConnectIntent.disconnected { return c.status }
        if c.status == .connecting { c.stopVPNTunnel() }
        await wait(c, whileIn: [.connecting, .disconnecting], upTo: 5)
        return c.status
    }

    /// Waits up to `seconds` while the connection is in one of `states`. Control Center
    /// re-reads the toggle as soon as the action returns, so waiting briefly for the new
    /// state keeps it from snapping back to the old one.
    /// `untilDisconnected`: also stop waiting once you've turned the VPN off.
    static func wait(_ c: NEVPNConnection, whileIn states: Set<NEVPNStatus>, upTo seconds: TimeInterval = 2,
                     untilDisconnected: Bool = false) async {
        let deadline = Date().addingTimeInterval(seconds)
        while states.contains(c.status), Date() < deadline, !(untilDisconnected && ConnectIntent.disconnected) {
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
