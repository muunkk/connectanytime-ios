import Foundation
import NetworkExtension
import SwiftUI
import UIKit

/// Owns the single VPN configuration and drives connect/disconnect.
@MainActor
final class VPNController: ObservableObject {
    static let shared = VPNController()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?
    @Published var netID: String { didSet { UserDefaults.standard.set(netID, forKey: "netID") } }
    @Published var server: String { didSet { UserDefaults.standard.set(server, forKey: "server") } }
    @Published private(set) var autoNetworks: [String] {
        didSet {
            UserDefaults.standard.set(autoNetworks, forKey: "autoNetworks")
        }
    }
    /// Like Cisco's Connect On Demand: after you connect, iOS keeps the VPN up on any
    /// network and starts it again if it drops.
    @Published var stayConnected: Bool {
        didSet {
            UserDefaults.standard.set(stayConnected, forKey: "stayConnected")
            inOrder { await self.applyOnDemand() }
            if stayConnected { armOnDemandIfConnected() } // already connected: keep it up from now
        }
    }
    @Published private(set) var hasPassword = SharedKeychain.hasPassword

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    /// The last configuration change queued by inOrder.
    private var lastQueued: Task<Void, Never>?
    /// New on-demand rules wait while the VPN is connecting: saving the configuration
    /// then can restart the attempt, which means another Duo push.
    private var rulesSavePending = false
    /// Bump when onDemandRules() changes, so existing installs pick up the new rules.
    private static let onDemandRulesVersion = 2

    private init() {
        netID = UserDefaults.standard.string(forKey: "netID") ?? ""
        server = UserDefaults.standard.string(forKey: "server") ?? AppConfig.defaultServer
        autoNetworks = UserDefaults.standard.stringArray(forKey: "autoNetworks") ?? []
        stayConnected = UserDefaults.standard.object(forKey: "stayConnected") as? Bool ?? true
    }

    var isConnected: Bool { status == .connected }
    var isBusy: Bool { [.connecting, .disconnecting, .reasserting].contains(status) }

    func load() async {
        guard manager == nil else { return }
        let existing = (try? await NETunnelProviderManager.loadAllFromPreferences())?.first
        manager = existing ?? NETunnelProviderManager()
        observeStatus()
        if existing != nil, UserDefaults.standard.integer(forKey: "onDemandRulesVersion") < Self.onDemandRulesVersion {
            inOrder { await self.applyOnDemand() } // records the version once saved
        }
        armOnDemandIfConnected() // e.g. connected from Control Center while the app wasn't running
        disarmIfNothingToRejoin()
    }

    /// Re-reads the VPN status, e.g. on returning from the Duo app.
    func refresh() {
        guard manager != nil else { return }
        statusChanged()
    }

    // MARK: Actions

    func connect() async {
        lastError = nil
        await load()
        guard !netID.trimmingCharacters(in: .whitespaces).isEmpty else { return lastError = "Enter your NetID first." }
        guard hasPassword else { return lastError = "Save your password first." }
        guard ![.connected, .reasserting].contains(status) else { return }
        ConnectIntent.set(disconnected: false)
        var started: NEVPNConnection?
        await inOrder {
            guard let m = self.manager else { return }
            guard await self.mayStartLogin(m) else { return }
            do {
                let m = try await self.savedManager() // saves on-demand off
                // iOS may have an automatic attempt under way (it can only rejoin); a start
                // sent while one is running or stopping is ignored.
                let settled = await VPNQuickControl.settle(m.connection)
                guard !ConnectIntent.disconnected else { return } // Disconnect tapped meanwhile
                switch settled {
                case .connected, .reasserting: return
                case .disconnected, .invalid: break
                default: return self.lastError = "The last attempt is still stopping. Tap Connect again in a moment."
                }
                // Auto-connect stays off until the VPN is up (see armOnDemandIfConnected).
                try (m.connection as? NETunnelProviderSession)?
                    .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
                // Until iOS reports the start, so a Connect queued behind this one sees it.
                await VPNQuickControl.wait(m.connection, whileIn: [.disconnected, .invalid])
                started = m.connection
            } catch {
                self.lastError = error.localizedDescription
            }
        }.value
        if let started { armWhenConnected(started) }
    }

    /// Turns Stay Connected on once this login is through. Approving Duo usually means
    /// leaving the app, for the Duo app or its notification, and iOS suspends the app
    /// soon after; it would then miss the VPN coming up, and Stay Connected would stay
    /// off until you next opened the app, so a drop meanwhile would leave the VPN off.
    /// Background time lets it see the login through (iOS allows about 30 s).
    private func armWhenConnected(_ c: NEVPNConnection) {
        let app = UIApplication.shared
        let task = BackgroundTask()
        task.id = app.beginBackgroundTask(withName: "Turn on Stay Connected") { task.end() }
        Task { @MainActor in
            await VPNQuickControl.wait(c, whileIn: [.connecting], upTo: 120)
            self.refresh() // arms if it's up (statusChanged)
            await self.lastQueued?.value
            task.end()
        }
    }

    /// A background task that ends once, whichever ends it first: the work or iOS.
    @MainActor
    private final class BackgroundTask {
        var id = UIBackgroundTaskIdentifier.invalid
        func end() {
            guard id != .invalid else { return }
            UIApplication.shared.endBackgroundTask(id)
            id = .invalid
        }
    }

    /// Whether Connect should go ahead. Not if the VPN is up, or our own login is
    /// waiting for Duo (say a Shortcut run twice): saving the configuration then could
    /// restart it. A manual login always saves on-demand off first, so connecting with
    /// it on is iOS's automatic attempt, which Connect takes over from.
    private func mayStartLogin(_ m: NETunnelProviderManager) async -> Bool {
        try? await m.loadFromPreferences()
        switch m.connection.status {
        case .connected, .reasserting: return false
        case .connecting: return m.isOnDemandEnabled
        default: return true
        }
    }

    /// With no session to rejoin, iOS's automatic attempts can only fail ("tap Connect
    /// to log in"), so turn them off, as Cisco's client stops once the session ends.
    /// Mostly for a phone updated from a build that left on-demand on: otherwise the
    /// button keeps flipping to Disconnect while iOS retries. Safe because on-demand is
    /// only turned on once connected, the session is saved before that, and our own
    /// logins run with on-demand off.
    private func disarmIfNothingToRejoin() {
        guard ![.connected, .reasserting].contains(status), let m = manager, !SavedSessionItem.exists else { return }
        inOrder {
            try? await m.loadFromPreferences()
            guard m.isOnDemandEnabled, ![.connected, .reasserting].contains(m.connection.status),
                  !SavedSessionItem.exists else { return }
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
    }

    /// Also pauses auto-connect and Stay Connected, otherwise iOS would reconnect
    /// right away. The next Connect turns them back on.
    func disconnect() async {
        lastError = nil
        guard let m = manager else { return }
        ConnectIntent.set(disconnected: true)
        await inOrder {
            try? await m.loadFromPreferences() // the Control Center toggle may have changed it
            m.isOnDemandEnabled = false // saved even if it reads off: another process may be arming it
            try? await m.saveToPreferences()
            m.connection.stopVPNTunnel()
        }.value
    }

    func toggle() async {
        await load()
        if isConnected || isBusy { await disconnect() } else { await connect() }
    }

    func savePassword(_ password: String) {
        guard !password.isEmpty else { return }
        hasPassword = SharedKeychain.save(password)
        if !hasPassword { lastError = "Couldn't save the password to the Keychain." }
    }

    func addAutoNetwork(_ ssid: String) {
        let name = ssid.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !autoNetworks.contains(name) else { return }
        autoNetworks.append(name)
        inOrder { await self.applyOnDemand() }
    }

    func removeAutoNetworks(at offsets: IndexSet) {
        autoNetworks.remove(atOffsets: offsets)
        inOrder { await self.applyOnDemand() }
    }

    /// The Wi-Fi network the phone is on now (needs the VPN configuration to exist).
    func currentWiFi() async -> String? {
        await withCheckedContinuation { cont in
            NEHotspotNetwork.fetchCurrent { cont.resume(returning: $0?.ssid) }
        }
    }

    // MARK: Configuration

    /// Saves the configuration with auto-connect off, for a manual start. Connect
    /// turns it back on once the VPN is up.
    private func savedManager() async throws -> NETunnelProviderManager {
        await load()
        let m = manager!
        try? await m.loadFromPreferences() // pick up changes from the toggle; fails if never saved
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleID
        proto.serverAddress = server.trimmingCharacters(in: .whitespaces)
        proto.username = netID.trimmingCharacters(in: .whitespaces)
        proto.disconnectOnSleep = false
        m.protocolConfiguration = proto
        m.localizedDescription = "NYU Shanghai VPN"
        m.isEnabled = true
        m.onDemandRules = onDemandRules()
        m.isOnDemandEnabled = false
        try await m.saveToPreferences()
        try await m.loadFromPreferences() // required before starting a freshly saved config
        return m
    }

    /// Runs `work` after every configuration change queued before it. Each one loads,
    /// edits and saves the shared manager, so two at once could undo each other, e.g.
    /// a settings save landing after Disconnect and turning on-demand back on.
    @discardableResult
    private func inOrder(_ work: @escaping @MainActor () async -> Void) -> Task<Void, Never> {
        let previous = lastQueued
        let task = Task { @MainActor in
            await previous?.value
            await work()
        }
        lastQueued = task
        return task
    }

    /// Saves the on-demand rules for the current settings. Returns whether it saved.
    /// Leaves on-demand as it is (off if there are no rules), so a settings change
    /// can't undo a Disconnect, including one from Control Center that's still saving.
    @discardableResult
    private func applyOnDemand() async -> Bool {
        guard let m = manager, m.protocolConfiguration != nil else { return false }
        try? await m.loadFromPreferences()
        if m.connection.status == .connecting {
            rulesSavePending = true // saved once it's done connecting (statusChanged)
            return false
        }
        let rules = onDemandRules()
        m.onDemandRules = rules
        if rules.isEmpty || ConnectIntent.disconnected { m.isOnDemandEnabled = false }
        let savedOn = m.isOnDemandEnabled
        do {
            try await m.saveToPreferences()
            UserDefaults.standard.set(Self.onDemandRulesVersion, forKey: "onDemandRulesVersion")
        } catch {
            return false
        }
        // Control Center may have disconnected since this loaded; don't undo it.
        if savedOn, ConnectIntent.disconnected {
            try? await m.loadFromPreferences()
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
        return true
    }

    /// Turns auto-connect (and so Stay Connected) back on once the VPN is up, however
    /// it was connected. Never while it's still connecting: with on-demand on, iOS
    /// can hold other apps' traffic until the VPN is up, Duo's approval included, and
    /// saving the configuration mid-connect can restart the attempt, which sends
    /// another push. Not after a Disconnect (app or Control Center) until the next
    /// connect, even if a late status update still says connected.
    private func armOnDemandIfConnected() {
        guard status == .connected, !ConnectIntent.disconnected, let m = manager else { return }
        inOrder { await VPNQuickControl.armIfConnected(m) }
    }

    /// Stay connected: keep the VPN up on every network, Wi-Fi or cellular.
    /// Otherwise connect on saved Wi-Fi networks and leave the VPN alone elsewhere.
    private func onDemandRules() -> [NEOnDemandRule] {
        if stayConnected { return [NEOnDemandRuleConnect()] } // matches any interface
        guard !autoNetworks.isEmpty else { return [] }
        let connect = NEOnDemandRuleConnect()
        connect.interfaceTypeMatch = .wiFi
        connect.ssidMatch = autoNetworks
        return [connect, NEOnDemandRuleIgnore()]
    }

    private func observeStatus() {
        guard let m = manager else { return }
        status = m.connection.status
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.statusChanged() }
        }
    }

    private func statusChanged() {
        guard let m = manager else { return }
        let old = status
        status = m.connection.status
        if status != .connecting, rulesSavePending {
            rulesSavePending = false
            inOrder { await self.applyOnDemand() }
        }
        if status == .connected { armOnDemandIfConnected() }
        if [.disconnected, .connecting].contains(status) { disarmIfNothingToRejoin() }
        VPNQuickControl.reloadControl()
        if status == .disconnected, old != .disconnected {
            m.connection.fetchLastDisconnectError { error in
                Task { @MainActor in
                    if let error, (error as NSError).domain != NEVPNConnectionErrorDomain || (error as NSError).code != 0 {
                        self.lastError = error.localizedDescription
                    }
                }
            }
        }
    }
}
