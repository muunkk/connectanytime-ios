import Foundation
import NetworkExtension
import SwiftUI

/// Owns the single VPN configuration and drives connect/disconnect.
@MainActor
final class VPNController: ObservableObject {
    static let shared = VPNController()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?
    @Published var netID: String { didSet { UserDefaults.standard.set(netID, forKey: "netID") } }
    @Published var server: String { didSet { UserDefaults.standard.set(server, forKey: "server") } }
    @Published private(set) var autoNetworks: [String] { didSet { UserDefaults.standard.set(autoNetworks, forKey: "autoNetworks") } }
    /// Like Cisco's Connect On Demand: after you connect, iOS keeps the VPN up on any
    /// network and starts it again if it drops.
    @Published var stayConnected: Bool {
        didSet {
            UserDefaults.standard.set(stayConnected, forKey: "stayConnected")
            inOrder { await self.applyOnDemand() }
        }
    }
    @Published private(set) var hasPassword = SharedKeychain.hasPassword

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    /// The last configuration change queued by inOrder.
    private var lastQueued: Task<Void, Never>?
    /// Set by Disconnect, cleared by Connect. A settings change made in between
    /// mustn't turn on-demand back on, even if the tunnel hasn't finished stopping.
    private var userDisconnected = false
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
            inOrder {
                // Only once saved, so a failed save is tried again next launch.
                if await self.applyOnDemand() {
                    UserDefaults.standard.set(Self.onDemandRulesVersion, forKey: "onDemandRulesVersion")
                }
            }
        }
    }

    // MARK: Actions

    func connect() async {
        lastError = nil
        await load()
        guard !netID.trimmingCharacters(in: .whitespaces).isEmpty else { return lastError = "Enter your NetID first." }
        guard hasPassword else { return lastError = "Save your password first." }
        userDisconnected = false
        await inOrder {
            do {
                let m = try await self.savedManager()
                try (m.connection as? NETunnelProviderSession)?
                    .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
                // Turn auto-connect back on only after starting, as the Control Center
                // toggle does. Turning it on first can make iOS start an automatic
                // attempt that takes the place of this one (and is refused while
                // auto-connect is paused). Best effort: the VPN is already connecting.
                if !(m.onDemandRules ?? []).isEmpty, !m.isOnDemandEnabled {
                    m.isOnDemandEnabled = true
                    try? await m.saveToPreferences()
                }
            } catch {
                self.lastError = error.localizedDescription
            }
        }.value
    }

    /// Also pauses auto-connect and Stay Connected, otherwise iOS would reconnect
    /// right away. The next Connect turns them back on.
    func disconnect() async {
        lastError = nil
        guard let m = manager else { return }
        userDisconnected = true
        await inOrder {
            try? await m.loadFromPreferences() // the Control Center toggle may have changed it
            if m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                try? await m.saveToPreferences()
            }
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

    /// Saves the configuration, leaving auto-connect as it is unless there are no
    /// rules to connect on.
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
        let rules = onDemandRules()
        m.onDemandRules = rules
        if rules.isEmpty { m.isOnDemandEnabled = false }
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
    @discardableResult
    private func applyOnDemand() async -> Bool {
        guard let m = manager, m.protocolConfiguration != nil else { return false }
        try? await m.loadFromPreferences()
        let rules = onDemandRules()
        m.onDemandRules = rules
        if rules.isEmpty {
            m.isOnDemandEnabled = false
        } else if stayConnected, !userDisconnected,
                  [.connected, .connecting, .reasserting].contains(m.connection.status) {
            m.isOnDemandEnabled = true // already connected: start keeping it up now
        }
        do {
            try await m.saveToPreferences()
            return true
        } catch {
            return false
        }
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
