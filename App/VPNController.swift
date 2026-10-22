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
    @Published private(set) var hasPassword = SharedKeychain.hasPassword

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    private init() {
        netID = UserDefaults.standard.string(forKey: "netID") ?? ""
        server = UserDefaults.standard.string(forKey: "server") ?? AppConfig.defaultServer
        autoNetworks = UserDefaults.standard.stringArray(forKey: "autoNetworks") ?? []
    }

    var isConnected: Bool { status == .connected }
    var isBusy: Bool { [.connecting, .disconnecting, .reasserting].contains(status) }

    func load() async {
        guard manager == nil else { return }
        let existing = (try? await NETunnelProviderManager.loadAllFromPreferences())?.first
        manager = existing ?? NETunnelProviderManager()
        observeStatus()
    }

    // MARK: Actions

    func connect() async {
        lastError = nil
        guard !netID.trimmingCharacters(in: .whitespaces).isEmpty else { return lastError = "Enter your NetID first." }
        guard hasPassword else { return lastError = "Save your password first." }
        do {
            let m = try await savedManager(onDemand: !autoNetworks.isEmpty)
            try (m.connection as? NETunnelProviderSession)?
                .startTunnel(options: [AppConfig.manualStartKey: true as NSNumber])
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Also pauses auto-connect, otherwise iOS would reconnect right away on a
    /// saved network. The next Connect turns it back on.
    func disconnect() async {
        lastError = nil
        guard let m = manager else { return }
        if m.isOnDemandEnabled {
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
        m.connection.stopVPNTunnel()
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
        Task { await applyAutoNetworks() }
    }

    func removeAutoNetworks(at offsets: IndexSet) {
        autoNetworks.remove(atOffsets: offsets)
        Task { await applyAutoNetworks() }
    }

    /// The Wi-Fi network the phone is on now (needs the VPN configuration to exist).
    func currentWiFi() async -> String? {
        await withCheckedContinuation { cont in
            NEHotspotNetwork.fetchCurrent { cont.resume(returning: $0?.ssid) }
        }
    }

    // MARK: Configuration

    private func savedManager(onDemand: Bool) async throws -> NETunnelProviderManager {
        await load()
        let m = manager!
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleID
        proto.serverAddress = server.trimmingCharacters(in: .whitespaces)
        proto.username = netID.trimmingCharacters(in: .whitespaces)
        proto.disconnectOnSleep = false
        m.protocolConfiguration = proto
        m.localizedDescription = "NYU Shanghai VPN"
        m.isEnabled = true
        m.onDemandRules = onDemandRules()
        m.isOnDemandEnabled = onDemand
        try await m.saveToPreferences()
        try await m.loadFromPreferences() // required before starting a freshly saved config
        return m
    }

    private func applyAutoNetworks() async {
        guard let m = manager, m.protocolConfiguration != nil else { return }
        m.onDemandRules = onDemandRules()
        if autoNetworks.isEmpty { m.isOnDemandEnabled = false }
        try? await m.saveToPreferences()
    }

    /// Connect on saved Wi-Fi networks; leave the VPN alone everywhere else.
    private func onDemandRules() -> [NEOnDemandRule] {
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
