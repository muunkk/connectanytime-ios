import Network
import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.muunkk.connectanytime", category: "tunnel")
    private let queue = DispatchQueue(label: "connectanytime.tunnel")
    private var session: OpaquePointer?
    /// Guards freeing `session` against stopTunnel cancelling it. stopTunnel can't
    /// use `queue`: that's blocked while logging in (waiting for Duo).
    private let sessionLock = NSLock()
    private var stopping = false
    private var pathMonitor: NWPathMonitor?
    private var lastNetwork: String?
    private var watchdog: DispatchSourceTimer?
    private var reconnectDeadline: Date?
    private var lastReconnectKick = Date.distantPast
    /// Bumped whenever a reconnect starts, so the result of an earlier one (such as a
    /// slow settings update) can't mark a newer one as done or end it.
    private var reconnectEpoch = 0
    /// Tunnel settings: the last ones iOS confirmed, and the newest the server sent.
    private var installedKey: String?
    private var wanted: WantedSettings?
    private var applyingSettings = false

    private struct WantedSettings {
        let key: String
        let settings: NEPacketTunnelNetworkSettings
        let epoch: Int // the reconnect that produced them
    }
    private var pendingReconnect: DispatchWorkItem?
    private var server = ""
    /// Why the session ended, when it's our doing rather than OpenConnect's.
    private var endReason: String?

    /// After an auto-connect fails (e.g. Duo ignored), don't let iOS's on-demand
    /// retries keep sending Duo pushes. Manual connects are never blocked.
    private static let autoRetryPause: TimeInterval = 15 * 60
    private static let lastAutoFailureKey = "lastAutoFailure"

    /// How long to keep retrying a dropped connection with the existing session
    /// (no Duo) before giving up, e.g. while walking between Wi-Fi networks.
    /// The server may end the session sooner; then the next connect needs Duo.
    private static let resumeWindow: Int32 = 30 * 60

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Refresh the Control Center toggle whichever way this ends; otherwise it can
        // keep showing "Connected" after a failed or dropped connection. Before the
        // completion too: iOS may tear this process down right after a failure.
        let done: (Error?) -> Void = { error in
            VPNQuickControl.reloadControl()
            completionHandler(error)
            VPNQuickControl.reloadControl()
        }
        let manual = options?[AppConfig.manualStartKey] != nil
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let user = proto.username, !user.isEmpty else {
            return done(failure("Open ConnectAnytime and enter your NetID."))
        }
        guard let password = SharedKeychain.read() else {
            return done(failure("Open ConnectAnytime and save your password."))
        }
        if !manual, let last = UserDefaults.standard.object(forKey: Self.lastAutoFailureKey) as? Date,
           Date().timeIntervalSince(last) < Self.autoRetryPause {
            return done(failure("Auto-connect paused after a failed attempt. Tap Connect to try again."))
        }
        let server = proto.serverAddress ?? AppConfig.defaultServer
        self.server = server
        log("Connecting to \(server) (\(manual ? "manual" : "auto"))")

        queue.async {
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            guard let s = ocb_new(server, user, password, AppConfig.duoSecondPassword, { ctx, _, line in
                guard let ctx, let line else { return }
                Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue().log(String(cString: line))
            }, { ctx, event, cfg in
                guard let ctx else { return }
                let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
                // cfg is only valid during this call.
                let config = cfg.map { (String(cString: $0.pointee.key),
                                        PacketTunnelProvider.networkSettings($0.pointee, server: provider.server)) }
                provider.queue.async {
                    switch Int(event) {
                    case Int(OCB_ATTEMPT): provider.reconnecting(attempt: true)
                    case Int(OCB_RECONNECTED): provider.reconnected(config)
                    default: provider.reconnecting()
                    }
                }
            }, ctx) else {
                return done(self.failure("Couldn't start the VPN client."))
            }
            self.sessionLock.withLock { self.session = s }

            var err = [CChar](repeating: 0, count: 512)
            guard ocb_connect(s, &err, err.count) == 0 else {
                let message = self.stopping ? "Cancelled." : String(cString: err)
                self.finishSession()
                if !manual, !self.stopping { UserDefaults.standard.set(Date(), forKey: Self.lastAutoFailureKey) }
                return done(self.failure(message))
            }
            UserDefaults.standard.removeObject(forKey: Self.lastAutoFailureKey)

            var cfg = ocb_config()
            guard ocb_get_config(s, &cfg) == 0 else {
                self.finishSession()
                return done(self.failure("The server didn't send tunnel settings."))
            }
            let settings = Self.networkSettings(cfg, server: server)
            let key = String(cString: cfg.key)
            ocb_config_free(&cfg)

            self.setTunnelNetworkSettings(settings) { error in
                self.queue.async { if error == nil { self.installedKey = key } }
                if let error {
                    self.queue.async { self.finishSession() }
                    return done(self.failure("Couldn't apply VPN settings: \(error.localizedDescription)"))
                }
                let fd = ocb_find_utun_fd()
                guard fd >= 0 else {
                    self.queue.async { self.finishSession() }
                    return done(self.failure("Couldn't find the tunnel interface."))
                }
                self.log("Connected")
                done(nil)
                self.queue.async { self.watchNetwork() }

                Thread {
                    let result = ocb_run(s, fd, Self.resumeWindow) // blocks until cancelled or the session ends
                    self.queue.async {
                        let byServer = !self.stopping
                        let reason = self.endReason
                        self.finishSession()
                        guard byServer else { return }
                        let message = reason ?? (result == -EPERM
                            ? "Your VPN session expired. Connect again to log in."
                            : "The VPN session ended.")
                        VPNQuickControl.reloadControl()
                        self.cancelTunnelWithError(self.failure(message))
                        VPNQuickControl.reloadControl()
                    }
                }.start()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log("Stopping (reason \(reason.rawValue))")
        sessionLock.withLock {
            stopping = true
            if let s = session { ocb_cancel(s) }
        }
        completionHandler()
        VPNQuickControl.reloadControl()
    }

    // MARK: Helpers

    private func finishSession() {
        pathMonitor?.cancel()
        pathMonitor = nil
        lastNetwork = nil
        watchdog?.cancel()
        watchdog = nil
        reconnectDeadline = nil
        pendingReconnect?.cancel()
        pendingReconnect = nil
        endReason = nil
        installedKey = nil
        wanted = nil
        applyingSettings = false
        sessionLock.withLock {
            if let s = session { ocb_free(s) }
            session = nil
        }
    }

    /// On a network change, reconnect right away with the existing session
    /// instead of waiting for the old connection to time out. Like Cisco's
    /// client, this doesn't log in again, so there's no Duo push.
    private func watchNetwork() {
        guard session != nil, pathMonitor == nil else { return }
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback]) // skip our own tunnel
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.session != nil else { return }
            // The first interface is the one in use. Its name alone misses Wi-Fi → Wi-Fi
            // (both en0); the gateway differs.
            let network = path.status != .satisfied ? "offline"
                : ([path.availableInterfaces.first?.name ?? ""] + path.gateways.map { "\($0)" }.sorted()).joined(separator: ",")
            defer { self.lastNetwork = network }
            guard let last = self.lastNetwork, last != network else { return }
            self.reconnecting()
            guard network != "offline" else { return }
            // Path updates come in bursts (interface, then gateways); reconnect once,
            // after they settle. Each reconnect is a new tunnel on the server, so extra
            // ones only add churn.
            self.pendingReconnect?.cancel()
            let work = DispatchWorkItem { [weak self] in
                guard let self, self.session != nil else { return }
                self.log("Network changed; reconnecting with the existing session")
                self.kickReconnect()
            }
            self.pendingReconnect = work
            self.queue.asyncAfter(deadline: .now() + 2, execute: work)
        }
        pathMonitor = monitor
        monitor.start(queue: queue)

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in self?.checkReconnect() }
        timer.resume()
        watchdog = timer
    }

    /// `attempt`: OpenConnect is starting a connection attempt, so the watchdog
    /// shouldn't abort it for another minute.
    private func reconnecting(attempt: Bool = false) {
        reasserting = true
        reconnectEpoch += 1
        if reconnectDeadline == nil {
            reconnectDeadline = Date().addingTimeInterval(TimeInterval(Self.resumeWindow))
            lastReconnectKick = Date() // OpenConnect is already retrying
        }
        if attempt { lastReconnectKick = Date() }
    }

    /// OpenConnect is back up. The server may have assigned new tunnel settings,
    /// typically a new address because it hadn't yet noticed the old connection drop.
    /// The session is still valid, so apply them instead of ending it. Reconnecting
    /// is over once the tunnel has the newest settings.
    private func reconnected(_ config: (key: String, settings: NEPacketTunnelNetworkSettings)?) {
        guard session != nil else { return }
        if let config {
            wanted = WantedSettings(key: config.key, settings: config.settings, epoch: reconnectEpoch)
        } else if !applyingSettings {
            return finishReconnect(epoch: reconnectEpoch) // couldn't read settings; keep the current ones
        } else if let w = wanted {
            wanted = WantedSettings(key: w.key, settings: w.settings, epoch: reconnectEpoch)
        }
        if !applyingSettings { applyWantedSettings() }
    }

    private func applyWantedSettings() {
        guard session != nil, let want = wanted else { return }
        guard want.key != installedKey else {
            wanted = nil
            return finishReconnect(epoch: want.epoch)
        }
        log("Applying new tunnel settings from the server")
        applyingSettings = true
        setTunnelNetworkSettings(want.settings) { error in
            self.queue.async {
                guard let s = self.session else { return }
                self.applyingSettings = false
                if error == nil { self.installedKey = want.key }
                if let newer = self.wanted, newer.epoch != want.epoch || newer.key != want.key {
                    return self.applyWantedSettings() // the server sent newer settings meanwhile
                }
                self.wanted = nil
                guard want.epoch == self.reconnectEpoch else { return } // a newer reconnect will apply its own
                if let error {
                    self.endReason = "Couldn't apply new VPN settings: \(error.localizedDescription)"
                    self.log(self.endReason!)
                    ocb_cancel(s)
                } else {
                    self.finishReconnect(epoch: want.epoch)
                }
            }
        }
    }

    /// Clears "Reconnecting…" unless another reconnect has started since.
    private func finishReconnect(epoch: Int) {
        guard epoch == reconnectEpoch else { return }
        reasserting = false
        reconnectDeadline = nil
    }

    /// Drop the current connection and reconnect now with the existing session.
    private func kickReconnect() {
        guard let s = session else { return }
        lastReconnectKick = Date()
        reconnectEpoch += 1
        ocb_reconnect(s)
    }

    /// OpenConnect's retry timeout only counts its sleeps, and a connect or TLS
    /// handshake can hang with no timeout. While reconnecting, retry once nothing has
    /// happened for a minute (not sooner: that would abort an attempt in progress),
    /// and give up by the clock, so a full tunnel can't blackhole traffic for long.
    private func checkReconnect() {
        guard let s = session, let deadline = reconnectDeadline else { return }
        if Date() >= deadline {
            endReason = "Couldn't reconnect in \(Self.resumeWindow / 60) minutes. Connect again to log in."
            log("Couldn't reconnect in \(Self.resumeWindow / 60) minutes; ending the session")
            ocb_cancel(s)
        } else if Date().timeIntervalSince(lastReconnectKick) >= 60 {
            kickReconnect()
        }
    }

    private func failure(_ message: String) -> NSError {
        log("Failed: \(message)")
        return NSError(domain: "ConnectAnytime", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    /// OpenConnect's INFO-level messages and our own; never contains typed input.
    private func log(_ message: String) {
        logger.log("\(message, privacy: .public)")
    }

    private static func networkSettings(_ cfg: ocb_config, server: String) -> NEPacketTunnelNetworkSettings {
        func str(_ p: UnsafeMutablePointer<CChar>?) -> String? { p.map { String(cString: $0) } }
        func lines(_ p: UnsafeMutablePointer<CChar>?) -> [String] {
            (str(p) ?? "").split(separator: "\n").map(String.init)
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: str(cfg.gateway) ?? server)
        let includes = lines(cfg.split_includes)
        let tunnelAll = includes.isEmpty

        let v4 = NEIPv4Settings(addresses: [str(cfg.addr) ?? "0.0.0.0"], subnetMasks: [str(cfg.netmask) ?? "255.255.255.255"])
        v4.includedRoutes = tunnelAll ? [.default()] : includes.compactMap(ipv4Route)
        v4.excludedRoutes = lines(cfg.split_excludes).compactMap(ipv4Route)
        settings.ipv4Settings = v4

        if let a6 = str(cfg.addr6), let slash = a6.firstIndex(of: "/"), let len = Int(a6[a6.index(after: slash)...]) {
            let v6 = NEIPv6Settings(addresses: [String(a6[..<slash])], networkPrefixLengths: [NSNumber(value: len)])
            v6.includedRoutes = tunnelAll ? [.default()] : []
            settings.ipv6Settings = v6
        } else if tunnelAll {
            // No IPv6 on the VPN. Route IPv6 into the tunnel anyway so it's dropped,
            // as Cisco does ("Drop All Traffic"), instead of leaking around the VPN.
            let v6 = NEIPv6Settings(addresses: ["fd00:ca::1"], networkPrefixLengths: [128])
            v6.includedRoutes = [.default()]
            settings.ipv6Settings = v6
        }

        let dns = [cfg.dns.0, cfg.dns.1, cfg.dns.2].compactMap(str)
        if !dns.isEmpty {
            let d = NEDNSSettings(servers: dns)
            if let domain = str(cfg.domain) { d.searchDomains = domain.split(separator: " ").map(String.init) }
            let splitDNS = lines(cfg.split_dns)
            d.matchDomains = tunnelAll ? [""] : (splitDNS.isEmpty ? d.searchDomains : splitDNS)
            settings.dnsSettings = d
        }
        if cfg.mtu > 0 { settings.mtu = NSNumber(value: cfg.mtu) }
        return settings
    }

    /// "10.0.0.0/255.0.0.0" or "10.0.0.0/8" → route. IPv6 entries are skipped.
    private static func ipv4Route(_ route: String) -> NEIPv4Route? {
        let parts = route.split(separator: "/").map(String.init)
        guard parts.count == 2, !parts[0].contains(":") else { return nil }
        if parts[1].contains(".") { return NEIPv4Route(destinationAddress: parts[0], subnetMask: parts[1]) }
        guard let bits = Int(parts[1]), (0...32).contains(bits) else { return nil }
        let mask = bits == 0 ? 0 : UInt32.max << (32 - UInt32(bits))
        let dotted = [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xff) }.joined(separator: ".")
        return NEIPv4Route(destinationAddress: parts[0], subnetMask: dotted)
    }
}
