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
    private var _stopping = false
    /// Whether that stop logs out of the server's session (see stopTunnel).
    private var _logOutOnStop = false
    /// Set by stopTunnel on iOS's thread, read on `queue`.
    private var stopping: Bool { sessionLock.withLock { _stopping } }
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
    /// We ended it without logging out, so the saved session stays for a rejoin.
    private var keepSessionOnEnd = false

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
        let server = proto.serverAddress ?? AppConfig.defaultServer
        self.server = server
        let saved = SessionStore.load().flatMap { $0.server == server && $0.user == user ? $0 : nil }
        log("Connecting to \(server) (\(manual ? "manual" : "auto")\(saved != nil ? ", rejoining session" : ""))")

        queue.async {
            var err = [CChar](repeating: 0, count: 512)
            var session: OpaquePointer?
            var rejoined: SavedSession?

            // Rejoin the session from the last login if the server still has it: no
            // password, no Duo. This is how Stay Connected comes back after iOS stops
            // the tunnel, e.g. with no network.
            if let saved {
                guard let s = self.newSession(server: server, user: user, password: "") else {
                    return done(self.failure(self.stopping ? "Cancelled." : "Couldn't start the VPN client."))
                }
                let result = ocb_resume(s, saved.url, saved.cookie, saved.dnsName, saved.ip, &err, err.count)
                if result == 0 {
                    session = s
                    rejoined = saved
                } else {
                    let message = String(cString: err)
                    self.finishSession()
                    if self.stopping { return done(self.failure("Cancelled.")) }
                    if result == OCB_SESSION_ENDED {
                        self.log("The server has ended the saved session")
                        SessionStore.clear()
                    } else if !manual {
                        // Keep the session: iOS tries again once there's a network.
                        return done(self.failure(message))
                    }
                }
            }

            if session == nil {
                if let refusal = Self.loginRefusal(manual: manual) { return done(self.failure(refusal)) }
                guard let password = SharedKeychain.read() else {
                    return done(self.failure("Open ConnectAnytime and save your password."))
                }
                guard let s = self.newSession(server: server, user: user, password: password) else {
                    return done(self.failure(self.stopping ? "Cancelled." : "Couldn't start the VPN client."))
                }
                guard ocb_connect(s, &err, err.count) == 0 else {
                    let message = self.stopping ? "Cancelled." : String(cString: err)
                    self.finishSession()
                    return done(self.failure(message))
                }
                session = s
            }
            guard let s = session else { return }
            // Settings from builds that paused auto-connect after failed logins.
            UserDefaults.standard.removeObject(forKey: "autoPausedUntil")
            UserDefaults.standard.removeObject(forKey: "autoFailures")
            if let url = ocb_session_url(s), let cookie = ocb_session_cookie(s) {
                SessionStore.save(.init(server: server, user: user,
                                        url: String(cString: url), cookie: String(cString: cookie),
                                        // A rejoin keeps the login's address: on an IPv6-only
                                        // network it would read as a translated one.
                                        dnsName: rejoined?.dnsName ?? ocb_session_dnsname(s).map { String(cString: $0) },
                                        ip: rejoined?.ip ?? ocb_session_ip(s).map { String(cString: $0) }))
            }
            // Stopped just as the login finished: don't bring the tunnel up, and don't keep
            // a session you just disconnected.
            if self.stopping {
                if self.sessionLock.withLock({ self._logOutOnStop }) { SessionStore.clear() }
                self.finishSession()
                return done(self.failure("Cancelled."))
            }

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
                        let keepSession = self.keepSessionOnEnd
                        self.finishSession()
                        guard byServer else { return }
                        // Ended by the server, or by us with a logout. Otherwise, e.g. no
                        // network for too long, the next start tries to rejoin and the server
                        // decides.
                        if (reason != nil && !keepSession) || result == -EPERM || result == -EPIPE {
                            SessionStore.clear()
                        }
                        let message = reason ?? (result == -EPERM
                            ? "Your VPN session expired. Connect again to log in."
                            : result == -EPIPE ? "The server ended the VPN session."
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
        // Log out when you disconnect. When iOS stops the tunnel on its own (no network,
        // sleep, an update), leave the server's session open, like Cisco's client, so
        // the next start rejoins it without Duo.
        let logOut = Self.endsSession(reason)
        log("Stopping (reason \(reason.rawValue)\(logOut ? "" : ", keeping the session"))")
        sessionLock.withLock {
            _stopping = true
            _logOutOnStop = logOut
            if let s = session { logOut ? ocb_cancel(s) : ocb_detach(s) }
        }
        if logOut { SessionStore.clear() }
        completionHandler()
        VPNQuickControl.reloadControl()
    }

    // MARK: Helpers

    /// A new OpenConnect session, set as the current one. Nil if creating it failed
    /// or the tunnel is already stopping.
    private func newSession(server: String, user: String, password: String) -> OpaquePointer? {
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
        }, ctx) else { return nil }
        // Checked under the lock stopTunnel takes, so a stop can't slip in between and
        // leave this session running, say waiting for Duo.
        let stopped = sessionLock.withLock {
            if !_stopping { session = s }
            return _stopping
        }
        if stopped { ocb_free(s) }
        return stopped ? nil : s
    }

    /// Why this start mustn't log in, or nil if it may. Logging in sends a Duo push, so
    /// like Cisco's client only a connect you asked for does it. An automatic one can't
    /// work anyway: while on-demand is starting the VPN, iOS holds other apps'
    /// connections, so Duo's approval would wait for the VPN that's waiting for it.
    private static func loginRefusal(manual: Bool) -> String? {
        // Turning the VPN on in iOS Settings looks the same as an automatic start (no
        // options), so it only rejoins too.
        manual ? nil : "The VPN session has ended. Tap Connect in ConnectAnytime to log in again."
    }

    /// Whether this stop is someone turning the VPN off, as opposed to iOS stopping it
    /// for now. Another VPN taking over (superceded) keeps the session, so it can be
    /// rejoined once that one is done.
    private static func endsSession(_ reason: NEProviderStopReason) -> Bool {
        switch reason {
        case .userInitiated, .userLogout, .userSwitch, .configurationDisabled, .configurationRemoved,
             .providerDisabled, .authenticationCanceled:
            true
        default:
            false
        }
    }

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
        keepSessionOnEnd = false
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
            lastReconnectKick = Date() // give the attempt underway, or about to be kicked, its minute
        }
        if attempt { lastReconnectKick = Date() }
    }

    /// OpenConnect is back up. The server may have assigned new tunnel settings,
    /// typically a new address because it hadn't yet noticed the old connection drop.
    /// The session is still valid, so apply them instead of ending it. Reconnecting
    /// is over once the tunnel has the newest settings.
    private func reconnected(_ config: (key: String, settings: NEPacketTunnelNetworkSettings)?) {
        guard session != nil else { return }
        lastReconnectKick = Date() // it's up: don't let the watchdog drop it while settings apply
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
    /// handshake can hang with no timeout. While reconnecting, retry a minute after
    /// the latest attempt started (not sooner: that would abort it), and give up by
    /// the clock, so a full tunnel can't blackhole traffic for long.
    private func checkReconnect() {
        guard let s = session, let deadline = reconnectDeadline else { return }
        if Date() >= deadline {
            endReason = "Couldn't reconnect in \(Self.resumeWindow / 60) minutes. Connect again to log in."
            log("Couldn't reconnect in \(Self.resumeWindow / 60) minutes; stopping")
            // Without logging out: if the server still has the session when there's a
            // network again, the next start rejoins it without Duo.
            keepSessionOnEnd = true
            ocb_detach(s)
        } else if Date().timeIntervalSince(lastReconnectKick) >= 60 {
            kickReconnect()
        }
    }

    /// What rejoining the last session takes: the server's address after any redirects,
    /// and its session cookie. In the Keychain, on this device only, since the cookie
    /// works like a password until the session ends. Cleared on logout and once the
    /// server ends the session.
    private struct SavedSession: Codable {
        let server, user, url, cookie: String
        let dnsName, ip: String? // the server's name and the address the session is on
    }

    private enum SessionStore {
        static func load() -> SavedSession? {
            KeychainItem.read(SavedSessionItem.account).flatMap { try? JSONDecoder().decode(SavedSession.self, from: Data($0.utf8)) }
        }
        static func save(_ session: SavedSession) {
            guard let data = try? JSONEncoder().encode(session) else { return }
            KeychainItem.save(String(decoding: data, as: UTF8.self), as: SavedSessionItem.account)
        }
        static func clear() { KeychainItem.delete(SavedSessionItem.account) }
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
