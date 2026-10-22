import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.muunkk.connectanytime", category: "tunnel")
    private let queue = DispatchQueue(label: "connectanytime.tunnel")
    private var session: OpaquePointer?
    private var stopping = false

    /// After an auto-connect fails (e.g. Duo ignored), don't let iOS's on-demand
    /// retries keep sending Duo pushes. Manual connects are never blocked.
    private static let autoRetryPause: TimeInterval = 15 * 60
    private static let lastAutoFailureKey = "lastAutoFailure"

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let manual = options?[AppConfig.manualStartKey] != nil
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let user = proto.username, !user.isEmpty else {
            return completionHandler(failure("Open ConnectAnytime and enter your NetID."))
        }
        guard let password = SharedKeychain.read() else {
            return completionHandler(failure("Open ConnectAnytime and save your password."))
        }
        if !manual, let last = UserDefaults.standard.object(forKey: Self.lastAutoFailureKey) as? Date,
           Date().timeIntervalSince(last) < Self.autoRetryPause {
            return completionHandler(failure("Auto-connect paused after a failed attempt. Tap Connect to try again."))
        }
        let server = proto.serverAddress ?? AppConfig.defaultServer
        log("Connecting to \(server) (\(manual ? "manual" : "auto"))")

        queue.async {
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            guard let s = ocb_new(server, user, password, AppConfig.duoSecondPassword, { ctx, _, line in
                guard let ctx, let line else { return }
                Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue().log(String(cString: line))
            }, ctx) else {
                return completionHandler(self.failure("Couldn't start the VPN client."))
            }
            self.session = s

            var err = [CChar](repeating: 0, count: 512)
            guard ocb_connect(s, &err, err.count) == 0 else {
                let message = self.stopping ? "Cancelled." : String(cString: err)
                self.finishSession()
                if !manual, !self.stopping { UserDefaults.standard.set(Date(), forKey: Self.lastAutoFailureKey) }
                return completionHandler(self.failure(message))
            }
            UserDefaults.standard.removeObject(forKey: Self.lastAutoFailureKey)

            var cfg = ocb_config()
            guard ocb_get_config(s, &cfg) == 0 else {
                self.finishSession()
                return completionHandler(self.failure("The server didn't send tunnel settings."))
            }
            let settings = Self.networkSettings(cfg, server: server)
            ocb_config_free(&cfg)

            self.setTunnelNetworkSettings(settings) { error in
                if let error {
                    self.queue.async { self.finishSession() }
                    return completionHandler(self.failure("Couldn't apply VPN settings: \(error.localizedDescription)"))
                }
                let fd = ocb_find_utun_fd()
                guard fd >= 0 else {
                    self.queue.async { self.finishSession() }
                    return completionHandler(self.failure("Couldn't find the tunnel interface."))
                }
                self.log("Connected")
                completionHandler(nil)
                VPNQuickControl.reloadControl()

                Thread {
                    ocb_run(s, fd) // blocks until cancelled or the server ends the session
                    self.queue.async {
                        let byServer = !self.stopping
                        self.finishSession()
                        if byServer { self.cancelTunnelWithError(self.failure("The VPN session ended.")) }
                    }
                }.start()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log("Stopping (reason \(reason.rawValue))")
        stopping = true
        if let s = session { ocb_cancel(s) }
        completionHandler()
        VPNQuickControl.reloadControl()
    }

    // MARK: Helpers

    private func finishSession() {
        if let s = session { ocb_free(s) }
        session = nil
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
