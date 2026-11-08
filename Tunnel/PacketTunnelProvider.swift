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
    /// The rejoin under way, so a timer can abort it if it hangs (under sessionLock).
    private var _resumeToken: UUID?
    /// Likewise the login under way (see connectWithDeadline), and whether it ran out of time.
    private var _loginToken: UUID?
    private var _loginTimedOut = false
    /// Set by stopTunnel on iOS's thread, read on `queue`.
    private var stopping: Bool { sessionLock.withLock { _stopping } }
    private var pathMonitor: NWPathMonitor?
    private var lastNetwork: String?
    private var watchdog: DispatchSourceTimer?
    /// Set while the connection is down and we're getting it back.
    private var reconnectingSince: Date?
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
    /// The next try at rejoining the session on a new connection (see rejoin).
    private var pendingRejoin: DispatchWorkItem?
    private var lastRejoin = Date.distantPast
    private var rejoinTries = 0
    private var server = ""
    private var user = ""
    /// iOS's tunnel interface, kept across rejoins. -1 until the tunnel is up.
    private var tunFD: Int32 = -1
    /// Why we ended the connection, when it's our doing rather than OpenConnect's.
    private var endReason: String?

    /// OpenConnect's own limit on retrying a dropped connection. The watchdog restarts
    /// its attempts every minute, so this isn't reached; and when its connection does
    /// end, we rejoin the session on a new one (see rejoin). Nothing gives up on a
    /// session the server still has: like Cisco's client, the VPN stays on, retrying,
    /// until you disconnect or the server says the session is over.
    private static let reconnectTimeout: Int32 = 30 * 60

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
        self.user = user
        let saved = savedSession()
        // One saved for another NetID or server, before you changed it: no use now.
        if saved == nil, SessionStore.load() != nil { SessionStore.clear() }
        if RunMarker.isSet {
            // Set while the tunnel is up, cleared whenever it stops: so the last run ended
            // without stopping, e.g. iOS ended the extension or it crashed.
            log("The VPN extension quit unexpectedly last time")
            RunMarker.clear()
        }
        log("Connecting to \(server) (\(manual ? "manual" : "auto")\(saved != nil ? ", rejoining session" : ""))")

        queue.async {
            var err = [CChar](repeating: 0, count: 512)
            var session: OpaquePointer?
            var rejoined: SavedSession?

            // Rejoin the session from the last login if the server still has it: no
            // password, no Duo. This is how Stay Connected comes back after iOS stops
            // the tunnel, e.g. with no network. An automatic start tries for a while
            // before failing, since the network may still be coming up.
            if let saved {
                for attempt in 1... {
                    let (s, result) = self.resume(saved, err: &err)
                    if let s {
                        session = s
                        rejoined = saved
                        break
                    }
                    if self.stopping { return done(self.failure("Cancelled.")) }
                    if result == OCB_SESSION_ENDED {
                        self.log("The server has ended the saved session")
                        SessionStore.clear()
                        break
                    }
                    // You asked to connect and the server answered, but wouldn't take the
                    // session: log in rather than retry it indefinitely.
                    if manual, result == OCB_REFUSED { break }
                    // The server may well still have the session; it just can't be reached
                    // right now (no signal, a network still coming up). Like Cisco's client,
                    // stay on: bring the VPN up on the last settings, so traffic waits
                    // instead of going around it, and keep rejoining in the background.
                    // Connect too: logging in again would mean another Duo push for a
                    // session that's still there.
                    if let settings = saved.tunnelSettings, let key = saved.settingsKey {
                        return self.upWhileRejoining(settings, key: key, done: done)
                    }
                    if saved.settings != nil { self.log("Couldn't read the saved tunnel settings") }
                    if manual { break } // log in instead
                    // A session saved by an older build, without settings: keep it, and let
                    // iOS try again later.
                    guard attempt < 4, self.sleepUnlessStopping(Double(attempt) * 5) else {
                        return done(self.failure(self.stopping ? "Cancelled." : String(cString: err)))
                    }
                }
            }

            if session == nil {
                // Started before the first unlock after a restart: the saved session can't
                // be read yet, which doesn't mean it's gone. iOS starts it again later.
                if saved == nil, KeychainItem.isLocked(SavedSessionItem.account) {
                    return done(self.failure("Unlock your iPhone to reconnect the VPN."))
                }
                if let refusal = Self.loginRefusal(manual: manual) { return done(self.failure(refusal)) }
                guard let password = SharedKeychain.read() else {
                    return done(self.failure("Open ConnectAnytime and save your password."))
                }
                // A network just joined, such as another iPhone's hotspot, can take a few
                // seconds to carry traffic. If the server wasn't reached, the password
                // wasn't sent and there was no Duo push, so try again before failing.
                for attempt in 1... {
                    guard let s = self.newSession(server: server, user: user, password: password) else {
                        return done(self.failure(self.stopping ? "Cancelled." : "Couldn't start the VPN client."))
                    }
                    let (result, timedOut) = self.connectWithDeadline(s, err: &err)
                    if result == 0 {
                        session = s
                        break
                    }
                    self.finishSession()
                    if self.stopping { return done(self.failure("Cancelled.")) }
                    if timedOut {
                        return done(self.failure("The VPN server stopped answering during the login. Tap Connect to try again."))
                    }
                    let message = String(cString: err)
                    guard result == OCB_UNREACHABLE, attempt < 3 else { return done(self.failure(message)) }
                    self.log("\(message) Trying again")
                    guard self.sleepUnlessStopping(Double(attempt) * 3) else { return done(self.failure("Cancelled.")) }
                }
            }
            guard let s = session else { return done(self.failure("Couldn't start the VPN client.")) }
            // Settings from builds that paused auto-connect after failed logins.
            UserDefaults.standard.removeObject(forKey: "autoPausedUntil")
            UserDefaults.standard.removeObject(forKey: "autoFailures")
            self.saveSession(s, rejoined: rejoined)
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
                if error == nil { self.saveSettings(settings, key: key) }
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
                self.sessionLock.withLock { if !self._stopping { RunMarker.set() } } // see stopTunnel
                done(nil)
                self.queue.async {
                    self.tunFD = fd
                    self.watchNetwork()
                    self.run(s)
                }
            }
        }
    }

    /// Brings the tunnel up on `settings` without a connection, then rejoins the session
    /// in place until it's back or the server says it's over (see rejoin). Call on `queue`.
    private func upWhileRejoining(_ settings: NEPacketTunnelNetworkSettings, key: String,
                                  done: @escaping (Error?) -> Void) {
        setTunnelNetworkSettings(settings) { error in
            if let error {
                return done(self.failure("Couldn't apply VPN settings: \(error.localizedDescription)"))
            }
            let fd = ocb_find_utun_fd()
            guard fd >= 0 else { return done(self.failure("Couldn't find the tunnel interface.")) }
            self.log("Up on the last settings; rejoining the session")
            self.sessionLock.withLock { if !self._stopping { RunMarker.set() } }
            done(nil)
            self.queue.async {
                guard !self.stopping else { return }
                self.tunFD = fd
                self.installedKey = key
                self.watchNetwork()
                self.reconnecting()
                self.scheduleRejoin()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Log out when you disconnect. When iOS stops the tunnel on its own (no network,
        // sleep, an update), leave the server's session open, like Cisco's client, so
        // the next start rejoins it without Duo.
        let logOut = Self.endsSession(reason)
        log("Stopping (\(Self.describe(reason))\(logOut ? "" : ", keeping the session"))")
        sessionLock.withLock {
            _stopping = true
            _logOutOnStop = logOut
            if let s = session { logOut ? ocb_cancel(s) : ocb_detach(s) }
            RunMarker.clear() // under the lock, so startTunnel can't set it again after
        }
        if logOut { SessionStore.clear() }
        ActivityLog.flush()
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

    /// The session from the last login, if it's for this server and NetID.
    private func savedSession() -> SavedSession? {
        SessionStore.load().flatMap { $0.server == server && $0.user == user ? $0 : nil }
    }

    /// Keeps what rejoining `s` takes. A rejoin keeps the login's address: on an
    /// IPv6-only network it would read as a translated one.
    private func saveSession(_ s: OpaquePointer, rejoined: SavedSession?) {
        guard let url = ocb_session_url(s), let cookie = ocb_session_cookie(s) else { return }
        SessionStore.save(.init(server: server, user: user,
                                url: String(cString: url), cookie: String(cString: cookie),
                                dnsName: rejoined?.dnsName ?? ocb_session_dnsname(s).map { String(cString: $0) },
                                ip: rejoined?.ip ?? ocb_session_ip(s).map { String(cString: $0) },
                                settings: rejoined?.settings, settingsKey: rejoined?.settingsKey))
    }

    /// Remembers the tunnel settings iOS just installed with the saved session. Not once
    /// you've disconnected: checked under the lock stopTunnel sets `_stopping` under, and
    /// it clears the session after, so this can't bring a cleared session back.
    private func saveSettings(_ settings: NEPacketTunnelNetworkSettings, key: String) {
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: settings, requiringSecureCoding: true) else { return }
        sessionLock.withLock {
            guard !_stopping, var saved = savedSession(), saved.settingsKey != key || saved.settings == nil else { return }
            saved.settings = data
            saved.settingsKey = key
            SessionStore.save(saved)
        }
    }

    /// Rejoins `saved` on a new OpenConnect session, which becomes the current one.
    /// Returns it, or nil with ocb_resume's result (OCB_SESSION_ENDED if the server no
    /// longer has the session). A connect or TLS handshake has no timeout of its own,
    /// so an attempt that hangs is aborted after 30 s. Blocks; call on `queue`.
    private func resume(_ saved: SavedSession, err: inout [CChar]) -> (OpaquePointer?, Int32) {
        guard let s = newSession(server: server, user: user, password: "") else { return (nil, -1) }
        let token = UUID()
        sessionLock.withLock { _resumeToken = token }
        // After 30 s, and every second after that until ocb_resume returns: one abort may
        // only end the attempt on one of the server's addresses (see connectWithDeadline).
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 30, repeating: 1)
        var logged = false
        timer.setEventHandler { [weak self] in
            guard let self else { return timer.cancel() }
            let stuck = self.sessionLock.withLock {
                guard self._resumeToken == token, let s = self.session else { return false }
                ocb_detach(s) // fails the attempt, leaving the server's session open
                return true
            }
            guard stuck else { return timer.cancel() }
            if !logged { self.log("Rejoining is taking too long; giving up on this attempt") }
            logged = true
        }
        timer.resume()
        defer { timer.cancel() }
        let result = ocb_resume(s, saved.url, saved.cookie, saved.dnsName, saved.ip, &err, err.count)
        sessionLock.withLock { _resumeToken = nil }
        if result == 0 { return (s, 0) }
        log("Couldn't rejoin the session: \(String(cString: err))")
        freeSession()
        return (nil, result)
    }

    /// Logs in on `s` (ocb_connect). Reaching the server has no timeout of its own, and a
    /// network that drops traffic, say a hotspot whose phone has no signal, would hang it
    /// until you tap Disconnect. So it's aborted if it hasn't sent the password within
    /// 20 s, failing with OCB_UNREACHABLE (safe to retry). Once the password is sent the
    /// server waits for Duo, which gives up after about a minute, so it's only aborted
    /// after 3 minutes; `timedOut` is then true, and it mustn't be retried: that would
    /// send another Duo push. Blocks; call on `queue`.
    private func connectWithDeadline(_ s: OpaquePointer, err: inout [CChar]) -> (Int32, timedOut: Bool) {
        let token = UUID()
        sessionLock.withLock { _loginToken = token; _loginTimedOut = false }
        let start = DispatchTime.now()
        // After 20 s, and every second after that until ocb_connect returns.
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: start + 20, repeating: 1)
        var logged = false
        timer.setEventHandler { [weak self] in
            guard let self else { return timer.cancel() }
            let late = DispatchTime.now() >= start + 180
            let (current, aborted) = self.sessionLock.withLock {
                guard self._loginToken == token, let s = self.session else { return (false, false) }
                if ocb_cancel_unless_answered(s) { return (true, true) } // password not sent
                if late, !self._loginTimedOut {
                    self._loginTimedOut = true
                    ocb_cancel(s) // no cookie yet, so nothing to log out of
                }
                return (true, false)
            }
            guard current else { return timer.cancel() } // ocb_connect returned
            if aborted, !logged {
                self.log("The VPN server didn't answer within 20 s")
                logged = true
            }
            if late { timer.cancel() }
        }
        timer.resume()
        defer { timer.cancel() }
        let result = ocb_connect(s, &err, err.count)
        let timedOut = sessionLock.withLock {
            _loginToken = nil
            return _loginTimedOut
        }
        if timedOut { log("No answer from the VPN server for 3 minutes during the login") }
        return (result, timedOut && result != 0)
    }

    /// Waits, returning early (false) if the tunnel is stopping.
    private func sleepUnlessStopping(_ seconds: Double) -> Bool {
        let until = Date().addingTimeInterval(seconds)
        while Date() < until {
            if stopping { return false }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return !stopping
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

    private static func describe(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none: "no reason"
        case .userInitiated: "turned off"
        case .providerFailed: "the VPN extension failed"
        case .noNetworkAvailable: "no network"
        case .unrecoverableNetworkChange: "network change"
        case .providerDisabled: "VPN extension disabled"
        case .authenticationCanceled: "login cancelled"
        case .configurationFailed: "configuration failed"
        case .idleTimeout: "idle"
        case .configurationDisabled: "VPN configuration disabled"
        case .configurationRemoved: "VPN configuration removed"
        case .superceded: "another VPN took over"
        case .userLogout: "user logged out"
        case .userSwitch: "user switched"
        case .connectionFailed: "connection failed"
        case .sleep: "sleep"
        case .appUpdate: "app update"
        case .internalError: "iOS internal error"
        @unknown default: "reason \(reason.rawValue)"
        }
    }

    private static func describe(_ type: NWInterface.InterfaceType?) -> String {
        switch type {
        case .wifi: "Wi-Fi"
        case .cellular: "cellular"
        case .wiredEthernet: "Ethernet"
        default: "other"
        }
    }

    /// Frees the OpenConnect session, leaving the tunnel up.
    private func freeSession() {
        sessionLock.withLock {
            if let s = session { ocb_free(s) }
            session = nil
        }
    }

    private func finishSession() {
        pathMonitor?.cancel()
        pathMonitor = nil
        lastNetwork = nil
        watchdog?.cancel()
        watchdog = nil
        reconnectingSince = nil
        pendingReconnect?.cancel()
        pendingReconnect = nil
        pendingRejoin?.cancel()
        pendingRejoin = nil
        endReason = nil
        installedKey = nil
        wanted = nil
        applyingSettings = false
        tunFD = -1
        freeSession()
    }

    /// Runs the tunnel on `s` until it ends, then rejoins the session on a new one.
    private func run(_ s: OpaquePointer) {
        let fd = tunFD
        Thread {
            let result = ocb_run(s, fd, Self.reconnectTimeout) // blocks until cancelled or the connection ends
            self.queue.async { self.connectionEnded(s, result: result) }
        }.start()
    }

    /// OpenConnect's connection ended: it gave up retrying, the server refused or ended
    /// it, or we aborted it. Unless you're disconnecting, that doesn't end the VPN:
    /// rejoining the session settles whether the server still has it. If it does, the
    /// tunnel carries on, as Cisco's client does, with no Duo; if the server answers
    /// that it's over, only then does the VPN stop and wait for you to tap Connect.
    private func connectionEnded(_ s: OpaquePointer, result: Int32) {
        guard session == s else { return }
        let reason = endReason
        endReason = nil
        freeSession()
        if stopping { return finishSession() }
        log("The connection ended (\(reason ?? String(cString: strerror(-result)))); rejoining the session")
        scheduleRejoin()
    }

    /// Rejoin right away the first time; back off while it keeps failing or dropping.
    private func scheduleRejoin() {
        pendingRejoin?.cancel()
        if Date().timeIntervalSince(lastRejoin) > 120 { rejoinTries = 0 }
        let delay = rejoinTries == 0 ? 0 : min(5 * pow(2, Double(rejoinTries - 1)), 60)
        rejoinTries += 1
        if delay > 0 { log("Trying to rejoin again in \(Int(delay)) s") }
        let work = DispatchWorkItem { [weak self] in self?.rejoin() }
        pendingRejoin = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    /// Rejoins the session on a new OpenConnect session, on the same tunnel, which
    /// stays up meanwhile ("Reconnecting…"; traffic waits rather than bypassing the
    /// VPN). Keeps trying, straight away after a network change, until it's back, the
    /// server says the session has ended, or you disconnect.
    private func rejoin() {
        pendingRejoin = nil
        guard !stopping, tunFD >= 0 else { return finishSession() }
        guard session == nil else { return }
        reconnecting()
        lastRejoin = Date()
        guard let saved = savedSession() else {
            // Can't read it before the first unlock after a restart; it may still be valid.
            if KeychainItem.isLocked(SavedSessionItem.account) { return scheduleRejoin() }
            return end("The VPN session has ended. Tap Connect in ConnectAnytime to log in again.")
        }
        var err = [CChar](repeating: 0, count: 512)
        let (s, result) = resume(saved, err: &err)
        // Saved before checking for a stop, so a Disconnect meanwhile can't have its
        // logout undone: either it clears the session after this, or we do below.
        if let s { saveSession(s, rejoined: saved) }
        if stopping {
            if sessionLock.withLock({ _logOutOnStop }) { SessionStore.clear() }
            return finishSession()
        }
        guard let s else {
            if result == OCB_SESSION_ENDED {
                SessionStore.clear()
                return end("The server has ended your VPN session. Tap Connect to log in again.")
            }
            return scheduleRejoin()
        }
        log("Rejoined the session")
        var cfg = ocb_config()
        let config = ocb_get_config(s, &cfg) == 0
            ? cfg.key.map { (key: String(cString: $0), settings: Self.networkSettings(cfg, server: server)) } : nil
        ocb_config_free(&cfg)
        reconnected(config) // as after OpenConnect's own reconnects: apply any new settings
        run(s)
    }

    /// Stops the VPN. Call with no OpenConnect session running.
    private func end(_ message: String) {
        finishSession()
        RunMarker.clear()
        VPNQuickControl.reloadControl()
        cancelTunnelWithError(failure(message))
        VPNQuickControl.reloadControl()
    }

    /// On a network change, reconnect right away with the existing session
    /// instead of waiting for the old connection to time out. Like Cisco's
    /// client, this doesn't log in again, so there's no Duo push.
    private func watchNetwork() {
        guard tunFD >= 0, pathMonitor == nil else { return }
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback]) // skip our own tunnel
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.tunFD >= 0 else { return }
            // The first interface is the one in use. Its name alone misses Wi-Fi → Wi-Fi
            // (both en0); the gateway differs.
            let network = path.status != .satisfied ? "offline"
                : ([path.availableInterfaces.first?.name ?? ""] + path.gateways.map { "\($0)" }.sorted()).joined(separator: ",")
            defer { self.lastNetwork = network }
            guard let last = self.lastNetwork, last != network else { return }
            self.log(network == "offline" ? "Network lost" : "Network changed (\(Self.describe(path.availableInterfaces.first?.type)))")
            self.reconnecting()
            guard network != "offline" else { return }
            // Path updates come in bursts (interface, then gateways); reconnect once,
            // after they settle. Each reconnect is a new tunnel on the server, so extra
            // ones only add churn.
            self.pendingReconnect?.cancel()
            let work = DispatchWorkItem { [weak self] in
                guard let self, self.tunFD >= 0, !self.stopping else { return }
                if let rejoin = self.pendingRejoin {
                    rejoin.cancel()
                    self.rejoinTries = 0
                    self.log("Rejoining the session on the new network")
                    self.rejoin()
                } else if self.session != nil {
                    self.log("Reconnecting with the existing session")
                    self.kickReconnect()
                }
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
        if reconnectingSince == nil {
            reconnectingSince = Date()
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
                self.applyingSettings = false
                if error == nil {
                    self.installedKey = want.key
                    self.saveSettings(want.settings, key: want.key)
                }
                guard let s = self.session else { return } // between connections: the rejoin applies its own
                if let newer = self.wanted, newer.epoch != want.epoch || newer.key != want.key {
                    return self.applyWantedSettings() // the server sent newer settings meanwhile
                }
                self.wanted = nil
                guard want.epoch == self.reconnectEpoch else { return } // a newer reconnect will apply its own
                if let error {
                    // Try again on a new connection, keeping the session.
                    self.endReason = "couldn't apply new VPN settings: \(error.localizedDescription)"
                    ocb_detach(s)
                } else {
                    self.finishReconnect(epoch: want.epoch)
                }
            }
        }
    }

    /// Clears "Reconnecting…" unless another reconnect has started since.
    private func finishReconnect(epoch: Int) {
        guard epoch == reconnectEpoch else { return }
        if reconnectingSince != nil { log("Back up") }
        reasserting = false
        reconnectingSince = nil
    }

    /// Drop the current connection and reconnect now with the existing session.
    private func kickReconnect() {
        guard let s = session else { return }
        lastReconnectKick = Date()
        reconnectEpoch += 1
        ocb_reconnect(s)
    }

    /// Every 10 s. OpenConnect's retry timeout only counts its sleeps, and a connect or
    /// TLS handshake can hang with no timeout. While reconnecting, retry a minute after
    /// the latest attempt started (not sooner: that would abort it). Not while offline:
    /// the network coming back starts an attempt.
    private func checkReconnect() {
        guard reconnectingSince != nil, lastNetwork != "offline" else { return }
        if session != nil, Date().timeIntervalSince(lastReconnectKick) >= 60 { kickReconnect() }
    }

    /// What rejoining the last session takes: the server's address after any redirects,
    /// and its session cookie. In the Keychain, on this device only, since the cookie
    /// works like a password until the session ends. Cleared on logout and once the
    /// server ends the session.
    private struct SavedSession: Codable {
        let server, user, url, cookie: String
        let dnsName, ip: String? // the server's name and the address the session is on
        /// The tunnel settings last installed for it (NEPacketTunnelNetworkSettings,
        /// archived) and their key, so a restart can bring the VPN up on them right away
        /// and rejoin in the background (see startTunnel). Not secret. Nil from builds
        /// before this.
        var settings: Data?
        var settingsKey: String?

        var tunnelSettings: NEPacketTunnelNetworkSettings? {
            settings.flatMap { try? NSKeyedUnarchiver.unarchivedObject(ofClass: NEPacketTunnelNetworkSettings.self, from: $0) }
        }
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

    /// Whether the tunnel is up, kept across launches of the extension, so the next start
    /// can tell when the last run ended without stopping (see startTunnel).
    private enum RunMarker {
        private static let account = "running"
        static var isSet: Bool { KeychainItem.read(account) != nil }
        static func set() { KeychainItem.save("1", as: account) }
        static func clear() { KeychainItem.delete(account) }
    }

    private func failure(_ message: String) -> NSError {
        log("Failed: \(message)")
        ActivityLog.flush() // iOS may end this process right after
        return NSError(domain: "ConnectAnytime", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    /// OpenConnect's INFO-level messages and our own; never contains typed input.
    private func log(_ message: String) {
        logger.log("\(message, privacy: .public)")
        // Not the retry countdowns, which would push out what led up to them.
        if !message.hasPrefix("sleep ") { ActivityLog.add(message) }
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
