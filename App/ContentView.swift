import Accessibility
import NetworkExtension
import SwiftUI
import UserNotifications

struct ContentView: View {
    @EnvironmentObject private var vpn: VPNController
    @Environment(\.scenePhase) private var scenePhase
    @State private var password = ""
    @State private var newNetwork = ""
    @FocusState private var focused: Field?

    private enum Field { case netID, password, network, server }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 16) {
                        Image(systemName: symbol)
                            .font(.system(size: 56, weight: .regular))
                            .foregroundStyle(vpn.isConnected ? Color.accentColor : .secondary)
                            .contentTransition(.symbolEffect(.replace))
                            .accessibilityHidden(true) // the status text says it
                        Text(statusText)
                            .font(.headline)
                        Button {
                            focused = nil
                            Task { vpn.isConnected || vpn.isBusy ? await vpn.disconnect() : await vpn.connect() }
                        } label: {
                            Text(vpn.isConnected || vpn.isBusy ? "Disconnect" : "Connect")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .tint(vpn.isConnected || vpn.isBusy ? .red : .accentColor)
                        if let error = vpn.lastError {
                            Text(error)
                                .font(.footnote)
                                .foregroundStyle(.red)
                                .multilineTextAlignment(.center)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                }

                Section {
                    TextField("NetID", text: $vpn.netID)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($focused, equals: .netID)
                    HStack {
                        SecureField(vpn.hasPassword ? "Password saved" : "Password", text: $password)
                            .textContentType(.password)
                            .focused($focused, equals: .password)
                            .submitLabel(.done)
                            .onSubmit(savePassword) // Return saves; otherwise the next Connect uses the old one
                        Button("Save", action: savePassword)
                            .disabled(password.isEmpty)
                    }
                } header: {
                    Text("NYU account")
                } footer: {
                    Text("Your password stays in this iPhone's Keychain and is only sent to the VPN server. You approve Duo on your phone; the app answers \"push\" for you.")
                }

                Section {
                    Toggle("Stay Connected", isOn: $vpn.stayConnected)
                } footer: {
                    Text("Like Cisco's AnyConnect. After you connect, the VPN keeps your session through network changes and comes back whenever it drops, on any network, without Duo. Once the server ends the session, it waits for you to tap Connect. Disconnecting pauses this until you tap Connect again.")
                }

                Section {
                    ForEach(vpn.autoNetworks, id: \.self) { Text($0) }
                        .onDelete { vpn.removeAutoNetworks(at: $0) }
                    Button("Add Current Wi-Fi") {
                        Task {
                            if let ssid = await vpn.currentWiFi() { vpn.addAutoNetwork(ssid) }
                            else { focused = .network }
                        }
                    }
                    HStack {
                        TextField("Wi-Fi name", text: $newNetwork)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused, equals: .network)
                            .onSubmit(addNetwork)
                        Button("Add", action: addNetwork)
                            .disabled(newNetwork.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("Auto-connect")
                } footer: {
                    Text(vpn.stayConnected
                         ? "Not used while Stay Connected is on, which already connects on every network. Swipe to remove."
                         : "Joining one of these networks brings the VPN back if your session is still open. A new login, and its Duo push, only happens when you tap Connect. Disconnecting pauses auto-connect until you tap Connect again. Swipe to remove.")
                }

                Section("Server") {
                    TextField("Server", text: $vpn.server)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .focused($focused, equals: .server)
                }

                Section {
                    NavigationLink("Activity") { ActivityView() }
                } footer: {
                    Text("What the VPN did recently, such as reconnecting after a network change, and why it stopped.")
                }

                Section("About") {
                    Text(AppConfig.buildDescription)
                        .font(.footnote)
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("ConnectAnytime")
        }
        .task {
            await vpn.load()
            // So the VPN can say when the session has ended and it needs you to tap Connect.
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { vpn.refresh() } // e.g. back from approving in Duo
        }
        .onChange(of: vpn.lastError) { _, error in
            if let error { AccessibilityNotification.Announcement(error).post() } // so VoiceOver reads it out
        }
    }

    private func savePassword() {
        vpn.savePassword(password)
        password = ""
        focused = nil
    }

    private func addNetwork() {
        vpn.addAutoNetwork(newNetwork)
        newNetwork = ""
    }

    private var symbol: String {
        switch vpn.status {
        case .connected: "network"
        case .connecting, .reasserting, .disconnecting: "network.badge.shield.half.filled"
        default: "network.slash"
        }
    }

    private var statusText: String {
        switch vpn.status {
        case .connected: "Connected"
        case .connecting: "Connecting… approve Duo on your phone"
        case .reasserting: "Reconnecting…"
        case .disconnecting: "Disconnecting…"
        default: "Not connected"
        }
    }
}

/// The tunnel's recent activity, newest first.
struct ActivityView: View {
    @State private var lines: [String] = []

    var body: some View {
        List(lines.reversed().indices, id: \.self) { i in
            Text(lines.reversed()[i])
                .font(.caption.monospaced())
                .textSelection(.enabled)
        }
        .overlay { if lines.isEmpty { ContentUnavailableView("No activity yet", systemImage: "list.bullet") } }
        .navigationTitle("Activity")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                ShareLink(item: ([AppConfig.buildDescription] + lines).joined(separator: "\n")) {
                    Label("Share", systemImage: "square.and.arrow.up").labelStyle(.iconOnly) // named for VoiceOver
                }
                .disabled(lines.isEmpty)
                Button("Clear") {
                    ActivityLog.clear()
                    lines = []
                }
                .disabled(lines.isEmpty)
            }
        }
        .refreshable { lines = ActivityLog.read() }
        .onAppear { lines = ActivityLog.read() }
    }
}
