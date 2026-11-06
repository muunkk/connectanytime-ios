import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var vpn: VPNController
    @Environment(\.scenePhase) private var scenePhase
    @State private var password = ""
    @State private var newNetwork = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 16) {
                        Image(systemName: symbol)
                            .font(.system(size: 56, weight: .regular))
                            .foregroundStyle(vpn.isConnected ? Color.accentColor : .secondary)
                            .contentTransition(.symbolEffect(.replace))
                        Text(statusText)
                            .font(.headline)
                        Button {
                            focused = false
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
                        .focused($focused)
                    HStack {
                        SecureField(vpn.hasPassword ? "Password saved" : "Password", text: $password)
                            .textContentType(.password)
                            .focused($focused)
                        Button("Save") {
                            vpn.savePassword(password)
                            password = ""
                            focused = false
                        }
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
                            else { newNetwork = "" ; focused = true }
                        }
                    }
                    HStack {
                        TextField("Wi-Fi name", text: $newNetwork)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused)
                        Button("Add") {
                            vpn.addAutoNetwork(newNetwork)
                            newNetwork = ""
                        }
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
                        .focused($focused)
                }
            }
            .navigationTitle("ConnectAnytime")
        }
        .task { await vpn.load() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { vpn.refresh() } // e.g. back from approving in Duo
        }
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
