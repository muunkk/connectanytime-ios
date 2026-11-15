import AppIntents
import SwiftUI
import WidgetKit

@main
struct ConnectAnytimeWidgets: WidgetBundle {
    var body: some Widget {
        VPNControl()
    }
}

/// Control Center toggle: filled when on (connected or on the way there), plain when
/// not. On while connecting, so a tap stops it; its label says which.
struct VPNControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: AppConfig.controlKind, provider: Provider()) { state in
            ControlWidgetToggle("NYU VPN", isOn: state != .off, action: SetVPNIntent()) { on in
                Label {
                    // Right after a tap turns it on, `on` is true while `state` is still off.
                    Text(!on ? "Off" : state == .connected ? "Connected" : "Connecting…")
                } icon: {
                    // The network globe fills its whole frame; scale it down to sit
                    // like the other Control Center glyphs.
                    Image(systemName: on ? "network" : "network.slash")
                        .imageScale(.small)
                }
            }
        }
        .displayName("NYU VPN")
        .description("Connect or disconnect the NYU Shanghai VPN.")
    }

    struct Provider: ControlValueProvider {
        var previewValue: VPNQuickControl.ToggleState { .off }
        func currentValue() async throws -> VPNQuickControl.ToggleState { await VPNQuickControl.state() }
    }
}

struct SetVPNIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Set NYU VPN"
    // Control Center works on the lock screen; require Face ID / passcode there.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    @Parameter(title: "Connected")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try await VPNQuickControl.set(value)
        return .result()
    }
}
