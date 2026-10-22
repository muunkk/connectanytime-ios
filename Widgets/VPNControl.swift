import AppIntents
import SwiftUI
import WidgetKit

@main
struct ConnectAnytimeWidgets: WidgetBundle {
    var body: some Widget {
        VPNControl()
    }
}

/// Control Center toggle: filled when connected, plain when not.
struct VPNControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: AppConfig.controlKind, provider: Provider()) { isOn in
            ControlWidgetToggle("NYU VPN", isOn: isOn, action: SetVPNIntent()) { on in
                Label {
                    Text(on ? "Connected" : "Off")
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
        var previewValue: Bool { false }
        func currentValue() async throws -> Bool { await VPNQuickControl.isOn() }
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
