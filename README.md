# ConnectAnytime for iOS

One-tap Connect/Disconnect for the NYU Shanghai VPN on iPhone, without Cisco Secure Client.

Cisco's app makes you type your password, type `push` and approve Duo every time.
ConnectAnytime saves your NetID and password once. After that, Connect logs in, sends the
Duo push and opens the tunnel. You only approve Duo on your phone.

Sister project: [ConnectAnytime for macOS](https://github.com/muunkk/connectanytime).

## Features

- **Connect / Disconnect** in the app, from a **Control Center** toggle (filled when
  connected), or with Siri, Shortcuts and the Action button.
- **Stay Connected** (on by default), like Cisco's Connect On Demand. After you connect,
  iOS starts the VPN again whenever it drops, on any network. If the server has ended
  the session by then, that means a new Duo push.
- **Auto-connect** when you join Wi-Fi networks you choose (not needed with Stay
  Connected on). If an automatic attempt fails after sending your password (say you
  ignored Duo), it waits 15 minutes before trying again, then twice as long after each
  further failure, up to 4 hours, instead of sending more pushes. If it couldn't reach
  the server at all, say with no signal yet, it tries again a minute later.
  Disconnecting pauses auto-connect until you connect again.
- **Survives network changes.** Switch Wi-Fi, drop to cellular or lose signal for a while,
  and the VPN reconnects with the session it already has, like Cisco's client. No new
  login, no new Duo push, as long as the server still holds the session. It usually
  reconnects within seconds, and keeps trying for up to 30 minutes; meanwhile traffic
  waits rather than bypassing the VPN. If the server gives the phone a new VPN address
  when it reconnects, the tunnel switches to it instead of disconnecting.
- **Full tunnel**, like NYU's Cisco setup. IPv6 is dropped rather than bypassing the VPN.

## How it works

The app ships its own VPN, a Network Extension packet tunnel built on
[OpenConnect](https://www.infradead.org/openconnect/), an open-source client for Cisco's
AnyConnect protocol. It logs in to `vpn.shanghai.nyu.edu` with your NetID, password and
`push` (Duo). It checks the server's certificate against iOS's trust store, then routes
traffic through the tunnel.

## Your password

- Stored in the iPhone Keychain, shared only between the app and its VPN extension.
- Sent only to the VPN server, over TLS, after the server's certificate is verified.
- Never logged. The extension logs OpenConnect's status lines only, and debug output (which
  would include form data) is turned off.
- Each login field is answered once. A wrong password fails instead of retrying, so it
  can't lock your account.
- Siri, Shortcuts and Control Center actions need Face ID or your passcode when the phone
  is locked.

## Build

Requires a Mac with Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) and a paid
Apple Developer account (iOS VPN apps need one).

```sh
Vendor/build-deps.sh        # builds OpenSSL + OpenConnect for iOS (checksums pinned)
echo 'DEVELOPMENT_TEAM = YOURTEAMID' > Config/Local.xcconfig
xcodegen generate
open ConnectAnytime.xcodeproj
```

The bundle IDs use `com.muunkk.*`. To build under your own team, change them in
`project.yml`, and change `tunnelBundleID` and `controlKind` in `Shared/Shared.swift` to
match.

## Licenses

ConnectAnytime's own code is MIT (see `LICENSE`). The build downloads and statically links
OpenConnect (LGPL-2.1), with the small changes in `Vendor/patches`, and OpenSSL
(Apache-2.0). If you distribute built binaries, you must meet the LGPL's terms for
OpenConnect.

Not affiliated with Cisco or NYU.
