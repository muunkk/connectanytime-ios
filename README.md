# ConnectAnytime for iOS

One-tap Connect/Disconnect for the NYU Shanghai VPN on iPhone, without Cisco Secure Client.

Cisco's app makes you type your password, type `push` and approve Duo every time.
ConnectAnytime saves your NetID and password once. After that, Connect logs in, sends the
Duo push and opens the tunnel. You only approve Duo on your phone.

Sister project: [ConnectAnytime for macOS](https://github.com/muunkk/connectanytime).

## Features

- **Connect / Disconnect** in the app, from a **Control Center** toggle (filled while
  connecting or connected; its label says which), or with Siri, Shortcuts and the
  Action button.
- **Stay Connected** (on by default), like Cisco's AnyConnect. After you connect, iOS
  starts the VPN again whenever it drops, on any network, and it rejoins the session
  you already have: no new login, no Duo. Once the server has ended the session, it
  waits for you to tap Connect instead of sending Duo pushes on its own. It switches on
  once the VPN is up, not while you're approving Duo, so the approval isn't held up.
  Turning the VPN on in iOS Settings counts as automatic too, so it only rejoins an open
  session; to log in, use the app, Control Center, Siri or Shortcuts.
- **Auto-connect** when you join Wi-Fi networks you choose (not needed with Stay
  Connected on), if your session is still open. Like Stay Connected, it never logs in
  by itself: a new login, and its Duo push, only happens when you connect. It couldn't
  work anyway, since iOS holds Duo's approval while it's starting the VPN
  automatically. Disconnecting pauses auto-connect until you connect again.
- **Survives network changes.** Switch Wi-Fi, drop to cellular or lose signal for a while,
  and the VPN reconnects with the session it already has, like Cisco's client. No new
  login, no new Duo push, as long as the server still holds the session. It usually
  reconnects within seconds. It keeps trying through any number of network changes and
  any time offline, and only stops once the server says the session is over (or it can't
  reach the server for 30 minutes on a working network). Meanwhile traffic waits rather
  than bypassing the VPN. If the server gives the phone a new VPN address when it
  reconnects, the tunnel switches to it instead of disconnecting.
- **Activity** in the app shows what the VPN did recently and why it stopped, if it did,
  including when iOS ended the VPN extension without stopping it. Share it from there
  when reporting a problem.
- **Full tunnel**, like NYU's Cisco setup. IPv6 is dropped rather than bypassing the VPN.

## How it works

The app ships its own VPN, a Network Extension packet tunnel built on
[OpenConnect](https://www.infradead.org/openconnect/), an open-source client for Cisco's
AnyConnect protocol. It logs in to `vpn.shanghai.nyu.edu` with your NetID, password and
`push` (Duo). It checks the server's certificate against iOS's trust store, then routes
traffic through the tunnel.

To come back without Duo after iOS stops or restarts the VPN extension, the extension
saves the session and rejoins it. The session's cookie carries a key (OpenConnect's
STRAP key), and every reconnect hands the server a new one. OpenConnect 9.21 leaves the
cookie as it was at login, so a session saved then carries a key the server no longer
holds (ConnectAnytime for Android, which shares this code, got 401 for every such
rejoin). `Vendor/patches/openconnect-strap-cookie.patch` puts the key the server
accepted back into the cookie, and the extension saves the session again in every
reconnect, twice: just before the request that carries the new key goes out, and when
the server answers it. iOS can end the extension at any moment, including while that
request waits for its answer, and what's in the Keychain then is all the next start has.
Between those two moments the server holds one of two keys: both are saved, and a rejoin
tries the newer one only if the other is refused. That's one more request at most, never
a password or a Duo push. Until the server answers 200, every further attempt presents
that same new key, never a third.

This rests on two things about the server that can only be seen from outside. One is
that it checks each request against the key it holds and then keeps the key presented,
which fits the 401s above. The other is that refusing a key with 401 leaves the session
itself open, so the other saved key can still rejoin it. If a refusal ended the session
instead, a reconnect cut off between its two saves could still cost a new login.

If saving to the Keychain fails, the extension logs it and reconnects anyway: holding
the VPN down until the Keychain works would cost more than the new login this risks, and
only if iOS also ends the extension before the next save succeeds.

## Your password

- Stored in the iPhone Keychain, shared only between the app and its VPN extension.
- Sent only to the VPN server, over TLS, after the server's certificate is verified.
- Never logged. The extension logs OpenConnect's status lines only, and debug output (which
  would include form data) is turned off.
- To rejoin the VPN session without Duo, the extension keeps the server's session
  cookie in the Keychain, on this iPhone only. It's never logged, and it's deleted when
  you disconnect or the server ends the session.
- Each login field is answered once. A wrong password fails instead of retrying, so it
  can't lock your account.
- Siri, Shortcuts and Control Center actions need Face ID or your passcode when the phone
  is locked.

## Versioning insider builds

The current insider build is **0.1.3 (build 4)**, from the `overnight-diagnostics`
branch: 0.1.2 (3) plus the audit fixes (PR #15) and the STRAP key kept in the saved
session, so a rejoin after a phone restart doesn't need Duo (PR #16). 0.1.2 (3) is
0.1.1 (2) plus logging to find why the VPN can be off in the morning (the
server's session limits, long sleeps, and a run of refused automatic starts counted
instead of filling the log), and a notification when the session has ended. 0.1.1
(build 2) contains the hotspot and reconnect fixes merged in PR #13.
The app shows its version under About and includes it in shared Activity logs.
Each tunnel start also records the extension's version, so older log entries remain
distinguishable after an update.

For every distributed fix, increment the patch version and build number in
`project.yml` (next: `0.1.4`, build `5`), then run `xcodegen generate` before building.
Use an immutable matching Git tag, such as `v0.1.1`, and name the insider release
`0.1.1 (2) — Hotspot and reconnect fixes`. Never replace an existing tag or distribute
different code under an already used version/build pair. All three targets inherit
the same version settings.

Insiders receive builds through the **internal** TestFlight group in App Store
Connect (app ID `6825901619`). Archive the Release configuration and export with
`Config/ExportOptions-TestFlight.plist`, which preserves the version/build pair
instead of letting Xcode change it. When exporting on this Mac, put `/usr/bin`
before Homebrew in `PATH` so Xcode's rsync subprocess uses Apple's rsync.
Upload the IPA, add What to Test notes identifying the fixes and requested checks,
and verify that Apple has processed the build and made it available to the internal
group. A Git tag alone does not distribute an iOS build.

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

Run `Vendor/build-deps.sh` again whenever `Vendor/patches` changes. It rebuilds
OpenConnect only if they did. Until you do, the tunnel's build stops with an error
rather than link the old library.

### Tests and the Simulator

```sh
xcodebuild test -project ConnectAnytime.xcodeproj -scheme ConnectAnytimeTests \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

The unit tests cover logic that needs no VPN or Keychain, and run on the Simulator
without the app or the libraries above.

```sh
scripts/test-strap-cookie.sh
```

This one runs on the Mac, after `Vendor/build-deps.sh` (it uses the OpenConnect
download) and with Homebrew's `openssl@3`. It builds the patched OpenConnect for the Mac
and checks that a saved session can be rejoined: `Vendor/tests/strap-cookie-test.c` tests
the patch above, and `Vendor/tests/bridge-session-test.c` runs the extension's own
`Tunnel/ocbridge.c` against a local server that refuses any key but the session's
current one, including a rejoin from what had been saved while a reconnect was still
waiting for the server. Both then have to fail against OpenConnect without the patch.

A VPN can't run in the Simulator, but the whole app builds for it once the libraries
exist for it too (Apple silicon Macs only):

```sh
Vendor/build-deps.sh simulator   # into Vendor/out-sim
xcodebuild build -project ConnectAnytime.xcodeproj -scheme ConnectAnytime \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' CODE_SIGNING_ALLOWED=NO
```

## Licenses

ConnectAnytime's own code is MIT (see `LICENSE`). The build downloads and statically links
OpenConnect (LGPL-2.1), with the small changes in `Vendor/patches`, and OpenSSL
(Apache-2.0). If you distribute built binaries, you must meet the LGPL's terms for
OpenConnect.

Not affiliated with Cisco or NYU.
