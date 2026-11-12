# Building and publishing the apps

`.github/workflows/release.yml` builds the apps on GitHub's machines:

| App | Machine | What it produces |
|---|---|---|
| Windows and Linux desktop app (Tauri) | `windows-2025`, `ubuntu-24.04` | `.msi` and `-setup.exe`; `.deb`, `.rpm`, `.AppImage` |
| macOS desktop app (SwiftUI) | `macos-26` (Xcode 26.6) | `ONA-macOS-arm64.zip` (Apple silicon only: the ona-core bridge is built for arm64) |
| iPhone app | `macos-26` | a TestFlight build |

The workflow runs:

- **On a pull request that touches the apps:** it builds and tests them and keeps the files as artifacts of the run for a few days. Nothing is signed or published.
- **On a version tag (`v0.1.0`…):**
  - it publishes a **GitHub Release** with the desktop installers;
  - it sends the iPhone app to **TestFlight**;
  - it signs the Mac app with Developer ID and notarizes it, when the secrets below are set.

## Publishing a version

```bash
git tag v0.1.0
git push origin v0.1.0
```

Then the Release appears under *Releases* on GitHub. The website's download page can link to
`https://github.com/<owner>/<repo>/releases/latest`.

## Secrets (GitHub → Settings → Secrets and variables → Actions)

None is in the repository. Without them, the Mac app is ad-hoc signed and the iPhone app is built but not sent to
TestFlight.

| Secret | What it is |
|---|---|
| `APPLE_TEAM_ID` | The 10-character team ID of the Apple Developer account |
| `ASC_KEY_ID` | ID of an App Store Connect API key (App Store Connect → Users and Access → Integrations → Keys) |
| `ASC_ISSUER_ID` | The issuer ID shown on that page |
| `ASC_KEY_P8_BASE64` | The key file (`AuthKey_….p8`), in base64: `base64 -i AuthKey_XXXX.p8 \| pbcopy` |
| `MACOS_CERT_P12_BASE64` | The **Developer ID Application** certificate and its private key, as a `.p12`, in base64 |
| `MACOS_CERT_PASSWORD` | The `.p12`'s export password |

The key needs the **Admin** role. With `-allowProvisioningUpdates`, Xcode uses it to create the iPhone app's certificates
and profiles (cloud-managed signing) and to register its bundle ID. `notarytool` uses the same key.

The Mac app's **Developer ID Application** certificate cannot be made with that key: Apple lets only the team's Account
Holder create one (the first release run failed with "Cloud signing permission error"). It is made once on
developer.apple.com (Certificates, +, Developer ID Application) from a certificate request, then exported as a `.p12`
with its private key and stored in the two `MACOS_CERT_…` secrets. The workflow imports it into a temporary keychain,
signs with hardened runtime and a timestamp, notarizes and staples. Without these secrets the Mac app is ad-hoc
signed. A Mac failure does not stop the Release: it is published with what was built.

## Before the first TestFlight build

- The bundle IDs `org.ona.remote` (iPhone) and `org.ona.desktop` (Mac) must be free, or already belong to this team.
  If Apple refuses one, change `PRODUCT_BUNDLE_IDENTIFIER` (`ios/ONA/Config/ONA.xcconfig`,
  `desktop/ONADesktop/ONADesktop.xcodeproj`).
- Create the app once in App Store Connect (My Apps → +) with the iPhone bundle ID.
- TestFlight asks about encryption export rules at the first build: the app uses standard cryptography (Tor, ECDSA
  signatures).
- External testers (the jury, for example) need Apple's beta review of the first build, usually about a day. A public
  TestFlight link can then be put on the website.

## What the downloads do not include

- **`tor`**: the desktop apps need it installed for the Tor mode (`brew install tor` on a Mac, the `tor` package on
  Linux, the Tor Expert Bundle on Windows). Without it, only the local-network mode of the development builds works.
- **Windows and Linux installers are not signed**: Windows SmartScreen shows a warning the person can pass. No code
  signing certificate is set up for them.

## Status

This workflow has not run yet when this file was written. The first run on its pull request will show whether each
job builds on GitHub's machines.
