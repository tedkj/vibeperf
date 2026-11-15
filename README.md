# VibePerf

Real network speed between two PCs or to any iperf3 server, and how much the delay grows under
load. For Windows.

VibePerf is a client and a server that speak iperf3's protocol, so it tests against any iperf3
server that asks for no password (Linux, a NAS, OPNsense, pfSense) or against VibePerf on another
PC. TCP and UDP; normal, reverse and both ways at once; 1 to 8 streams. A live graph while it runs,
retransmitted bytes as Windows counts them (never a made-up number), the latency while the link is
loaded with a bufferbloat grade, and a history of your tests. It is written in Rust with a native
Slint interface, with no browser engine inside.

## What it does and doesn't do

- **As a client** it connects only to the host you type, on the port you choose (5201 unless you
  change it).
- **As a server** it listens on that port (TCP and UDP) until you stop it. A per-user app can't
  open Windows Firewall, so the first **Start server** asks once for admin rights (one Windows
  prompt) and a short helper adds two inbound rules for VibePerf alone, for your local subnet
  only. The helper removes them again when you stop the server or close VibePerf, and after a
  crash too. If you say no, VibePerf still works as a client. VibePerf itself never runs elevated.
- **Keeps** its settings in `%APPDATA%\com.tedkj.vibeperf` and the last 200 tests in
  `%LOCALAPPDATA%\com.tedkj.vibeperf`.

## What it connects to

Only the PCs you test with, your router and your DNS servers (for the latency under load and the
names), and getvibeware.com when you press About's "Check this install". No accounts, no ads, no
telemetry.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibeperf/releases), or from
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, `VibePerf.exe` and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (the certificate's name; right-click, Properties › Digital Signatures). Compare
the installer's SHA-256 with the one on the release page:

```powershell
Get-FileHash .\VibePerf_0.1.0-preview_x64-setup.exe
```

Uninstalling (Settings › Apps) removes the app and leaves your settings and test history where
they are, so a reinstall finds them.

## What is in this repository

| Folder | What it is |
|--------|-----------|
| `src/` | The app: iperf3's protocol, the client and the server, latency under load, the firewall helper. |
| `ui/` | The Slint interface (the VibeWare design system in `ui/vibeware/`). |
| `assets/` | The icon and the manifest. |
| `installer/` | The NSIS installer and its build script. |
| `vendor/` | Slint's `i-slint-core` 1.18.1 with one small repaint fix; `vendor/README.md` says what changed and why. |

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibeperf.exe`.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibePerf_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
