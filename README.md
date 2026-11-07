# Static IP Manager

A desktop GUI for **Windows** and **Linux** that sets a static IPv4 configuration on a network adapter - with validation, a preview of the exact commands, automatic backup, and an **automatic rollback timer** so a wrong address can't lock you out.

Written in Rust with [egui](https://github.com/emilk/egui). One self-contained binary per OS, no runtime to install.

## Features

- Lists adapters: name, state, MAC, IPv4/mask, gateway, DNS, DHCP vs static, IPv6 (read-only).
- Static IP form with strict validation: valid ranges, netmask or prefix (contiguous masks only), no network/broadcast/loopback/multicast address, gateway inside the subnet, max 3 unique DNS servers.
- DHCP <-> static switching, one-click **Reset to DHCP**, **Restore last backup**.
- Saved profiles (JSON in your user config folder).
- **Review screen** shows the exact script that will run with admin rights before anything happens.
- **Auto-revert**: after applying you get a countdown (15-300 s, default 60). Press *Keep settings* or the previous configuration is restored - even if you lose network access, because the revert runs inside the privileged helper, not in the GUI.
- Warnings when you change the adapter that holds the default route, or while in an SSH / Remote Desktop session.
- Optional "Check if address is in use": 2 pings to that single address, only when you click it.
- The GUI never runs as administrator/root. Privilege is requested per apply: UAC on Windows, `pkexec` (polkit) on Linux.
- No telemetry. No network access except what you click. No LAN scanning.

### Linux backends

The detected backend is shown in the top bar (switchable if several are present). Order of preference:

| Backend | How it is applied |
|---|---|
| NetworkManager | `nmcli connection modify/up` on the device's active connection |
| netplan | writes `/etc/netplan/90-static-ip-manager-<iface>.yaml`, `netplan generate` + `netplan apply` |
| systemd-networkd | writes `/etc/systemd/network/05-static-ip-manager-<iface>.network`, `networkctl reload/reconfigure` |
| dhcpcd (Raspberry Pi OS Bullseye and older) | managed block in `/etc/dhcpcd.conf`, restart dhcpcd |

Files are backed up to `/var/lib/static-ip-manager/backups/` before they are touched.

### Windows

Uses the `NetTCPIP` / `DnsClient` PowerShell cmdlets (`New-NetIPAddress`, `Set-NetIPInterface`, `Set-DnsClientServerAddress`). The script is passed to an elevated PowerShell as an encoded command (no script file on disk that could be tampered with).

## Download

Get binaries from the [Releases](https://github.com/itsnavin/static-ip-manager/releases) page (`SHA256SUMS.txt` included):

- Windows: `static-ip-manager-windows-x86_64.zip`
- Linux: `static-ip-manager_amd64.deb` (`sudo apt install ./static-ip-manager_amd64.deb`), `static-ip-manager-x86_64.AppImage`, or `static-ip-manager-linux-x86_64.tar.gz`

Verify: `sha256sum -c SHA256SUMS.txt` (Linux) or `Get-FileHash` (Windows).

Linux runtime needs: `pkexec` (polkit) with a polkit agent running (any desktop has one), `ip` from iproute2 (JSON support), and an OpenGL-capable display.

## Usage

1. Start the app and pick an adapter on the left.
2. Choose *Static IP*, fill in address, prefix/netmask, gateway and DNS. Fix anything shown in red.
3. (Optional) *Check if address is in use*.
4. *Review and apply...*, read the script and warnings, press *Apply*, approve the UAC/polkit prompt.
5. Test connectivity, then press **Keep settings** inside the countdown. Do nothing and it reverts.

## Build from source

```
cargo test
cargo build --release
```

Linux build dependencies (Debian/Ubuntu): `libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxi-dev libxrandr-dev libgl1-mesa-dev`.

`cargo run --example list` prints what the app sees (read-only).

## Safety notes

- Do the first apply while you have physical/console access, not only SSH.
- The adapter carrying your remote session is the one most likely to lock you out; the app warns, the auto-revert is your safety net.
- Auto-revert restores the configuration captured *by the GUI* (NetworkManager, Windows) or the backed-up files (netplan, networkd, dhcpcd). If the machine loses power during the countdown, the revert does not run; the new config simply persists.

## Limitations (honest list)

- **IPv6 is displayed but not configurable.** IPv4 only.
- **Applying to real adapters has not been tested by the author** (only read-only adapter listing on one Windows machine). See *Testing*. Expect rough edges on Linux, especially on distros I could not try.
- Linux needs `ip -j` (iproute2 >= 4.13). BusyBox-only systems (some minimal Yocto images) are unsupported; images with full iproute2 + systemd-networkd should work in theory.
- netplan: other YAML files for the same interface are merged by netplan; list values such as `addresses` are *appended*, so an older static address in another file can remain. Wi-Fi interfaces are written under `ethernets` and are not supported on netplan.
- NetworkManager: the device must already have an active connection profile (Wi-Fi: connect first).
- systemd-networkd: a `.network` file named earlier than `05-` that matches the same interface wins.
- Switching to DHCP on dhcpcd/networkd may leave old addresses until the lease is renewed.
- Duplicate-IP check is ping-only: no reply does not prove an address is free.
- x86_64 only; Windows binary is unsigned (SmartScreen may warn); no ARM (Raspberry Pi) build is published yet - build from source on the Pi (`cargo build --release`).
- Windows 10/11 with PowerShell 5.1+ assumed.

## Testing

Run in CI on Ubuntu and Windows (`cargo test`): parsing of `ip -j`, `resolvectl`, and PowerShell JSON output; validation rules; script/YAML/unit generation for every backend; backend detection and duplicate-IP checks via a **mock command runner**; profile/snapshot storage; status handling; base64/encoded-command. **No test changes real network configuration.** The privileged apply/revert scripts are checked by string-level tests, not executed against real adapters.

## License

MIT
