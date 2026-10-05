# Lantern

Lantern is a terminal-based IPv4 LAN device monitor for Linux. It observes ARP traffic, shows devices seen on the local network, and can save user-assigned device labels. Optional tools provide ping checks and Nmap scans. A separate, explicitly confirmed feature can temporarily intercept one device's IPv4 traffic through the gateway to summarize visible flows.

> **Use responsibly.** Only monitor networks and devices you own or are authorized to assess. ARP interception changes peer ARP caches and can interrupt connectivity. It does not decrypt HTTPS. Stop interception from Lantern when finished; restoration frames are best-effort and cannot guarantee that peers updated their ARP caches.

## Requirements

- Linux with `AF_PACKET` support (Lantern is not supported on macOS or Windows).
- Python 3.10 or newer.
- `ip` from `iproute2` to discover the active IPv4 interface, address, subnet, gateway, and MAC address.
- An interactive terminal with `curses` support. Some Linux distributions package this separately (for example, `python3-curses`).
- Permission to open raw packet sockets. The documented setup runs Lantern with `sudo`; administrators may configure a narrower, system-managed permission if appropriate for their environment.
- Optional: `ping` for ICMP checks and `nmap` for version-light scans of the selected device's top 20 ports. These features report when their executable is unavailable.

Lantern has **no third-party Python runtime dependencies**; its application code uses the standard library.

## Install and run

Clone the repository and enter its directory:

```sh
git clone <repository-url>
cd lantern
```

The `lantern` launcher is included and marked executable. If that permission was not preserved by your copy or download, make it executable and run it from the project directory:

```sh
chmod +x ./lantern
sudo ./lantern
```

No virtual environment or package installation is required to run from the checkout. Lantern stores labels in `~/.config/lantern/labels.json` for the invoking user, including when launched through `sudo`. If your system grants the process raw-socket permission without `sudo`, run `./lantern` directly.

## Optional: install in a virtual environment

A virtual environment is not required to run `./lantern`. Use one if you want an isolated editable install and a `lantern` command:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --editable .
sudo .venv/bin/lantern
```

Some Linux distributions package `venv` separately (for example, as `python3-venv`). To remove this installation, delete `.venv`.

## Features

- Discovers the IPv4 interface selected by the system's default route and ARP-observed LAN devices.
- Tracks devices by MAC address so a DHCP address change does not create a second saved identity.
- Shows new, online, quiet, and offline labeled devices; reverse DNS names are resolved using the system resolver.
- Saves labels locally, keyed by MAC address; labels are not uploaded by Lantern.
- Offers optional ping and Nmap actions for the selected device.
- Shows bounded, in-memory TCP/UDP flow summaries for traffic visible on the selected interface. DNS names are learned from observed DNS answers and expire according to their TTL.
- Offers confirmed, temporary target-to-gateway IPv4 ARP interception from the traffic view. It does not enable IP forwarding system-wide or persist packet captures to disk.

Packet visibility depends on the interface, network topology, operating system, and traffic encryption. On switched networks, ordinary passive capture usually sees only traffic to/from the local machine; the optional interception feature changes that behavior for one selected target and gateway.

## Controls

Press `?` in Lantern for the full in-app help. The main view supports device selection, filtering, device details, immediate/periodic ARP sweeps, ping, Nmap, labels, and a traffic view. In the traffic view, `s` opens a separate confirmation before starting or stopping ARP interception.

## Development and tests

To run the test suite from a standalone checkout, first install Lantern in editable mode using the optional virtual-environment steps above, then use Python's standard-library test runner:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use fake sockets and deterministic fixtures; they do not open raw sockets or scan a real network. The GitHub Actions workflow runs the test suite on supported Python versions.

## Configuration and privacy

Lantern stores only device labels in `~/.config/lantern/labels.json`, with restrictive file permissions. Packet and flow summaries are held in memory for the current session. Lantern does not phone home or send telemetry. System DNS lookups, ping, and Nmap use the local machine's normal system/network configuration.

## License

Lantern is distributed under the MIT License. See [LICENSE](LICENSE).
