from __future__ import annotations

import ipaddress
import json
import os
import pwd
import re
import select
import shutil
import socket
import struct
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from .models import Device

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
PROBE_INTERVAL = 15
QUIET_AFTER = 45
REMOVE_AFTER = 5 * 60
NEW_FOR = 20

def command(args: list[str], timeout: float = 3) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)

def network_info() -> tuple[str, str, str, str, str]:
    """Return interface, local IP, subnet, gateway, and local Ethernet MAC."""
    if not shutil.which("ip"):
        raise RuntimeError("The 'ip' command is required (iproute2).")
    # Prefer the interface selected by the default route so address discovery
    # and packet capture use the same outbound LAN.
    routes = command(["ip", "-4", "route", "show", "default"]).stdout.splitlines()
    route = routes[0].split() if routes else []
    iface = route[route.index("dev") + 1] if "dev" in route else ""
    gateway = route[route.index("via") + 1] if "via" in route else ""

    args = ["ip", "-4", "-o", "addr", "show", "scope", "global"]
    if iface:
        args += ["dev", iface]
    addresses = command(args).stdout.splitlines()
    if not addresses:
        raise RuntimeError("No global IPv4 address found; connect to the LAN first.")
    fields = addresses[0].split()
    if not iface:
        iface = fields[1]
    interface = ipaddress.ip_interface(fields[3])

    links = command(["ip", "-o", "link", "show", "dev", iface]).stdout
    match = re.search(r"\blink/ether\s+([0-9a-fA-F:]{17})", links)
    if not match:
        raise RuntimeError(f"Could not read the Ethernet/Wi-Fi MAC for {iface}.")
    return iface, str(interface.ip), str(interface.network), gateway, match.group(1).lower()

def user_config_dir() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir) / ".config" / "lantern"
        except KeyError:
            pass
    return Path.home() / ".config" / "lantern"

def load_labels(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {str(mac).lower(): str(label) for mac, label in raw.items()
                    if isinstance(label, str) and label.strip()}
    except (OSError, json.JSONDecodeError):
        pass
    return {}

def save_labels(path: Path, labels: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    if os.geteuid() == 0 and os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
        os.chown(temporary, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    temporary.replace(path)

def reverse_resolve(ip: str) -> str:
    """Resolve a hostname using the system's configured reverse DNS."""
    try:
        name, _aliases, _addresses = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name.rstrip(".")
    except (OSError, socket.herror, socket.gaierror):
        pass
    return ""

class ArpMonitor:
    def __init__(self) -> None:
        self.iface, self.local_ip, cidr, self.gateway, self.local_mac = network_info()
        self.labels_path = user_config_dir() / "labels.json"
        self.labels = load_labels(self.labels_path)
        self.network = ipaddress.ip_network(cidr, strict=False)
        # A full ARP sweep sends one frame per host; bound it to avoid probing
        # unexpectedly large networks by default.
        if self.network.num_addresses > 4096:
            raise RuntimeError(f"Refusing to ARP-probe unusually large subnet {self.network} (>4096 addresses).")
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.bind((self.iface, 0))
            self.sock.setblocking(False)
        except (AttributeError, OSError) as exc:
            raise RuntimeError(
                "Raw ARP listening needs Linux AF_PACKET and CAP_NET_RAW; run with sudo. "
                f"({exc})"
            ) from exc

        now = time.monotonic()
        # MAC addresses are stable across DHCP address changes, unlike IPs.
        self.devices: dict[str, Device] = {
            self.local_mac: Device(mac=self.local_mac, ip=self.local_ip, first_seen=now,
                                   last_seen=now, state="LOCAL", name=socket.gethostname(),
                                   source="local interface", label=self.labels.get(self.local_mac, ""))
        }  # keyed by MAC; handles DHCP IP changes
        for mac, label in self.labels.items():
            if mac != self.local_mac:
                self.devices[mac] = Device(mac=mac, ip="unknown", first_seen=now, last_seen=None,
                                           state="OFFLINE", source="saved device list", label=label)
        self.events: list[str] = []
        offline_inventory = sum(device.state == "OFFLINE" for device in self.devices.values())
        if offline_inventory:
            self.add_event(f"Loaded {offline_inventory} saved labeled device(s); waiting for ARP to confirm status.")
        self.status_message = ""
        self.pending_names: dict[str, Future[str]] = {}
        self.resolver = ThreadPoolExecutor(max_workers=4, thread_name_prefix="arp-resolve")
        self.initialized_at = time.monotonic() + 3
        self.interval = PROBE_INTERVAL
        self.auto_probe = True
        self.next_probe = 0.0
        self.last_sweep = 0.0
        self.last_sweep_sent = 0
        self.send_sweep()

    def close(self) -> None:
        self.sock.close()
        self.resolver.shutdown(wait=False, cancel_futures=True)

    def add_event(self, message: str) -> None:
        stamp = datetime.now().astimezone().strftime("%H:%M:%S")
        self.events.append(f"{stamp}  {message}")
        self.events = self.events[-8:]

    def _remove_stale_devices(self, now: float) -> None:
        for mac, device in list(self.devices.items()):
            # Keep labeled devices as offline inventory; discard only transient discoveries.
            if device.state == "QUIET" and device.last_seen is not None and now - device.last_seen >= REMOVE_AFTER:
                if mac in self.labels:
                    device.state = "OFFLINE"
                    self.add_event(f"{device.label or mac} marked offline after five minutes without ARP.")
                else:
                    del self.devices[mac]
                    self.pending_names.pop(mac, None)
                    self.add_event(f"Removed {device.ip} ({mac}) after five minutes without ARP.")

    def _arp_request(self, target_ip: str) -> bytes:
        src_mac = bytes.fromhex(self.local_mac.replace(":", ""))
        dst_mac = b"\xff" * 6
        ethernet = dst_mac + src_mac + struct.pack("!H", ETH_P_ARP)
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        arp += src_mac + socket.inet_aton(self.local_ip) + b"\x00" * 6 + socket.inet_aton(target_ip)
        return ethernet + arp

    def send_sweep(self) -> None:
        sent = 0
        try:
            for address in self.network.hosts():
                ip = str(address)
                if ip == self.local_ip:
                    continue
                try:
                    self.sock.send(self._arp_request(ip))
                    sent += 1
                except OSError:
                    continue
        finally:
            self.last_sweep = time.monotonic()
            self.last_sweep_sent = sent
            self.next_probe = self.last_sweep + self.interval

    def _schedule_name(self, device: Device) -> None:
        existing = self.pending_names.get(device.mac)
        if existing and not existing.done():
            return
        if not device.name:
            self.pending_names[device.mac] = self.resolver.submit(reverse_resolve, device.ip)

    def _ingest(self, frame: bytes) -> None:
        # Ignore non-ARP and truncated Ethernet/ARP frames before unpacking fields.
        if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
            return
        htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", frame[14:22])
        if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4) or opcode not in (1, 2):
            return
        mac_bytes = frame[22:28]
        ip_bytes = frame[28:32]
        if mac_bytes == b"\x00" * 6 or mac_bytes[0] & 1:
            return
        mac = ":".join(f"{byte:02x}" for byte in mac_bytes)
        if mac == self.local_mac:
            return
        ip = socket.inet_ntoa(ip_bytes)
        try:
            if ipaddress.ip_address(ip) not in self.network or ip == "0.0.0.0":
                return
        except ValueError:
            return

        now = time.monotonic()
        device = self.devices.get(mac)
        if device is None:
            initial = now < self.initialized_at
            device = Device(mac=mac, ip=ip, first_seen=now, last_seen=now,
                            state="ONLINE" if initial else "NEW",
                            source="ARP reply" if opcode == 2 else "ARP request",
                            label=self.labels.get(mac, ""))
            self.devices[mac] = device
            self._schedule_name(device)
            if not initial:
                self.add_event(f"New device {ip} ({mac}) appeared via ARP.")
        else:
            was_offline = device.state in ("QUIET", "OFFLINE")
            if device.last_seen is None:
                device.ip = ip
                device.first_seen = now
                device.name = ""
                self._schedule_name(device)
            elif device.ip != ip:
                old_ip = device.ip
                device.ip = ip
                device.name = ""
                self.pending_names.pop(mac, None)
                self._schedule_name(device)
                self.add_event(f"{mac} changed address {old_ip} → {ip}.")
            if was_offline:
                self.add_event(f"{device.label or ip} is responding to ARP again.")
            device.last_seen = now
            device.state = "ONLINE"
            device.source = "ARP reply" if opcode == 2 else "ARP request"

    def listen(self, timeout: float = 0.35) -> None:
        try:
            ready, _, _ = select.select([self.sock], [], [], timeout)
            if ready:
                # Drain the nonblocking receive queue so bursts do not leave stale frames queued.
                while True:
                    try:
                        frame = self.sock.recv(2048)
                    except BlockingIOError:
                        break
                    self._ingest(frame)
        except (OSError, ValueError):
            pass
        now = time.monotonic()
        for device in self.devices.values():
            if device.state in ("NEW", "ONLINE") and device.last_seen is not None and now - device.last_seen >= QUIET_AFTER:
                device.state = "QUIET"
                self.add_event(f"{device.ip} ({device.mac}) has been quiet for {QUIET_AFTER}s; no ARP heard.")
            elif device.state == "NEW" and now - device.first_seen >= NEW_FOR:
                device.state = "ONLINE"
        self._remove_stale_devices(now)
        for mac, future in list(self.pending_names.items()):
            if future.done():
                try:
                    name = future.result()
                except Exception:
                    name = ""
                if name and mac in self.devices:
                    self.devices[mac].name = name
                del self.pending_names[mac]

    def gateway_device(self) -> Device | None:
        for device in self.devices.values():
            if device.ip == self.gateway:
                return device
        return None

def ago(seconds: float) -> str:
    value = max(0, int(seconds))
    if value < 60:
        return f"{value}s ago"
    return f"{value // 60}m ago"

def seen_when(last_seen: float | None) -> str:
    return "never" if last_seen is None else ago(time.monotonic() - last_seen)

def age_compact(last_seen: float | None) -> str:
    if last_seen is None:
        return "n/a"
    seconds = max(0, int(time.monotonic() - last_seen))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d" if days < 1000 else ">999"

def ordered_devices(monitor: ArpMonitor) -> list[Device]:
    def group_order(device: Device) -> int:
        if device.state == "NEW":
            return 0
        if device.state in ("QUIET", "OFFLINE"):
            return 2
        return 1

    def ip_order(device: Device) -> tuple[int, int]:
        try:
            return 0, int(ipaddress.ip_address(device.ip))
        except ValueError:
            return 1, 0

    return sorted(
        monitor.devices.values(),
        key=lambda d: (group_order(d), d.ip != monitor.gateway, ip_order(d), d.mac),
    )

def filtered_devices(monitor: ArpMonitor, query: str) -> list[Device]:
    devices = ordered_devices(monitor)
    query = query.strip().casefold()
    if not query:
        return devices
    return [device for device in devices if query in " ".join((
        device.label, device.name, device.ip, device.mac,
    )).casefold()]
