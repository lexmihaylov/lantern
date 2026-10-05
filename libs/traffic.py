"""Passive packet capture and bounded flow summaries."""
from __future__ import annotations

import ipaddress
import select
import socket
import struct
import time

from .models import Flow

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
SOL_PACKET = 263
PACKET_VNET_HDR = 15
VNET_HDR_FORMAT = "=BBHHHH"
VNET_HDR_SIZE = struct.calcsize(VNET_HDR_FORMAT)
VNET_HDR_EMPTY = bytes(VNET_HDR_SIZE)
MAX_CAPTURE_SIZE = 128 * 1024


class ArpSpoofSession:
    """Temporary, target-to-gateway ARP interception on the capture socket."""
    REFRESH_INTERVAL = 5.0

    def __init__(self, sock, *, local_ip: str, local_mac: str, target_ip: str,
                 target_mac: str, gateway_ip: str, gateway_mac: str,
                 network: ipaddress.IPv4Network,
                 vnet_hdr_enabled: bool = False) -> None:
        self.sock = sock
        self.vnet_hdr_enabled = vnet_hdr_enabled
        self.local_ip = str(ipaddress.IPv4Address(local_ip))
        self.target_ip = str(ipaddress.IPv4Address(target_ip))
        self.gateway_ip = str(ipaddress.IPv4Address(gateway_ip))
        self.network = network
        self.local_mac = self._mac_bytes(local_mac)
        self.target_mac = self._mac_bytes(target_mac)
        self.target_mac_text = self._mac_text(self.target_mac)
        self.gateway_mac = self._mac_bytes(gateway_mac)
        self.gateway_mac_text = self._mac_text(self.gateway_mac)
        # Interception is valid only when all three participants are distinct
        # hosts on this LAN; reject stale or mismatched monitor state up front.
        if (self.local_ip == self.target_ip or self.local_ip == self.gateway_ip
                or self.target_ip == self.gateway_ip
                or any(ipaddress.IPv4Address(ip) not in network for ip in
                       (self.local_ip, self.target_ip, self.gateway_ip))):
            raise ValueError("Target, gateway, and Lantern must be distinct IPv4 hosts on the same LAN.")
        if len({self.local_mac, self.target_mac, self.gateway_mac}) != 3:
            raise ValueError("Target, gateway, and Lantern must have distinct MAC addresses.")
        self.active = False
        self.needs_restore = False
        self.next_refresh = 0.0
        self.forwarded_packets = 0

    @staticmethod
    def _mac_bytes(value: str) -> bytes:
        try:
            raw = bytes.fromhex(value.replace(":", ""))
        except ValueError as exc:
            raise ValueError("Invalid Ethernet MAC address.") from exc
        if len(raw) != 6 or raw[0] & 1 or raw == b"\x00" * 6:
            raise ValueError("Expected a unicast Ethernet MAC address.")
        return raw

    @staticmethod
    def _mac_text(value: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in value)

    def _arp_reply(self, ethernet_dst: bytes, sender_mac: bytes, sender_ip: str,
                   target_mac: bytes, target_ip: str) -> bytes:
        ethernet = ethernet_dst + sender_mac + struct.pack("!H", ETH_P_ARP)
        arp = struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 2)
        arp += sender_mac + socket.inet_aton(sender_ip) + target_mac + socket.inet_aton(target_ip)
        return ethernet + arp

    def _send_frame(self, frame: bytes, vnet_header: bytes | None = None) -> None:
        # AF_PACKET can prepend virtio-net metadata; every transmitted frame must
        # carry that header when the socket option is enabled.
        if self.vnet_hdr_enabled:
            header = VNET_HDR_EMPTY if vnet_header is None else vnet_header
            if len(header) != VNET_HDR_SIZE:
                raise ValueError("Invalid AF_PACKET virtio-net header length.")
            self.sock.send(header + frame)
        else:
            self.sock.send(frame)

    def _advertise(self, poisoning: bool) -> None:
        if poisoning:
            to_target = (self.target_mac, self.gateway_ip, self.local_mac,
                         self.target_mac, self.target_ip)
            to_gateway = (self.gateway_mac, self.target_ip, self.local_mac,
                          self.gateway_mac, self.gateway_ip)
        else:
            to_target = (self.target_mac, self.gateway_ip, self.gateway_mac,
                         self.target_mac, self.target_ip)
            to_gateway = (self.gateway_mac, self.target_ip, self.target_mac,
                          self.gateway_mac, self.gateway_ip)
        # Update both peers' ARP caches: one maps the gateway through Lantern,
        # the other maps the target through Lantern. Restoration swaps in real MACs.
        frames = (
            self._arp_reply(to_target[0], to_target[2], to_target[1], to_target[3], to_target[4]),
            self._arp_reply(to_gateway[0], to_gateway[2], to_gateway[1], to_gateway[3], to_gateway[4]),
        )
        first_error = None
        for frame in frames:
            try:
                self._send_frame(frame)
            except OSError as exc:
                first_error = first_error or exc
        if first_error:
            raise first_error

    def start(self) -> None:
        if self.active:
            return
        # Mark restoration necessary before sending either frame because the first
        # peer may accept its update even if sending to the second peer fails.
        self.needs_restore = True
        try:
            self._advertise(poisoning=True)
        except OSError as exc:
            try:
                self._advertise(poisoning=False)
                self.needs_restore = False
            except OSError as restore_exc:
                raise RuntimeError(
                    f"Could not start ARP interception or send both peers' correction frames: {restore_exc}"
                ) from exc
            raise
        self.active = True
        self.next_refresh = time.monotonic() + self.REFRESH_INTERVAL

    def refresh(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        if not self.active or now < self.next_refresh:
            return
        self._advertise(poisoning=True)
        self.next_refresh = now + self.REFRESH_INTERVAL

    def stop(self) -> bool:
        """Send restoration frames; success does not confirm peer ARP-cache updates."""
        self.active = False
        if not self.needs_restore:
            return True
        try:
            self._advertise(poisoning=False)
            self.needs_restore = False
            return True
        except OSError:
            return False

    @staticmethod
    def _ipv4_endpoints(frame: bytes) -> tuple[int, str, str] | None:
        if len(frame) < 14:
            return None
        offset = 14
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ethertype != ETH_P_IP or len(frame) < offset + 20:
            return None
        version_ihl = frame[offset]
        header_len = (version_ihl & 0x0F) * 4
        total_len = struct.unpack_from("!H", frame, offset + 2)[0]
        if (version_ihl >> 4 != 4 or header_len < 20 or total_len < header_len
                or len(frame) < offset + total_len):
            return None
        source = socket.inet_ntoa(frame[offset + 12:offset + 16])
        destination = socket.inet_ntoa(frame[offset + 16:offset + 20])
        return offset, source, destination

    def relay_frame(self, frame: bytes, vnet_header: bytes | None = None) -> bool:
        """Relay target<->gateway IPv4 frames, retaining kernel GSO metadata."""
        if not self.active or len(frame) < 14:
            return False
        if self.vnet_hdr_enabled and vnet_header is None:
            raise ValueError("Missing AF_PACKET virtio-net metadata for relay.")
        endpoints = self._ipv4_endpoints(frame)
        if not endpoints:
            return False
        offset, source_ip, destination_ip = endpoints
        ip_length = struct.unpack_from("!H", frame, offset + 2)[0]
        packet_end = offset + ip_length
        destination_mac = frame[:6]
        source_mac = frame[6:12]
        if (source_mac == self.target_mac and destination_mac == self.local_mac
                and source_ip == self.target_ip):
            relay_to = self.gateway_mac
        elif (source_mac == self.gateway_mac and destination_mac == self.local_mac
              and destination_ip == self.target_ip):
            relay_to = self.target_mac
        else:
            return False
        # Drop Ethernet padding/FCS-like trailing bytes; they are not part of the IP datagram.
        relayed = relay_to + self.local_mac + frame[12:packet_end]
        self._send_frame(relayed, vnet_header)
        self.forwarded_packets += 1
        return True


class TrafficCapture:
    """Bounded, in-memory summaries of packets visible on one interface."""
    MAX_FLOWS = 200
    MAX_DNS = 256
    MAX_PENDING_DNS = 128

    def __init__(self, iface: str, target_ip: str) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise RuntimeError("Passive packet capture requires Linux AF_PACKET support.")
        self.target_ip = target_ip
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.vnet_hdr_enabled = False
        self.vnet_hdr_error = ""
        try:
            self.sock.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
            self.vnet_hdr_enabled = True
        except OSError as exc:
            self.vnet_hdr_error = str(exc)
        try:
            self.sock.bind((iface, 0))
            self.sock.setblocking(False)
        except Exception:
            self.sock.close()
            raise
        self.flows: dict[tuple[str, str, str, int, int], Flow] = {}
        self.names: dict[str, tuple[str, float]] = {}
        self.pending_dns: dict[tuple[int, str, str], str] = {}
        self.packet_count = 0
        self.last_packet: float | None = None

    def close(self) -> None:
        self.sock.close()

    def recv_packet(self) -> tuple[bytes, bytes, int, int]:
        """Return Ethernet bytes, vnet header, GSO type, and GSO size."""
        packet = self.sock.recv(MAX_CAPTURE_SIZE)
        if not self.vnet_hdr_enabled:
            return packet, b"", 0, 0
        if len(packet) < VNET_HDR_SIZE + 14:
            raise ValueError("Truncated AF_PACKET virtio-net packet.")
        header = packet[:VNET_HDR_SIZE]
        _flags, gso_type, _hdr_len, gso_size, _csum_start, _csum_offset = struct.unpack(
            VNET_HDR_FORMAT, header
        )
        return packet[VNET_HDR_SIZE:], header, gso_type, gso_size

    @staticmethod
    def _dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
        if depth > 8 or offset >= len(data):
            raise ValueError("invalid DNS name")
        labels: list[str] = []
        end = offset
        jumped = False
        while offset < len(data):
            size = data[offset]
            if size & 0xC0 == 0xC0:
                if offset + 1 >= len(data):
                    raise ValueError("truncated DNS pointer")
                pointer = ((size & 0x3F) << 8) | data[offset + 1]
                # DNS compression pointers may chain; the depth limit above bounds malformed loops.
                suffix, _ = TrafficCapture._dns_name(data, pointer, depth + 1)
                if suffix:
                    labels.append(suffix)
                offset += 2
                if not jumped:
                    end = offset
                jumped = True
                break
            if size & 0xC0 or size > 63:
                raise ValueError("invalid DNS label")
            offset += 1
            if size == 0:
                if not jumped:
                    end = offset
                break
            if offset + size > len(data):
                raise ValueError("truncated DNS label")
            labels.append(data[offset:offset + size].decode("ascii", "replace"))
            offset += size
        return ".".join(labels).rstrip("."), end

    @classmethod
    def parse_dns(cls, data: bytes) -> tuple[int, bool, list[str], list[tuple[str, int]]] | None:
        if len(data) < 12:
            return None
        ident, flags, qd, an, _ns, ar = struct.unpack_from("!HHHHHH", data)
        if qd > 32 or an > 128 or ar > 128:
            return None
        offset = 12
        questions: list[str] = []
        answers: list[tuple[str, int]] = []
        try:
            for _ in range(qd):
                name, offset = cls._dns_name(data, offset)
                if offset + 4 > len(data):
                    return None
                offset += 4
                if name:
                    questions.append(name.casefold())
            for _ in range(an + _ns + ar):
                name, offset = cls._dns_name(data, offset)
                if offset + 10 > len(data):
                    return None
                rtype, _rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
                offset += 10
                if offset + rdlength > len(data):
                    return None
                rdata = data[offset:offset + rdlength]
                if rtype == 1 and rdlength == 4:
                    answers.append((socket.inet_ntoa(rdata), ttl))
                elif rtype == 28 and rdlength == 16:
                    answers.append((socket.inet_ntop(socket.AF_INET6, rdata), ttl))
                offset += rdlength
        except (ValueError, struct.error):
            return None
        return ident, bool(flags & 0x8000), questions, answers

    @staticmethod
    def parse_frame(frame: bytes) -> tuple[str, str, str, int, int, int, bytes] | None:
        if len(frame) < 14:
            return None
        offset = 14
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        # Skip VLAN tag headers (including stacked tags) before parsing IP.
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ethertype == 0x0800:
            if len(frame) < offset + 20:
                return None
            version_ihl = frame[offset]
            ihl = (version_ihl & 0x0F) * 4
            total_len = struct.unpack_from("!H", frame, offset + 2)[0]
            fragment = struct.unpack_from("!H", frame, offset + 6)[0]
            # Non-initial IPv4 fragments lack transport ports, so omit them from flow summaries.
            if version_ihl >> 4 != 4 or ihl < 20 or len(frame) < offset + ihl or total_len < ihl or fragment & 0x1FFF:
                return None
            src = socket.inet_ntoa(frame[offset + 12:offset + 16])
            dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
            proto = frame[offset + 9]
            transport = offset + ihl
            packet_len = min(total_len, len(frame) - offset)
        elif ethertype == 0x86DD:
            if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
                return None
            payload_len = struct.unpack_from("!H", frame, offset + 4)[0]
            src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
            dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
            proto = frame[offset + 6]
            transport = offset + 40
            packet_len = min(40 + payload_len, len(frame) - offset)
            # These IPv6 extension/fragment headers need a chain parser; skip rather
            # than misread their bytes as TCP/UDP ports.
            if proto in (0, 43, 44, 50, 51, 60):
                return None
        else:
            return None
        if proto == 6:
            if packet_len < transport - offset + 20 or len(frame) < transport + 20:
                return None
            sport, dport = struct.unpack_from("!HH", frame, transport)
            data_offset = (frame[transport + 12] >> 4) * 4
            if data_offset < 20 or transport + data_offset > len(frame):
                return None
            payload = frame[transport + data_offset:offset + packet_len]
            protocol = "TCP"
        elif proto == 17:
            if packet_len < transport - offset + 8 or len(frame) < transport + 8:
                return None
            sport, dport, udp_len = struct.unpack_from("!HHH", frame, transport)
            if udp_len < 8:
                return None
            payload = frame[transport + 8:min(transport + udp_len, offset + packet_len)]
            protocol = "UDP"
        else:
            return None
        return src, dst, protocol, sport, dport, packet_len, payload

    def ingest(self, frame: bytes, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        parsed = self.parse_frame(frame)
        if not parsed:
            return
        src, dst, protocol, sport, dport, byte_count, payload = parsed
        if self.target_ip not in (src, dst):
            return
        self.packet_count += 1
        self.last_packet = now
        key = (src, dst, protocol, sport, dport)
        flow = self.flows.get(key)
        if flow is None:
            # Keep memory bounded during long captures by evicting the least-recent flow.
            if len(self.flows) >= self.MAX_FLOWS:
                oldest = min(self.flows, key=lambda item: self.flows[item].last_seen)
                del self.flows[oldest]
            flow = self.flows[key] = Flow(src, dst, protocol, sport, dport, 0, 0, now)
        flow.packets += 1
        flow.byte_count += byte_count
        flow.last_seen = now

        if protocol == "UDP" and (sport == 53 or dport == 53):
            dns = self.parse_dns(payload)
            if not dns:
                return
            ident, is_response, questions, answers = dns
            if not is_response and questions:
                self.pending_dns[(ident, src, dst)] = questions[0]
                if len(self.pending_dns) > self.MAX_PENDING_DNS:
                    self.pending_dns.pop(next(iter(self.pending_dns)))
            elif is_response:
                question = self.pending_dns.pop((ident, dst, src), "") or (questions[0] if questions else "")
                for address, ttl in answers:
                    if question and ttl > 0:
                        # DNS answers are temporary hints; cap them and expire each at its TTL.
                        if len(self.names) >= self.MAX_DNS and address not in self.names:
                            oldest = min(self.names, key=lambda item: self.names[item][1])
                            del self.names[oldest]
                        self.names[address] = (question, now + min(ttl, 86400))

    def names_for(self, ip: str, now: float | None = None) -> str:
        now = time.monotonic() if now is None else now
        entry = self.names.get(ip)
        if entry and entry[1] > now:
            return entry[0]
        self.names.pop(ip, None)
        return ""

