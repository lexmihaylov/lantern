import ipaddress
import socket
import struct
import unittest
from unittest.mock import patch

from lantern.libs.network import reverse_resolve

from lantern.libs.traffic import (
    PACKET_VNET_HDR,
    SOL_PACKET,
    VNET_HDR_EMPTY,
    VNET_HDR_FORMAT,
    VNET_HDR_SIZE,
    ArpSpoofSession,
    TrafficCapture,
)


LOCAL = bytes.fromhex("020000000002")
TARGET = bytes.fromhex("02000000000a")
GATEWAY = bytes.fromhex("020000000001")


class FakeSocket:
    def __init__(self, fail_vnet_header=False):
        self.sent = []
        self.options = []
        self.fail_next = False
        self.fail_vnet_header = fail_vnet_header

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))
        if self.fail_vnet_header and (level, option) == (SOL_PACKET, PACKET_VNET_HDR):
            raise OSError("unsupported packet metadata")

    def bind(self, _address):
        pass

    def setblocking(self, _blocking):
        pass

    def close(self):
        pass

    def send(self, frame):
        if self.fail_next:
            self.fail_next = False
            raise OSError("simulated send failure")
        self.sent.append(frame)
        return len(frame)


class FakeReceiveSocket:
    def __init__(self, packet):
        self.packet = packet

    def recv(self, _size):
        return self.packet


def make_session(sock=None, vnet_hdr_enabled=False):
    return ArpSpoofSession(
        sock or FakeSocket(), local_ip="192.168.1.2", local_mac="02:00:00:00:00:02",
        target_ip="192.168.1.10", target_mac="02:00:00:00:00:0a",
        gateway_ip="192.168.1.1", gateway_mac="02:00:00:00:00:01",
        network=ipaddress.ip_network("192.168.1.0/24"),
        vnet_hdr_enabled=vnet_hdr_enabled,
    )


def ipv4_frame(eth_dst, eth_src, ip_src, ip_dst, payload=b""):
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, 6, 0,
        socket.inet_aton(ip_src), socket.inet_aton(ip_dst),
    )
    return eth_dst + eth_src + struct.pack("!H", 0x0800) + ip + payload


class ReverseResolveTests(unittest.TestCase):
    @patch("lantern.libs.network.socket.getaddrinfo")
    @patch("lantern.libs.network.socket.gethostbyaddr", side_effect=OSError("no PTR record"))
    def test_missing_ptr_record_does_not_use_site_specific_hostnames(self, _gethostbyaddr, getaddrinfo):
        self.assertEqual(reverse_resolve("192.0.2.1"), "")
        getaddrinfo.assert_not_called()


class ArpSpoofSessionTests(unittest.TestCase):
    def test_start_sends_both_poison_mappings_and_stop_restores_them(self):
        sock = FakeSocket()
        session = make_session(sock)
        self.assertEqual(sock.sent, [])
        session.start()
        self.assertTrue(session.active)
        self.assertEqual(len(sock.sent), 2)

        self.assertEqual(sock.sent[0][:6], TARGET)
        self.assertEqual(sock.sent[1][:6], GATEWAY)
        target_arp = sock.sent[0][14:]
        gateway_arp = sock.sent[1][14:]
        self.assertEqual(struct.unpack_from("!H", target_arp, 6)[0], 2)
        self.assertEqual(target_arp[8:14], LOCAL)
        self.assertEqual(socket.inet_ntoa(target_arp[14:18]), "192.168.1.1")
        self.assertEqual(target_arp[18:24], TARGET)
        self.assertEqual(socket.inet_ntoa(target_arp[24:28]), "192.168.1.10")
        self.assertEqual(gateway_arp[8:14], LOCAL)
        self.assertEqual(socket.inet_ntoa(gateway_arp[14:18]), "192.168.1.10")
        self.assertEqual(gateway_arp[18:24], GATEWAY)
        self.assertEqual(socket.inet_ntoa(gateway_arp[24:28]), "192.168.1.1")

        self.assertTrue(session.stop())
        self.assertFalse(session.active)
        self.assertEqual(len(sock.sent), 4)
        self.assertEqual(sock.sent[2][6:12], GATEWAY)
        self.assertEqual(sock.sent[2][22:28], GATEWAY)
        self.assertEqual(sock.sent[3][6:12], TARGET)
        self.assertEqual(sock.sent[3][22:28], TARGET)

    def test_refresh_is_rate_limited(self):
        sock = FakeSocket()
        session = make_session(sock)
        session.start()
        self.assertEqual(len(sock.sent), 2)
        session.refresh(session.next_refresh - 0.01)
        self.assertEqual(len(sock.sent), 2)
        session.refresh(session.next_refresh)
        self.assertEqual(len(sock.sent), 4)

    def test_relay_only_forwards_target_gateway_ipv4_frames(self):
        sock = FakeSocket()
        session = make_session(sock)
        session.start()
        sock.sent.clear()

        outbound = ipv4_frame(LOCAL, TARGET, "192.168.1.10", "1.1.1.1")
        self.assertTrue(session.relay_frame(outbound))
        self.assertEqual(sock.sent[-1][:6], GATEWAY)
        self.assertEqual(sock.sent[-1][6:12], LOCAL)
        self.assertEqual(sock.sent[-1][14:], outbound[14:])

        padded = outbound + b"\x00" * 32
        self.assertTrue(session.relay_frame(padded))
        self.assertEqual(sock.sent[-1], GATEWAY + LOCAL + outbound[12:])

        inbound = ipv4_frame(LOCAL, GATEWAY, "1.1.1.1", "192.168.1.10")
        self.assertTrue(session.relay_frame(inbound))
        self.assertEqual(sock.sent[-1][:6], TARGET)
        self.assertEqual(sock.sent[-1][6:12], LOCAL)
        self.assertEqual(session.forwarded_packets, 3)

        unrelated = ipv4_frame(LOCAL, TARGET, "192.168.1.11", "1.1.1.1")
        self.assertFalse(session.relay_frame(unrelated))
        self.assertFalse(session.relay_frame(b"short"))
        self.assertEqual(session.forwarded_packets, 3)

    def test_vnet_header_preserved_for_gso_relay_and_added_to_arp(self):
        sock = FakeSocket()
        session = make_session(sock, vnet_hdr_enabled=True)
        session.start()
        self.assertEqual(sock.sent[0][:VNET_HDR_SIZE], VNET_HDR_EMPTY)
        self.assertEqual(sock.sent[0][VNET_HDR_SIZE:VNET_HDR_SIZE + 6], TARGET)
        sock.sent.clear()

        gso_header = struct.pack(VNET_HDR_FORMAT, 1, 1, 54, 1460, 34, 16)
        tcp = struct.pack("!HHIIHHHH", 1234, 443, 100, 1, 0x5010, 65535, 0, 0)
        aggregate = ipv4_frame(LOCAL, TARGET, "192.168.1.10", "1.1.1.1", tcp + b"x" * 2400)
        with self.assertRaisesRegex(ValueError, "Missing.*metadata"):
            session.relay_frame(aggregate)
        self.assertTrue(session.relay_frame(aggregate, gso_header))
        self.assertEqual(sock.sent[-1], gso_header + GATEWAY + LOCAL + aggregate[12:])

        session.stop()
        self.assertEqual(sock.sent[-2][:VNET_HDR_SIZE], VNET_HDR_EMPTY)
        self.assertEqual(sock.sent[-1][:VNET_HDR_SIZE], VNET_HDR_EMPTY)

    def test_capture_enables_vnet_metadata(self):
        sock = FakeSocket()
        with patch("lantern.libs.traffic.socket.socket", return_value=sock):
            capture = TrafficCapture("test0", "192.168.1.10")
        self.assertTrue(capture.vnet_hdr_enabled)
        self.assertIn((SOL_PACKET, PACKET_VNET_HDR, 1), sock.options)

    def test_capture_falls_back_to_passive_without_vnet_support(self):
        sock = FakeSocket(fail_vnet_header=True)
        with patch("lantern.libs.traffic.socket.socket", return_value=sock):
            capture = TrafficCapture("test0", "192.168.1.10")
        self.assertFalse(capture.vnet_hdr_enabled)
        self.assertIn("unsupported", capture.vnet_hdr_error)

    def test_capture_splits_vnet_header_from_ethernet_frame(self):
        frame = ipv4_frame(LOCAL, TARGET, "192.168.1.10", "1.1.1.1")
        header = struct.pack(VNET_HDR_FORMAT, 1, 1, 54, 1460, 34, 16)
        capture = object.__new__(TrafficCapture)
        capture.sock = FakeReceiveSocket(header + frame)
        capture.vnet_hdr_enabled = True
        received_frame, received_header, gso_type, gso_size = capture.recv_packet()
        self.assertEqual(received_frame, frame)
        self.assertEqual(received_header, header)
        self.assertEqual((gso_type, gso_size), (1, 1460))

    def test_rejects_truncated_vnet_header(self):
        capture = object.__new__(TrafficCapture)
        capture.sock = FakeReceiveSocket(b"short")
        capture.vnet_hdr_enabled = True
        with self.assertRaises(ValueError):
            capture.recv_packet()

    def test_rejects_addresses_outside_lan(self):
        with self.assertRaises(ValueError):
            ArpSpoofSession(
                FakeSocket(), local_ip="192.168.1.2", local_mac="02:00:00:00:00:02",
                target_ip="192.168.2.10", target_mac="02:00:00:00:00:0a",
                gateway_ip="192.168.1.1", gateway_mac="02:00:00:00:00:01",
                network=ipaddress.ip_network("192.168.1.0/24"),
            )

    def test_partial_start_failure_attempts_restoration(self):
        sock = FakeSocket()
        sock.fail_next = True
        session = make_session(sock)
        with self.assertRaises(OSError):
            session.start()
        self.assertFalse(session.active)
        self.assertEqual(len(sock.sent), 3)
        self.assertEqual(sock.sent[-2][6:12], GATEWAY)
        self.assertEqual(sock.sent[-1][6:12], TARGET)

    def test_failed_relay_stop_still_attempts_both_restoration_frames(self):
        sock = FakeSocket()
        session = make_session(sock)
        session.start()
        sock.fail_next = True
        self.assertFalse(session.stop())
        self.assertFalse(session.active)
        self.assertTrue(session.needs_restore)
        self.assertEqual(len(sock.sent), 3)
        self.assertTrue(session.stop())
        self.assertFalse(session.needs_restore)
        self.assertEqual(len(sock.sent), 5)


if __name__ == "__main__":
    unittest.main()
