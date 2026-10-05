from concurrent.futures import Future
import unittest

from lantern.libs.models import Flow
from lantern.libs.traffic_view import (
    _terminal_cell_width,
    format_traffic_header,
    format_traffic_row,
    group_traffic_flows,
    RuntimeEndpointNames,
    traffic_table_layout,
)


class TrafficTableLayoutTests(unittest.TestCase):
    def test_runtime_ptr_names_are_async_and_only_requested_once(self):
        class FakeExecutor:
            def __init__(self):
                self.futures = {}

            def submit(self, _fn, ip):
                future = Future()
                self.futures[ip] = future
                return future

        executor = FakeExecutor()
        resolver = RuntimeEndpointNames(executor)
        self.assertEqual(resolver.update(["1.1.1.1"]), {})
        executor.futures["1.1.1.1"].set_result("one.one.one.one")

        names = resolver.update(["1.1.1.1", "1.1.1.1"])

        self.assertEqual(names, {"1.1.1.1": "one.one.one.one"})
        self.assertEqual(len(executor.futures), 1)
        resolver.close()

    def test_flows_to_same_remote_ip_and_port_become_one_endpoint(self):
        flows = [
            Flow("192.168.1.10", "1.1.1.1", "TCP", 41000, 443, 2, 1200, 10.0),
            Flow("192.168.1.10", "1.1.1.1", "TCP", 41001, 443, 3, 1800, 12.0),
            Flow("1.1.1.1", "192.168.1.10", "UDP", 443, 53000, 1, 200, 11.0),
            Flow("192.168.1.10", "1.1.1.1", "TCP", 41000, 80, 4, 800, 13.0),
            Flow("192.168.1.10", "9.9.9.9", "TCP", 41000, 443, 1, 100, 9.0),
        ]

        endpoints = group_traffic_flows(flows, "192.168.1.10")

        by_key = {(endpoint.ip, endpoint.port): endpoint for endpoint in endpoints}
        self.assertEqual(len(endpoints), 3)
        https = by_key[("1.1.1.1", 443)]
        self.assertEqual(https.protocols, {"TCP", "UDP"})
        self.assertEqual(https.packets, 6)
        self.assertEqual(https.byte_count, 3200)
        self.assertEqual(https.last_seen, 12.0)

    def test_wide_table_columns_align_under_headers(self):
        layout = traffic_table_layout(120, packet_width=9, byte_width=11, last_width=10)
        header = format_traffic_header(layout)
        row = format_traffic_row("sensor.lan:443", "TCP", "123456789", "98765432100", "12m ago", layout)[0]
        self.assertEqual(layout.mode, "wide")
        self.assertEqual(_terminal_cell_width(header), layout.content_width)
        self.assertEqual(_terminal_cell_width(row), layout.content_width)

        protocol_start = layout.remote_width + 2
        packets_start = protocol_start + 8 + 2
        bytes_start = packets_start + layout.packet_width + 2
        last_start = bytes_start + layout.byte_width + 2
        self.assertEqual(header[protocol_start:protocol_start + 8], "PROTOCOL")
        self.assertEqual(header[packets_start:packets_start + layout.packet_width], "PACKETS".rjust(layout.packet_width))
        self.assertEqual(header[bytes_start:bytes_start + layout.byte_width], "BYTES".rjust(layout.byte_width))
        self.assertEqual(header[last_start:last_start + layout.last_width], "LAST SEEN".rjust(layout.last_width))
        self.assertEqual(row[protocol_start:protocol_start + 8], "TCP     ")
        self.assertEqual(row[packets_start:packets_start + layout.packet_width], "123456789")

    def test_wide_layout_keeps_last_seen_with_scrollbar_gutter_width(self):
        layout = traffic_table_layout(54)

        self.assertEqual(layout.mode, "wide")
        self.assertEqual(layout.last_width, 9)
        self.assertIn("LAST SEEN", format_traffic_header(layout))

    def test_medium_and_narrow_layouts_drop_lower_priority_columns(self):
        medium = traffic_table_layout(50)
        narrow = traffic_table_layout(42)
        self.assertEqual(medium.mode, "medium")
        self.assertEqual(medium.byte_width, 5)
        self.assertEqual(medium.last_width, 0)
        self.assertEqual(narrow.mode, "narrow")
        self.assertEqual(narrow.byte_width, 0)
        self.assertEqual(narrow.last_width, 0)
        narrow_header = format_traffic_header(narrow)
        narrow_row = format_traffic_row("device:53", "UDP", "12", "900", "4s ago", narrow)[0]
        self.assertNotIn("BYTES", narrow_header)
        self.assertEqual(_terminal_cell_width(format_traffic_header(medium)), medium.content_width)
        self.assertEqual(_terminal_cell_width(narrow_header), narrow.content_width)
        self.assertEqual(narrow_header.index("PROTOCOL"), narrow_row.index("UDP"))

    def test_long_remote_name_is_truncated_without_shifting_columns(self):
        layout = traffic_table_layout(50)
        header = format_traffic_header(layout)
        row = format_traffic_row("very-long-device-name.example:443", "TCP", "12", "9000", "4s ago", layout)[0]
        self.assertLessEqual(_terminal_cell_width(row), layout.content_width)
        self.assertIn("…", row)
        self.assertEqual(header.index("PROTOCOL"), row.index("TCP"))

    def test_small_width_switches_to_two_line_flow_cards(self):
        layout = traffic_table_layout(28)
        lines = format_traffic_row("192.168.0.104:53", "UDP", "12", "900", "4s ago", layout)
        self.assertEqual(layout.mode, "stacked")
        self.assertEqual(len(lines), 2)
        self.assertLessEqual(max(map(_terminal_cell_width, lines)), layout.content_width)
        self.assertIn("UDP", lines[0])
        self.assertIn("pkts", lines[1])

    def test_unicode_service_names_use_terminal_cell_width(self):
        layout = traffic_table_layout(50)
        row = format_traffic_row("東京" * 20, "TCP", "1", "100", "1s ago", layout)[0]
        self.assertLessEqual(_terminal_cell_width(row), layout.content_width)
        self.assertIn("…", row)


if __name__ == "__main__":
    unittest.main()
