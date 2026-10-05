import unittest
from unittest.mock import patch

from lantern.libs.models import Device
from lantern.libs.probes import ping_device, scan_device


class FakeMonitor:
    def __init__(self):
        self.status_message = ""
        self.events = []

    def add_event(self, message):
        self.events.append(message)


def make_device(ip):
    return Device(mac="02:00:00:00:00:01", ip=ip, first_seen=0, last_seen=0)


class ProbePreflightTests(unittest.TestCase):
    @patch("lantern.libs.probes.text_modal")
    def test_ping_rejects_saved_device_without_observed_ipv4(self, show_modal):
        device = make_device("unknown")
        monitor = FakeMonitor()

        ping_device(None, device, monitor)

        self.assertIn("No IPv4 address", device.ping_result)
        self.assertEqual(monitor.status_message, device.ping_result)
        show_modal.assert_called_once()

    @patch("lantern.libs.probes.text_modal")
    @patch("lantern.libs.probes.shutil.which", return_value=None)
    def test_ping_reports_missing_system_command(self, _which, show_modal):
        device = make_device("192.0.2.10")
        monitor = FakeMonitor()

        ping_device(None, device, monitor)

        self.assertEqual(device.ping_result, "The ping command is not installed.")
        show_modal.assert_called_once()

    @patch("lantern.libs.probes.text_modal")
    @patch("lantern.libs.probes.shutil.which", return_value=None)
    def test_scan_reports_missing_nmap(self, _which, show_modal):
        device = make_device("192.0.2.10")
        monitor = FakeMonitor()

        scan_device(None, device, monitor)

        self.assertEqual(monitor.status_message, "Nmap unavailable; ARP discovery is unaffected.")
        show_modal.assert_called_once()


if __name__ == "__main__":
    unittest.main()
