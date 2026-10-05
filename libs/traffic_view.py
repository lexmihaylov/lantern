"""Traffic screen, table layout, and temporary ARP interception controls."""
from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import dataclass
import curses
import select
import time
import unicodedata

from .models import Device, Flow
from .network import ArpMonitor, QUIET_AFTER, ago, reverse_resolve
from .traffic import ArpSpoofSession, TrafficCapture
from .ui_components import scrollbar, style
from .ui_components.modal import make_modal
from .ui_components.text_modal import text_modal

def confirm_arp_spoof(stdscr, target: Device, gateway: Device) -> bool:
    window = make_modal(stdscr, 10, 76)
    window.timeout(-1)
    while True:
        window.erase()
        window.box()
        height, width = window.getmaxyx()
        lines = [
            "This temporarily redirects IPv4 traffic through Lantern.",
            "Only continue on a network you own or are authorized to monitor.",
            f"Target: {target.label or target.name or target.mac} · {target.ip} · {target.mac}",
            f"Gateway: {gateway.ip} · {gateway.mac}",
            "Traffic may be interrupted; HTTPS contents remain encrypted.",
        ]
        for row, text in enumerate(lines, 1):
            if row < height - 2:
                window.addnstr(row, 2, text, max(1, width - 4))
        if height > 2:
            window.addnstr(height - 2, 2, "y/Enter start · n/Esc cancel", max(1, width - 4))
        window.refresh()
        key = window.getch()
        if key in (ord("y"), ord("Y"), 10, 13, curses.KEY_ENTER):
            return True
        if key in (ord("n"), ord("N"), ord("q"), 27):
            return False

def toggle_arp_spoof(stdscr, monitor: ArpMonitor, selected_mac: str,
                     capture: TrafficCapture,
                     session: ArpSpoofSession | None) -> ArpSpoofSession | None:
    if session and (session.active or session.needs_restore):
        restored = session.stop()
        monitor.status_message = (
            "ARP interception stopped; restoration frames sent, peer caches unverified."
            if restored else "ARP interception stopped, but restoration sends failed; press s to retry."
        )
        return None if restored else session

    if not capture.vnet_hdr_enabled:
        detail = f" ({capture.vnet_hdr_error})" if capture.vnet_hdr_error else ""
        monitor.status_message = f"Cannot start ARP interception: PACKET_VNET_HDR is unavailable{detail}."
        return None

    target = monitor.devices.get(selected_mac)
    gateway = monitor.gateway_device()
    now = time.monotonic()
    if (not target or not gateway or target.mac == monitor.local_mac
            or target.ip in ("", "unknown", monitor.gateway)
            or gateway.ip != monitor.gateway
            or target.state not in ("NEW", "ONLINE")
            or gateway.state not in ("NEW", "ONLINE")
            or target.last_seen is None or now - target.last_seen > QUIET_AFTER
            or gateway.last_seen is None or now - gateway.last_seen > QUIET_AFTER):
        monitor.status_message = "Cannot spoof ARP: target and gateway must have fresh, observed LAN IP/MAC mappings."
        return None
    try:
        session = ArpSpoofSession(
            capture.sock, local_ip=monitor.local_ip, local_mac=monitor.local_mac,
            target_ip=target.ip, target_mac=target.mac,
            gateway_ip=gateway.ip, gateway_mac=gateway.mac, network=monitor.network,
            vnet_hdr_enabled=capture.vnet_hdr_enabled,
        )
    except ValueError as exc:
        monitor.status_message = f"Cannot start ARP interception: {exc}"
        return None
    if not confirm_arp_spoof(stdscr, target, gateway):
        monitor.status_message = "ARP interception cancelled."
        return None
    # Confirmation is interactive and may take a while; check that both ARP
    # observations are still fresh immediately before changing peer caches.
    now = time.monotonic()
    if (target.last_seen is None or gateway.last_seen is None
            or now - target.last_seen > QUIET_AFTER or now - gateway.last_seen > QUIET_AFTER):
        monitor.status_message = "Cannot start ARP interception: target or gateway mapping became stale."
        return None
    try:
        session.start()
    except (OSError, RuntimeError) as exc:
        monitor.status_message = f"Could not start ARP interception: {exc}"
        return session if session.needs_restore else None
    monitor.status_message = f"ARP interception active for {target.ip} via {gateway.ip}; press s to stop."
    return session

class RuntimeEndpointNames:
    """Resolve endpoint PTR names without blocking curses, once per traffic view."""

    MAX_LOOKUPS = 128
    MAX_PENDING = 16

    def __init__(self, executor: Executor) -> None:
        self.executor = executor
        self.names: dict[str, str] = {}
        self.pending: dict[str, Future[str]] = {}
        self.requested: set[str] = set()

    def update(self, addresses: Iterable[str]) -> dict[str, str]:
        for ip, future in list(self.pending.items()):
            if future.done():
                self.pending.pop(ip)
                try:
                    name = future.result()
                except Exception:
                    name = ""
                if name:
                    self.names[ip] = name

        for ip in addresses:
            if ip in self.requested:
                continue
            if len(self.requested) >= self.MAX_LOOKUPS or len(self.pending) >= self.MAX_PENDING:
                break
            self.requested.add(ip)
            try:
                self.pending[ip] = self.executor.submit(reverse_resolve, ip)
            except RuntimeError:
                break
        return self.names

    def close(self) -> None:
        for future in self.pending.values():
            future.cancel()
        self.pending.clear()

@dataclass
class TrafficEndpoint:
    ip: str
    port: int
    protocols: set[str]
    packets: int = 0
    byte_count: int = 0
    last_seen: float = 0.0

@dataclass(frozen=True)
class TrafficTableLayout:
    mode: str
    content_width: int
    remote_width: int
    packet_width: int
    byte_width: int
    last_width: int

def _terminal_cell_width(text: str) -> int:
    return sum(
        0 if unicodedata.combining(char) or unicodedata.category(char) in ("Cf", "Mn", "Me")
        else 2 if unicodedata.east_asian_width(char) in ("W", "F")
        else 1
        for char in text
    )

def _fit_terminal_cell(text: str, width: int, *, right: bool = False) -> str:
    if width <= 0:
        return ""
    chars: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char in "\r\n\t":
            chars.append(" ")
        elif category in ("Cc", "Cs") or (category == "Cf" and char != "\u200d"):
            chars.append("�")
        else:
            chars.append(char)
    text = "".join(chars)
    if _terminal_cell_width(text) > width:
        if right:
            kept: list[str] = []
            used = 0
            for char in reversed(text):
                char_width = _terminal_cell_width(char)
                if used + char_width > width - 1:
                    break
                kept.append(char)
                used += char_width
            text = "…" + "".join(reversed(kept))
        else:
            kept = []
            used = 0
            for char in text:
                char_width = _terminal_cell_width(char)
                if used + char_width > width - 1:
                    break
                kept.append(char)
                used += char_width
            text = "".join(kept) + "…"
    padding = " " * max(0, width - _terminal_cell_width(text))
    return padding + text if right else text + padding

def group_traffic_flows(flows: Iterable[Flow], target_ip: str) -> list[TrafficEndpoint]:
    grouped: dict[tuple[str, int], TrafficEndpoint] = {}
    for flow in flows:
        if flow.source == target_ip:
            remote, port = flow.destination, flow.destination_port
        elif flow.destination == target_ip:
            remote, port = flow.source, flow.source_port
        else:
            continue
        key = (remote, port)
        endpoint = grouped.get(key)
        if endpoint is None:
            endpoint = grouped[key] = TrafficEndpoint(remote, port, set())
        endpoint.protocols.add(flow.protocol)
        endpoint.packets += flow.packets
        endpoint.byte_count += flow.byte_count
        endpoint.last_seen = max(endpoint.last_seen, flow.last_seen)
    return sorted(grouped.values(), key=lambda endpoint: endpoint.last_seen, reverse=True)

def traffic_table_layout(terminal_width: int, packet_width: int = 7,
                         byte_width: int = 5, last_width: int = 9) -> TrafficTableLayout:
    content_width = max(1, terminal_width - 2)
    packet_width = max(7, packet_width)
    byte_width = max(5, byte_width)
    last_width = max(9, last_width)
    candidates = (
        ("wide", 8 + packet_width + byte_width + last_width + 8, 15, byte_width, last_width),
        ("medium", 8 + packet_width + byte_width + 6, 16, byte_width, 0),
        ("narrow", 8 + packet_width + 4, 10, 0, 0),
    )
    for mode, fixed_width, min_remote, visible_bytes, visible_last in candidates:
        remote_width = content_width - fixed_width
        if remote_width >= min_remote:
            return TrafficTableLayout(
                mode, content_width, remote_width, packet_width, visible_bytes, visible_last
            )
    return TrafficTableLayout("stacked", content_width, 0, packet_width, 0, 0)

def _format_traffic_cells(fields: list[tuple[str, int, bool]]) -> str:
    return "  ".join(
        _fit_terminal_cell(value, width, right=right)
        for value, width, right in fields
    )

def format_traffic_header(layout: TrafficTableLayout) -> str:
    if layout.mode == "stacked":
        return "COMPACT FLOWS"
    fields = [("REMOTE / SERVICE" if layout.mode != "narrow" else "REMOTE", layout.remote_width, False),
              ("PROTOCOL", 8, False), ("PACKETS", layout.packet_width, True)]
    if layout.byte_width:
        fields.append(("BYTES", layout.byte_width, True))
    if layout.last_width:
        fields.append(("LAST SEEN", layout.last_width, True))
    return _format_traffic_cells(fields)

def format_traffic_row(remote: str, protocol: str, packets: str, byte_count: str,
                       last_seen: str, layout: TrafficTableLayout) -> list[str]:
    if layout.mode == "stacked":
        return [
            _fit_terminal_cell(f"{remote} · {protocol}", layout.content_width),
            _fit_terminal_cell(f"{packets} pkts · {byte_count} B · {last_seen}", layout.content_width),
        ]
    fields = [(remote, layout.remote_width, False), (protocol, 8, False),
              (packets, layout.packet_width, True)]
    if layout.byte_width:
        fields.append((byte_count, layout.byte_width, True))
    if layout.last_width:
        fields.append((last_seen, layout.last_width, True))
    return [_format_traffic_cells(fields)]

def restoration_failure_modal(stdscr) -> str:
    """Ask whether to retry a failed ARP correction or leave anyway."""
    window = make_modal(stdscr, 9, 76)
    window.timeout(-1)
    while True:
        window.erase()
        window.box()
        height, width = window.getmaxyx()
        lines = [
            "Lantern could not send all ARP restoration frames.",
            "The target or gateway may retain a stale ARP entry.",
            "r retries · Esc returns to traffic view · q leaves after final retries",
        ]
        for row, text in enumerate(lines, 1):
            if row < height - 2:
                window.addnstr(row, 2, text, max(1, width - 4))
        window.refresh()
        key = window.getch()
        if key in (ord("r"), ord("R")):
            return "retry"
        if key in (ord("q"), ord("Q")):
            return "force"
        if key in (27, ord("n"), ord("N")):
            return "return"


def _restore_with_retries(session: ArpSpoofSession, attempts: int = 3) -> bool:
    """Retry correction frames briefly before closing the packet socket."""
    for attempt in range(attempts):
        if session.stop():
            return True
        if attempt + 1 < attempts:
            time.sleep(0.2)
    return False


def _request_traffic_exit(stdscr, session: ArpSpoofSession | None) -> bool:
    """Keep the capture socket open until restore succeeds or exit is confirmed."""
    if not session or not (session.active or session.needs_restore):
        return True
    while session.active or session.needs_restore:
        if session.stop():
            return True
        choice = restoration_failure_modal(stdscr)
        if choice == "retry":
            continue
        if choice == "force":
            return True
        return False
    return True


def traffic_view(stdscr, monitor: ArpMonitor, selected_mac: str) -> None:
    device = monitor.devices.get(selected_mac)
    if not device or not device.ip or device.ip == "unknown":
        monitor.status_message = "Traffic view needs an observed IP for the selected device."
        return
    try:
        capture = TrafficCapture(monitor.iface, device.ip)
    except (OSError, RuntimeError) as exc:
        text_modal(stdscr, "Traffic capture unavailable", [
            str(exc), "Passive capture requires Linux AF_PACKET and CAP_NET_RAW.",
            "Press q to return.",
        ])
        return

    stdscr.keypad(True)
    stdscr.timeout(100)
    ptr_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="traffic-ptr")
    runtime_names = RuntimeEndpointNames(ptr_executor)
    spoof_session: ArpSpoofSession | None = None
    page_notice = ""
    capture_error = ""
    traffic_scroll = 0
    try:
        while True:
            monitor.listen(0)
            current = monitor.devices.get(selected_mac)
            if current and current.ip and current.ip != "unknown":
                capture.target_ip = current.ip
            if spoof_session and spoof_session.active:
                gateway = monitor.gateway_device()
                if (not current or current.ip != spoof_session.target_ip
                        or current.mac.lower() != spoof_session.target_mac_text
                        or not gateway or gateway.mac.lower() != spoof_session.gateway_mac_text):
                    restored = spoof_session.stop()
                    if restored:
                        spoof_session = None
                    monitor.status_message = (
                        "Device mapping changed; interception stopped; restoration frames sent, peer caches unverified."
                        if restored else "Device mapping changed; interception stopped but restoration sends failed. Press s to retry."
                    )
                    page_notice = monitor.status_message
                else:
                    try:
                        spoof_session.refresh()
                    except OSError as exc:
                        restored = spoof_session.stop()
                        if restored:
                            spoof_session = None
                        monitor.status_message = (
                            f"ARP refresh failed; interception stopped: {exc}; restoration frames sent, peer caches unverified."
                            if restored else f"ARP refresh failed and restoration sends failed; press s to retry: {exc}"
                        )
                        page_notice = monitor.status_message
            if not capture_error:
                try:
                    ready, _, _ = select.select([capture.sock], [], [], 0)
                except OSError as exc:
                    ready = []
                    capture_error = f"Traffic capture stopped: {exc}"
                if capture_error:
                    if spoof_session and spoof_session.active:
                        restored = spoof_session.stop()
                        if restored:
                            spoof_session = None
                    monitor.status_message = capture_error
                if ready:
                    while True:
                        try:
                            frame, vnet_header, gso_type, gso_size = capture.recv_packet()
                        except BlockingIOError:
                            break
                        except (OSError, ValueError) as exc:
                            capture_error = f"Traffic capture stopped: {exc}"
                            if spoof_session and spoof_session.active:
                                restored = spoof_session.stop()
                                if restored:
                                    spoof_session = None
                            monitor.status_message = capture_error
                            break
                        if spoof_session and spoof_session.active:
                            try:
                                spoof_session.relay_frame(frame, vnet_header)
                            except (OSError, ValueError) as exc:
                                restored = spoof_session.stop()
                                if restored:
                                    spoof_session = None
                                gso_detail = f", GSO type {gso_type}, size {gso_size}" if gso_type else ""
                                page_notice = (
                                    f"Relay failed for {len(frame)}-byte frame{gso_detail}: {exc}; "
                                    + ("restoration frames sent; peer caches unverified."
                                       if restored else "ARP restore sends failed; press s to retry.")
                                )
                                monitor.status_message = page_notice
                                continue
                            if frame[6:12] == spoof_session.local_mac:
                                continue
                        capture.ingest(frame)
            stdscr.erase()
            height, width = stdscr.getmaxyx()

            def put(y: int, text: str, attr: int = 0, *, scrollbar_gutter: bool = False) -> None:
                if 0 <= y < height and width > 2:
                    try:
                        available = width - (3 if scrollbar_gutter else 2)
                        stdscr.addnstr(y, 1, _fit_terminal_cell(text, available), available, attr)
                    except curses.error:
                        pass

            label = device.label or device.name or device.mac
            put(0, f"TRAFFIC · {label} · {capture.target_ip}", style.HEADER_ATTR)
            put(1, f"Capture stopped: {capture_error}" if capture_error else "ACTIVE ARP interception · forwarding selected device traffic" if spoof_session and spoof_session.active else "Passive, in-memory summary · only packets visible to this host are shown", style.HEADER_ATTR)
            endpoints = group_traffic_flows(capture.flows.values(), capture.target_ip)
            resolved_names = runtime_names.update(endpoint.ip for endpoint in endpoints)
            put(2, page_notice or f"{capture.packet_count} matching packets · {len(endpoints)} remote endpoints · {len(resolved_names)} PTR names")

            now = time.monotonic()
            entries = []
            for endpoint in endpoints:
                name = resolved_names.get(endpoint.ip) or next(
                    (item.name for item in monitor.devices.values()
                     if item.ip == endpoint.ip and item.name), ""
                )
                protocol = "/".join(sorted(endpoint.protocols))
                entries.append((f"{name or endpoint.ip}:{endpoint.port}", protocol,
                                str(endpoint.packets), str(endpoint.byte_count),
                                ago(now - endpoint.last_seen)))
            packet_width = max((len(entry[2]) for entry in entries), default=7)
            byte_width = max((len(entry[3]) for entry in entries), default=5)
            last_width = max((_terminal_cell_width(entry[4]) for entry in entries), default=9)
            layout = traffic_table_layout(width, packet_width, byte_width, last_width)
            visible = max(0, height - 6)
            table_lines: list[str] = []
            if not entries:
                put(3, format_traffic_header(layout), curses.A_UNDERLINE)
                put(4, "No matching packets observed yet. Other devices' unicast traffic may not be visible here.")
            else:
                for entry in entries:
                    table_lines.extend(format_traffic_row(*entry, layout))
                needs_scrollbar = len(table_lines) > visible
                if needs_scrollbar:
                    # Keep the scrollbar gutter out of the table's usable width.
                    layout = traffic_table_layout(width - 1, packet_width, byte_width, last_width)
                    table_lines = [line for entry in entries for line in format_traffic_row(*entry, layout)]
                put(3, format_traffic_header(layout), curses.A_UNDERLINE,
                    scrollbar_gutter=needs_scrollbar)
                max_scroll = max(0, len(table_lines) - visible)
                traffic_scroll = max(0, min(traffic_scroll, max_scroll))
                for index, line in enumerate(table_lines[traffic_scroll:traffic_scroll + visible], 4):
                    put(index, line, scrollbar_gutter=needs_scrollbar)
                scrollbar.draw_scrollbar(stdscr, len(table_lines), visible, traffic_scroll,
                               y=4, height=visible, x=width - 1)
            note = ("PTR names may be missing or generic; lookups use system DNS."
                    if width < 64 else "PTR lookups use system DNS; names may be missing or differ from service domains.")
            put(height - 2, note)
            action = ("s stop interception" if spoof_session and spoof_session.active
                      else "s retry ARP restore" if spoof_session and spoof_session.needs_restore
                      else "s start interception")
            scroll_hint = "↑/↓ scroll"
            if capture_error:
                footer = ("s retry ARP restore · q / Esc return"
                          if spoof_session and spoof_session.needs_restore
                          else "Capture stopped · q / Esc return")
            else:
                footer = f"{action} · {scroll_hint} · q / Esc return"
            put(height - 1, footer, style.FOOTER_ATTR)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                traffic_scroll = max(0, traffic_scroll - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                traffic_scroll = min(max(0, len(table_lines) - visible), traffic_scroll + 1)
            elif key == curses.KEY_PPAGE:
                traffic_scroll = max(0, traffic_scroll - max(1, visible))
            elif key == curses.KEY_NPAGE:
                traffic_scroll = min(max(0, len(table_lines) - visible), traffic_scroll + max(1, visible))
            elif key == curses.KEY_HOME:
                traffic_scroll = 0
            elif key == curses.KEY_END:
                traffic_scroll = max(0, len(table_lines) - visible)
            elif key in (ord("s"), ord("S")):
                if capture_error and not (spoof_session and spoof_session.needs_restore):
                    page_notice = "Cannot start interception because packet capture has stopped."
                    monitor.status_message = page_notice
                else:
                    spoof_session = toggle_arp_spoof(stdscr, monitor, selected_mac, capture, spoof_session)
                    page_notice = monitor.status_message
            elif key in (ord("q"), 27):
                if _request_traffic_exit(stdscr, spoof_session):
                    break
                page_notice = "ARP restoration still pending; press s to retry or q to try exiting again."
                monitor.status_message = page_notice
    finally:
        if spoof_session and (spoof_session.active or spoof_session.needs_restore):
            if _restore_with_retries(spoof_session):
                monitor.status_message = "ARP restoration frames sent; peer caches remain unverified."
            else:
                monitor.status_message = (
                    "WARNING: ARP restoration failed after retries. Check target and gateway connectivity; "
                    "stale ARP entries may need to expire or be cleared."
                )
        runtime_names.close()
        ptr_executor.shutdown(wait=False, cancel_futures=True)
        capture.close()
        stdscr.timeout(250)
        stdscr.erase()
        stdscr.refresh()
