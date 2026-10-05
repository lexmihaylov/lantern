"""Curses interface and interactive actions."""
from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import dataclass
import curses
import ipaddress
import os
import re
import select
import shutil
import subprocess
import textwrap
import time
import unicodedata

from .models import Device, Flow
from .network import ArpMonitor, QUIET_AFTER, age_compact, ago, filtered_devices, ordered_devices, reverse_resolve, save_labels, seen_when
from .traffic import ArpSpoofSession, TrafficCapture

MODAL_ATTR = curses.A_REVERSE
HEADER_ATTR = curses.A_BOLD
FOOTER_ATTR = curses.A_REVERSE

def init_modal_style() -> None:
    global MODAL_ATTR, HEADER_ATTR, FOOTER_ATTR
    HEADER_ATTR = curses.A_BOLD
    FOOTER_ATTR = curses.A_REVERSE
    MODAL_ATTR = curses.A_REVERSE
    try:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_CYAN)
        MODAL_ATTR = curses.color_pair(1)
        HEADER_ATTR = curses.color_pair(2) | curses.A_BOLD
        FOOTER_ATTR = curses.color_pair(3)
    except curses.error:
        pass

def draw(stdscr, monitor: ArpMonitor, selected_mac: str, query: str = "") -> str:
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    def put(y: int, text: str, attr: int = 0) -> None:
        if 0 <= y < height and width > 2:
            try:
                stdscr.addnstr(y, 1, text, width - 2, attr)
            except curses.error:
                pass

    put(0, "LANTERN · LAN DEVICE MONITOR", HEADER_ATTR)
    if height < 8 or width < 24:
        put(2, "Terminal too small; resize to at least 24 columns × 8 rows. q quits.")
        stdscr.refresh()
        return selected_mac
    put(1, f"{monitor.iface} · {monitor.network} · gateway {monitor.gateway or '—'} · sweep {ago(time.monotonic() - monitor.last_sweep)}", HEADER_ATTR)
    latest = monitor.status_message or (monitor.events[-1] if monitor.events else "")
    put(2, (latest or f"Auto probes {'ON' if monitor.auto_probe else 'OFF'} · interval {monitor.interval}s")[:width - 2], HEADER_ATTR)

    items = filtered_devices(monitor, query)
    put(3, f"Filter: /{query}" if query else "DEVICES")
    known_macs = {device.mac for device in items}
    if selected_mac not in known_macs and items:
        selected_mac = items[0].mac

    state_w, ip_w, age_w = 8, 15, 4
    compact = width < 70
    name_w = max(1, width - (34 if not compact else 14))
    column_header = (f"  {'STATE':<{state_w}} {'IP':<{ip_w}} {'NAME/LABEL':<{name_w}} {'AGE':>{age_w}}"
                     if not compact else f"  {'STATE':<{state_w}} {'IP':<{ip_w}} {'NAME/LABEL'}")
    groups = [
        ("NEW DEVICES", [d for d in items if d.state == "NEW"]),
        ("ONLINE DEVICES", [d for d in items if d.state not in ("NEW", "QUIET", "OFFLINE")]),
        ("OFFLINE / QUIET DEVICES", [d for d in items if d.state in ("QUIET", "OFFLINE")]),
    ]
    table_rows: list[tuple[str, Device | None, int]] = []
    selected_row = 0
    for section_index, (title, devices) in enumerate(groups):
        table_rows.append((f"{title} ({len(devices)})", None, curses.A_BOLD))
        table_rows.append((column_header, None, curses.A_UNDERLINE))
        for device in devices:
            age = age_compact(device.last_seen)
            name = device.label or device.name or "(unresolved)"
            if device.label and device.name:
                name += f" ({device.name})"
            if compact:
                row = f"{'>' if device.mac == selected_mac else ' '} {device.state:<{state_w}} {device.ip:<{ip_w}} {name}"
            else:
                row = f"{'>' if device.mac == selected_mac else ' '} {device.state:<{state_w}} {device.ip:<{ip_w}} {name:<{name_w}} {age:>{age_w}}"
            if device.mac == selected_mac:
                selected_row = len(table_rows)
            table_rows.append((row, device, curses.A_REVERSE if device.mac == selected_mac else 0))
        if section_index < len(groups) - 1:
            table_rows.append(("", None, 0))

    if not items:
        table_rows = [(f"No devices match '{query}'. Press / to change filter." if query else "No devices observed yet.", None, 0)]
    list_start = 4
    footer_start = max(list_start, height - 1)
    visible = max(0, footer_start - list_start)
    first = max(0, min(selected_row - visible + 1, len(table_rows) - visible)) if visible else 0
    for index, (text, _device, attr) in enumerate(table_rows[first:first + visible]):
        put(list_start + index, text, attr)

    put(height - 1, f"{len(items)} devices · ↑/↓ move · Enter details · / filter · t traffic · ? help · q quit", FOOTER_ATTR)
    stdscr.refresh()
    return selected_mac

def selected_device(monitor: ArpMonitor, mac: str) -> Device | None:
    return monitor.devices.get(mac) if mac else None

def wrap_lines(lines: list[str], width: int) -> list[str]:
    wrapped: list[str] = []
    width = max(1, width)
    for line in lines:
        clean = line.expandtabs(4).replace("\r", "")
        if not clean:
            wrapped.append("")
            continue
        wrapped.extend(textwrap.wrap(clean, width=width, replace_whitespace=False,
                                     drop_whitespace=True, break_long_words=True,
                                     break_on_hyphens=False) or [""])
    return wrapped

def text_modal(stdscr, title: str, lines: list[str]) -> None:
    height, width = stdscr.getmaxyx()
    modal_h = max(5, min(height - 2, max(12, len(lines) + 4)))
    window = make_modal(stdscr, modal_h, max(3, width - 4))
    window.timeout(100)
    top = 0
    while True:
        window.erase()
        window.box()
        h, w = window.getmaxyx()
        window.addnstr(0, 2, f" {title} ", max(1, w - 4), curses.A_BOLD)
        available = max(1, h - 4)
        display_lines = wrap_lines(lines, w - 4)
        max_top = max(0, len(display_lines) - available)
        top = max(0, min(top, max_top))
        for row, text in enumerate(display_lines[top:top + available], start=1):
            window.addnstr(row, 2, text, max(1, w - 4))
        count = min(available, max(0, len(display_lines) - top))
        hint = f"Rows {top + 1}-{top + count}/{len(display_lines)} · ↑/↓ PgUp/PgDn Home/End · q closes"
        window.addnstr(h - 2, 2, hint, max(1, w - 4))
        window.refresh()
        key = window.getch()
        if key == ord("q"):
            break
        if key in (curses.KEY_UP, ord("k")):
            top = max(0, top - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            top = min(max_top, top + 1)
        elif key == curses.KEY_PPAGE:
            top = max(0, top - available)
        elif key == curses.KEY_NPAGE:
            top = min(max_top, top + available)
        elif key == curses.KEY_HOME:
            top = 0
        elif key == curses.KEY_END:
            top = max_top
    window.clear()
    window.refresh()
    stdscr.touchwin()
    stdscr.refresh()

def device_details_modal(stdscr, device: Device) -> None:
    lines = [
        f"Label: {device.label or '(none)'}",
        f"Hostname (system resolver): {device.name or '(unresolved)'}",
        f"IPv4: {device.ip}",
        f"MAC: {device.mac}",
        f"State: {device.state}",
        f"Last ARP observed: {seen_when(device.last_seen)}",
        f"ARP packet type: {device.source}",
        "",
        "Fingerprint (session only):",
        device.fingerprint or "Not scanned. Press s to scan this device.",
        f"Ping result: {device.ping_result or 'Not pinged.'}",
    ]
    text_modal(stdscr, f"Device details — {device.label or device.name or device.ip}", lines)

def help_modal(stdscr) -> None:
    text_modal(stdscr, "Navigation and actions", [
        "↑ / ↓ or j / k      Select a device (selection stops at list ends).",
        "/                   Filter by label, hostname, IPv4, or MAC; Enter applies, Esc clears.",
        "Page Up / Page Down Move by one visible page.",
        "Home / End          Select the first / last device.",
        "g                   Select the configured gateway.",
        "Enter               Open details for the selected device.",
        "r                   Send an immediate ARP sweep.",
        "a                   Toggle periodic ARP sweeps.",
        "+ / -               Change sweep interval by five seconds.",
        "s                   Start a Nmap scan of the selected IP (no approval).",
        "p                   Ping the selected IP; no reply may mean ICMP is blocked.",
        "l                   Set or remove a persistent label (keyed by MAC).",
        "t                   Open traffic view; press s there to toggle confirmed ARP interception.",
        "q                   Exit the device table; only q closes modals.",
        "",
        "QUIET starts after 45 seconds without ARP; unlabeled entries are removed after five minutes.",
        "Saved labeled devices stay listed as OFFLINE until ARP returns; their IP may be unknown.",
        "Fingerprints are not persisted."
    ])

def make_modal(stdscr, min_height: int = 9, min_width: int = 58):
    height, width = stdscr.getmaxyx()
    modal_h = max(3, min(min_height, height - 2))
    modal_w = max(3, min(min_width, width - 2))
    top = max(0, (height - modal_h) // 2)
    left = max(0, (width - modal_w) // 2)
    window = curses.newwin(modal_h, modal_w, top, left)
    window.keypad(True)
    window.bkgd(" ", MODAL_ATTR)
    window.attrset(MODAL_ATTR)
    return window

def prompt_label(stdscr, device: Device) -> str | None:
    window = make_modal(stdscr, 11, 64)
    buffer = list(device.label)
    confirmed = False
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    while True:
        window.erase()
        window.box()
        h, w = window.getmaxyx()
        window.addnstr(0, 2, " Assign device label ", max(1, w - 4), curses.A_BOLD)
        window.addnstr(2, 2, f"{device.ip}  {device.mac}", max(1, w - 4))
        window.addnstr(4, 2, "Enter confirms; q applies/closes. Esc ignored.", max(1, w - 4))
        shown = "".join(buffer)
        window.addnstr(6, 2, shown[-max(1, w - 6):], max(1, w - 4))
        hint = "Confirmed; q saves and closes." if confirmed else "Type label, then Enter; q cancels."
        window.addnstr(h - 2, 2, hint, max(1, w - 4))
        window.move(6, min(w - 2, 2 + len(shown[-max(1, w - 6):])))
        window.refresh()
        try:
            key = window.get_wch()
        except curses.error:
            continue
        if key == "q":
            return "".join(buffer).strip() if confirmed else None
        if key in ("\n", "\r", curses.KEY_ENTER):
            confirmed = True
        elif key == "\x15":  # Ctrl-U clears the line
            buffer.clear()
            confirmed = False
        elif key in ("\x7f", "\b", curses.KEY_BACKSPACE):
            if buffer:
                buffer.pop()
            confirmed = False
        elif isinstance(key, str) and key.isprintable() and len(buffer) < 80:
            buffer.append(key)
            confirmed = False

def render_probe_modal(window, lines: list[str], status: str, follow: bool, scroll: int,
                       title: str = "Device scan — selected host only") -> int:
    window.erase()
    window.box()
    h, w = window.getmaxyx()
    content_width = max(1, w - 4)
    window.addnstr(0, 2, f" {title} ", content_width, curses.A_BOLD)
    rows = max(1, h - 4)
    display_lines = wrap_lines(lines, content_width)
    max_top = max(0, len(display_lines) - rows)
    start = max_top if follow else max(0, min(scroll, max_top))
    for idx, line in enumerate(display_lines[start:start + rows]):
        window.addnstr(1 + idx, 2, line, content_width)
    count = min(rows, max(0, len(display_lines) - start))
    footer = f"{status}  Lines {start + 1}-{start + count}/{len(display_lines)}"
    window.addnstr(h - 2, 2, footer, content_width)
    window.refresh()
    return start

def probe_scroll_bottom(window, lines: list[str]) -> int:
    h, w = window.getmaxyx()
    rows = max(1, h - 4)
    return max(0, len(wrap_lines(lines, max(1, w - 4))) - rows)

def ping_device(stdscr, device: Device, monitor: ArpMonitor) -> None:
    try:
        ip = str(ipaddress.IPv4Address(device.ip))
    except ipaddress.AddressValueError:
        message = "No IPv4 address has been observed for this saved device yet."
        device.ping_result = message
        monitor.status_message = message
        text_modal(stdscr, "Ping unavailable", [message, "Wait for an ARP response, then press p."])
        return
    ping_executable = shutil.which("ping")
    if not ping_executable:
        message = "The ping command is not installed."
        device.ping_result = message
        monitor.status_message = message
        text_modal(stdscr, "Ping unavailable", [message])
        return

    window = make_modal(stdscr, 18, 84)
    window.timeout(50)
    lines = [f"Target: {ip} ({device.label or device.name or device.mac})", "", "Starting 3 ICMP echo requests…"]
    status = "Ping in progress; q cancels/closes. ↑/↓ scroll output."
    follow, scroll = True, 0
    render_probe_modal(window, lines, status, follow, scroll, title=f"Ping {ip}")
    device.ping_result = "Ping in progress…"
    proc = None
    cancelled = False
    close_requested = False
    timed_out = False
    output = ""
    try:
        ping_args = [ping_executable, "-n", "-c", "3", "-W", "1", ip]
        stdbuf = shutil.which("stdbuf")
        if stdbuf:
            ping_args = [stdbuf, "-oL", *ping_args]
        proc = subprocess.Popen(
            ping_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        os.set_blocking(fd, False)
        started = time.monotonic()
        partial = ""
        eof = False
        terminate_at = 0.0
        while proc.poll() is None or not eof:
            if close_requested and proc.poll() is not None:
                break
            if time.monotonic() - started > 7 and proc.poll() is None and not timed_out:
                timed_out = True
                terminate_at = time.monotonic()
                proc.terminate()
                status = "Ping timed out; stopping ping…"
            if terminate_at and time.monotonic() - terminate_at > 1 and proc.poll() is None:
                proc.kill()
            ready, _, _ = select.select([fd], [], [], 0.08)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    eof = True
                    if partial:
                        lines.append(partial)
                        output += partial + "\n"
                        partial = ""
                elif chunk:
                    decoded = chunk.decode(errors="replace")
                    output += decoded
                    partial += decoded
                    new_lines = partial.split("\n")
                    partial = new_lines.pop()
                    lines.extend(new_lines)
            shown_lines = lines + ([partial] if partial else [])
            start = render_probe_modal(window, shown_lines, status, follow, scroll, title=f"Ping {ip}")
            key = window.getch()
            if key == ord("q"):
                close_requested = True
                if proc.poll() is None:
                    cancelled = True
                    terminate_at = time.monotonic()
                    proc.terminate()
                    status = "Ping cancelled; stopping ping…"
            elif key in (curses.KEY_UP, ord("k")):
                follow, scroll = False, max(0, start - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                bottom = probe_scroll_bottom(window, shown_lines)
                scroll = min(bottom, start + 1)
                follow = scroll == bottom
            elif key == curses.KEY_PPAGE:
                follow = False
                scroll = max(0, start - max(1, window.getmaxyx()[0] - 4))
            elif key == curses.KEY_NPAGE:
                bottom = probe_scroll_bottom(window, shown_lines)
                scroll = min(bottom, start + max(1, window.getmaxyx()[0] - 4))
                follow = scroll == bottom
            elif key == curses.KEY_HOME:
                follow, scroll = False, 0
            elif key == curses.KEY_END:
                follow, scroll = True, 0
        return_code = proc.wait(timeout=2)
        if cancelled:
            message = "Ping cancelled by user."
        elif timed_out:
            message = f"Ping timed out (ARP state: {device.state})."
        elif return_code == 0:
            message = "ICMP reply received; the device is reachable."
        else:
            message = f"No ICMP reply; the device may block ping (ARP state: {device.state})."
    except OSError as exc:
        message = f"Ping failed: {exc}"
        lines.append(message)
        status = "Ping failed; q closes."
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if proc and proc.stdout:
            proc.stdout.close()

    if cancelled:
        monitor.add_event(f"Ping to {ip} was cancelled.")
    elif timed_out:
        monitor.add_event(f"Ping to {ip} timed out; ARP state is {device.state}.")
    elif not message.startswith("Ping failed"):
        monitor.add_event(f"Ping to {ip}: {message}")
    device.ping_result = message
    monitor.status_message = f"Ping {ip}: {message}"
    if close_requested:
        window.clear()
        window.refresh()
        stdscr.touchwin()
        stdscr.refresh()
        return

    lines.extend(["", message, f"ARP state: {device.state}"])
    status = f"Finished. ↑/↓ scroll; q closes this modal."
    follow, scroll = True, 0
    window.timeout(-1)
    while True:
        start = render_probe_modal(window, lines, status, follow, scroll, title=f"Ping {ip}")
        key = window.getch()
        if key == ord("q"):
            break
        if key in (curses.KEY_UP, ord("k")):
            follow, scroll = False, max(0, start - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            bottom = probe_scroll_bottom(window, lines)
            scroll = min(bottom, start + 1)
            follow = scroll == bottom
        elif key == curses.KEY_PPAGE:
            follow = False
            scroll = max(0, start - max(1, window.getmaxyx()[0] - 4))
        elif key == curses.KEY_NPAGE:
            bottom = probe_scroll_bottom(window, lines)
            scroll = min(bottom, start + max(1, window.getmaxyx()[0] - 4))
            follow = scroll == bottom
        elif key == curses.KEY_HOME:
            follow, scroll = False, 0
        elif key == curses.KEY_END:
            follow, scroll = True, 0
    window.clear()
    window.refresh()
    stdscr.touchwin()
    stdscr.refresh()

def scan_device(stdscr, device: Device, monitor: ArpMonitor) -> None:
    try:
        ipaddress.IPv4Address(device.ip)
    except ipaddress.AddressValueError:
        text_modal(stdscr, "Device scan unavailable", [
            "This saved device has no IPv4 address observed yet.",
            "Wait for an ARP response before scanning it.",
        ])
        monitor.status_message = "No observed IPv4 address for this saved device yet."
        return
    if not shutil.which("nmap"):
        text_modal(stdscr, "Device scan unavailable", [
            "Nmap is not installed, so this selected-device scan cannot run.",
            "ARP-based device discovery continues to work without Nmap.",
        ])
        monitor.status_message = "Nmap unavailable; ARP discovery is unaffected."
        return
    args = ["nmap", "-Pn", "-n", "-sV", "--version-light", "--top-ports", "20",
            "-O", "--osscan-guess", "--reason", device.ip]
    window = make_modal(stdscr, 18, 84)
    window.timeout(50)
    lines = [f"Target: {device.ip} ({device.label or device.name or device.mac})", ""]
    status = "Starting Nmap…  q cancels; ↑/↓ scroll output."
    follow, scroll = True, 0
    proc = None
    output = ""
    cancelled = False
    timed_out = False
    close_requested = False
    device.fingerprint = "In progress…"
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        os.set_blocking(fd, False)
        started = time.monotonic()
        partial = ""
        eof = False
        terminate_at = 0.0
        while proc.poll() is None or not eof:
            if close_requested and proc.poll() is not None:
                break
            if time.monotonic() - started > 90 and proc.poll() is None and not timed_out:
                timed_out = True
                terminate_at = time.monotonic()
                proc.terminate()
                status = "Probe timed out; stopping Nmap…"
            if terminate_at and time.monotonic() - terminate_at > 2 and proc.poll() is None:
                proc.kill()
            ready, _, _ = select.select([fd], [], [], 0.08)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    eof = True
                    if partial:
                        lines.append(partial)
                        output += partial + "\n"
                        partial = ""
                elif chunk:
                    decoded = chunk.decode(errors="replace")
                    output += decoded
                    partial += decoded
                    new_lines = partial.split("\n")
                    partial = new_lines.pop()
                    lines.extend(new_lines)
            start = render_probe_modal(window, lines, status, follow, scroll)
            key = window.getch()
            if key == ord("q"):
                close_requested = True
                if proc.poll() is None and not cancelled:
                    cancelled = True
                    terminate_at = time.monotonic()
                    proc.terminate()
                    status = "Cancelled; stopping Nmap…"
            elif key in (curses.KEY_UP, ord("k")):
                follow, scroll = False, max(0, start - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                bottom = probe_scroll_bottom(window, lines)
                scroll = min(bottom, start + 1)
                follow = scroll == bottom
            elif key == curses.KEY_PPAGE:
                follow = False
                scroll = max(0, start - max(1, window.getmaxyx()[0] - 4))
            elif key == curses.KEY_NPAGE:
                bottom = probe_scroll_bottom(window, lines)
                scroll = min(bottom, start + max(1, window.getmaxyx()[0] - 4))
                follow = scroll == bottom
            elif key == curses.KEY_HOME:
                follow, scroll = False, 0
            elif key == curses.KEY_END:
                follow, scroll = True, 0
        return_code = proc.wait(timeout=2)
        if cancelled:
            status = "Cancelled. ↑/↓ scroll; q closes this modal."
        elif timed_out:
            status = "Timed out. ↑/↓ scroll; q closes this modal."
        else:
            status = f"Finished (exit {return_code}). ↑/↓ scroll; q closes this modal."
    except (OSError, subprocess.TimeoutExpired) as exc:
        status = f"Probe failed: {exc}. q closes this modal."
        device.fingerprint = f"Probe failed: {exc}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if proc and proc.stdout:
            proc.stdout.close()

    summary = []
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^\d+/(tcp|udp)\s+open\b", stripped):
            summary.append(stripped)
        elif stripped.startswith(("OS details:", "Running:", "Device type:", "Aggressive OS guesses:", "Service Info:")):
            summary.append(stripped)
    if cancelled:
        device.fingerprint = "Cancelled by user."
    elif timed_out:
        device.fingerprint = "Probe timed out after 90 seconds."
    elif not device.fingerprint.startswith("Probe failed:"):
        device.fingerprint = "; ".join(summary[:5]) or "No service/OS fingerprint obtained."
    monitor.status_message = f"Scan: {device.fingerprint}"
    if close_requested:
        window.clear()
        window.refresh()
        stdscr.touchwin()
        stdscr.refresh()
        return
    follow, scroll = True, 0
    window.timeout(-1)
    while True:
        start = render_probe_modal(window, lines, status, follow, scroll)
        key = window.getch()
        if key == ord("q"):
            break
        if key in (curses.KEY_UP, ord("k")):
            follow, scroll = False, max(0, start - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            bottom = probe_scroll_bottom(window, lines)
            scroll = min(bottom, start + 1)
            follow = scroll == bottom
        elif key == curses.KEY_PPAGE:
            follow = False
            scroll = max(0, start - max(1, window.getmaxyx()[0] - 4))
        elif key == curses.KEY_NPAGE:
            bottom = probe_scroll_bottom(window, lines)
            scroll = min(bottom, start + max(1, window.getmaxyx()[0] - 4))
            follow = scroll == bottom
        elif key == curses.KEY_HOME:
            follow, scroll = False, 0
        elif key == curses.KEY_END:
            follow, scroll = True, 0
    window.clear()
    window.refresh()
    stdscr.touchwin()
    stdscr.refresh()

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
        ("wide", 8 + packet_width + byte_width + last_width + 8, 16, byte_width, last_width),
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


def traffic_view(stdscr, monitor: ArpMonitor, selected_mac: str) -> None:
    device = selected_device(monitor, selected_mac)
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

            def put(y: int, text: str, attr: int = 0) -> None:
                if 0 <= y < height and width > 2:
                    try:
                        stdscr.addnstr(y, 1, _fit_terminal_cell(text, width - 2), width - 2, attr)
                    except curses.error:
                        pass

            label = device.label or device.name or device.mac
            put(0, f"TRAFFIC · {label} · {capture.target_ip}", HEADER_ATTR)
            put(1, f"Capture stopped: {capture_error}" if capture_error else "ACTIVE ARP interception · forwarding selected device traffic" if spoof_session and spoof_session.active else "Passive, in-memory summary · only packets visible to this host are shown", HEADER_ATTR)
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
            put(3, format_traffic_header(layout), curses.A_UNDERLINE)

            visible = max(0, height - 6)
            if not entries:
                put(4, "No matching packets observed yet. Other devices' unicast traffic may not be visible here.")
            else:
                table_lines: list[str] = []
                for entry in entries:
                    flow_lines = format_traffic_row(*entry, layout)
                    if len(table_lines) + len(flow_lines) > visible:
                        break
                    table_lines.extend(flow_lines)
                for index, line in enumerate(table_lines, 4):
                    put(index, line)
            note = ("PTR names may be missing or generic; lookups use system DNS."
                    if width < 64 else "PTR lookups use system DNS; names may be missing or differ from service domains.")
            put(height - 2, note)
            action = ("s stop interception" if spoof_session and spoof_session.active
                      else "s retry ARP restore" if spoof_session and spoof_session.needs_restore
                      else "s start interception")
            footer = "Capture stopped · q / Esc return" if capture_error else f"Capture active · {action} · q / Esc return"
            put(height - 1, footer, FOOTER_ATTR)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("s"), ord("S")):
                if capture_error and not (spoof_session and spoof_session.needs_restore):
                    page_notice = "Cannot start interception because packet capture has stopped."
                    monitor.status_message = page_notice
                else:
                    spoof_session = toggle_arp_spoof(stdscr, monitor, selected_mac, capture, spoof_session)
                    page_notice = monitor.status_message
            elif key in (ord("q"), 27):
                break
    finally:
        if spoof_session and (spoof_session.active or spoof_session.needs_restore):
            restored = spoof_session.stop()
            if not restored:
                monitor.status_message = "Traffic view closed; ARP restoration failed. Check target and gateway connectivity."
        runtime_names.close()
        ptr_executor.shutdown(wait=False, cancel_futures=True)
        capture.close()
        stdscr.timeout(250)
        stdscr.erase()
        stdscr.refresh()

def move_selection(monitor: ArpMonitor, selected_mac: str, key: int, page_size: int,
                   query: str = "") -> str:
    items = filtered_devices(monitor, query)
    if not items:
        return selected_mac
    if key in (curses.KEY_HOME,):
        return items[0].mac
    if key in (curses.KEY_END,):
        return items[-1].mac
    index = next((i for i, device in enumerate(items) if device.mac == selected_mac), 0)
    if key in (curses.KEY_UP, ord("k")):
        index -= 1
    elif key in (curses.KEY_DOWN, ord("j")):
        index += 1
    elif key == curses.KEY_PPAGE:
        index -= page_size
    elif key == curses.KEY_NPAGE:
        index += page_size
    return items[max(0, min(len(items) - 1, index))].mac

def main(stdscr, monitor: ArpMonitor) -> None:
    init_modal_style()
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.keypad(True)
    stdscr.timeout(250)
    selected_mac = ""
    query = ""
    while True:
        if monitor.auto_probe and time.monotonic() >= monitor.next_probe:
            monitor.send_sweep()
        monitor.listen(0.1)
        selected_mac = draw(stdscr, monitor, selected_mac, query)
        key = stdscr.getch()
        if key == ord("q"):
            return
        height, width = stdscr.getmaxyx()
        if key == ord("/"):
            buffer = list(query)
            while True:
                draw(stdscr, monitor, selected_mac, "".join(buffer))
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
                try:
                    input_key = stdscr.get_wch()
                except curses.error:
                    continue
                if input_key in ("\n", "\r", curses.KEY_ENTER):
                    query = "".join(buffer)
                    break
                if input_key == "\x1b":
                    query = ""
                    break
                if input_key in ("\x7f", "\b", curses.KEY_BACKSPACE):
                    if buffer:
                        buffer.pop()
                elif isinstance(input_key, str) and input_key.isprintable() and len(buffer) < 100:
                    buffer.append(input_key)
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            matches = filtered_devices(monitor, query)
            if not any(device.mac == selected_mac for device in matches):
                selected_mac = matches[0].mac if matches else ""
            continue
        if key in (ord("r"), ord("R")):
            monitor.send_sweep()
            monitor.status_message = "ARP sweep sent; waiting for replies."
        elif key in (ord("a"), ord("A")):
            monitor.auto_probe = not monitor.auto_probe
            if monitor.auto_probe:
                monitor.next_probe = time.monotonic()
            monitor.status_message = f"Automatic ARP probes {'enabled' if monitor.auto_probe else 'paused'}."
        elif key in (ord("+"), ord("=")):
            monitor.interval = min(60, monitor.interval + 5)
            monitor.next_probe = time.monotonic() + monitor.interval
            monitor.status_message = f"ARP interval set to {monitor.interval}s."
        elif key in (ord("-"), ord("_")):
            monitor.interval = max(5, monitor.interval - 5)
            monitor.next_probe = time.monotonic() + monitor.interval
            monitor.status_message = f"ARP interval set to {monitor.interval}s."
        elif key in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j"),
                     curses.KEY_PPAGE, curses.KEY_NPAGE, curses.KEY_HOME, curses.KEY_END):
            selected_mac = move_selection(monitor, selected_mac, key, max(1, height - 8), query)
        elif key in (10, 13, curses.KEY_ENTER):
            device = selected_device(monitor, selected_mac)
            if device:
                device_details_modal(stdscr, device)
        elif key in (ord("?"), curses.KEY_F1):
            help_modal(stdscr)
        elif key in (ord("g"), ord("G")):
            gateway_device = monitor.gateway_device()
            if gateway_device:
                selected_mac = gateway_device.mac
                monitor.status_message = "Gateway selected. Use s to scan, p to ping, or l to label it."
            else:
                monitor.status_message = "Gateway has not answered an ARP probe yet."
        elif key in (ord("l"), ord("L")):
            device = selected_device(monitor, selected_mac)
            if device:
                label = prompt_label(stdscr, device)
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass
                if label is not None:
                    if label:
                        monitor.labels[device.mac] = label
                    else:
                        monitor.labels.pop(device.mac, None)
                    device.label = label
                    if not label and device.state == "OFFLINE":
                        monitor.devices.pop(device.mac, None)
                    try:
                        save_labels(monitor.labels_path, monitor.labels)
                        monitor.status_message = f"Saved label for {device.mac}."
                    except OSError as exc:
                        monitor.status_message = f"Could not save label: {exc}"
        elif key in (ord("s"), ord("S")):
            device = selected_device(monitor, selected_mac)
            if device:
                scan_device(stdscr, device, monitor)
        elif key in (ord("p"), ord("P")):
            device = selected_device(monitor, selected_mac)
            if device:
                ping_device(stdscr, device, monitor)
        elif key in (ord("t"), ord("T")):
            traffic_view(stdscr, monitor, selected_mac)
