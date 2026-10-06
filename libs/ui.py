"""Main Lantern device screen and keyboard controller."""
from __future__ import annotations

import curses
import time

from .models import Device
from .network import ArpMonitor, age_compact, ago, filtered_devices, ordered_devices, save_labels, seen_when
from .probes import ping_device, scan_device
from .traffic_view import traffic_view
from .ui_components import scrollbar, style
from .ui_components.modal import make_modal
from .ui_components.style import init_modal_style
from .ui_components.text_modal import text_modal

def draw(stdscr, monitor: ArpMonitor, selected_mac: str, query: str = "") -> str:
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    def put(y: int, text: str, attr: int = 0, *, scrollbar_gutter: bool = False) -> None:
        if 0 <= y < height and width > 2:
            try:
                available = width - (3 if scrollbar_gutter else 2)
                stdscr.addnstr(y, 1, text, available, attr)
            except curses.error:
                pass

    put(0, "LANTERN · LAN DEVICE MONITOR", style.HEADER_ATTR)
    if height < 8 or width < 24:
        put(2, "Terminal too small; resize to at least 24 columns × 8 rows. q quits.")
        stdscr.refresh()
        return selected_mac
    put(1, f"{monitor.iface} · {monitor.network} · gateway {monitor.gateway or '—'} · sweep {ago(time.monotonic() - monitor.last_sweep)}", style.HEADER_ATTR)
    latest = monitor.status_message or (monitor.events[-1] if monitor.events else "")
    put(2, (latest or f"Auto probes {'ON' if monitor.auto_probe else 'OFF'} · interval {monitor.interval}s")[:width - 2], style.HEADER_ATTR)

    items = filtered_devices(monitor, query)
    put(3, f"Filter: /{query}" if query else "DEVICES")
    known_macs = {device.mac for device in items}
    if selected_mac not in known_macs and items:
        selected_mac = items[0].mac

    state_w, ip_w, age_w = 8, 15, 4
    compact = width < 70
    # Account for the list gutter by narrowing the name field, not the AGE column.
    name_w = max(1, width - (35 if not compact else 30))
    column_header = (f"  {'STATE':<{state_w}} {'IP':<{ip_w}} {'NAME/LABEL':<{name_w}} {'AGE':>{age_w}}"
                     if not compact else f"  {'STATE':<{state_w}} {'IP':<{ip_w}} {'NAME/LABEL'}")
    groups = [
        ("ONLINE DEVICES", [d for d in items if d.state not in ("QUIET", "OFFLINE")]),
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
        put(list_start + index, text, attr, scrollbar_gutter=True)
    scrollbar.draw_scrollbar(stdscr, len(table_rows), visible, first,
                   y=list_start, height=visible, x=width - 1)

    put(height - 1, f"{len(items)} devices · ↑/↓ move · Enter details · / filter · t traffic · ? help · q quit", style.FOOTER_ATTR)
    stdscr.refresh()
    return selected_mac

def selected_device(monitor: ArpMonitor, mac: str) -> Device | None:
    return monitor.devices.get(mac) if mac else None

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
