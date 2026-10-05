"""Interactive ping and Nmap actions for a selected device."""
from __future__ import annotations

import curses
import ipaddress
import os
import re
import select
import shutil
import subprocess
import time

from .models import Device
from .network import ArpMonitor
from .ui_components.modal import make_modal
from .ui_components.probe_modal import probe_scroll_bottom, render_probe_modal
from .ui_components.text_modal import text_modal

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
