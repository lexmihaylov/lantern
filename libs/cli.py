"""Lantern command startup and cleanup."""
from __future__ import annotations

import curses
import signal
import sys

from .network import ArpMonitor
from .ui import main


def _handle_termination_signal(_signum, _frame) -> None:
    # Convert termination signals into normal stack unwinding so active probes
    # and ARP interception get a chance to run their cleanup paths.
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)
    raise KeyboardInterrupt


def main_entry() -> int:
    # curses needs a real terminal; fail before opening raw sockets otherwise.
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this network table TUI from an interactive terminal.", file=sys.stderr)
        return 2
    try:
        monitor = ArpMonitor()
    except Exception as exc:
        print(f"Cannot start ARP monitor: {exc}", file=sys.stderr)
        print(f"Try: sudo {sys.argv[0]}", file=sys.stderr)
        return 1
    termination_signals = (signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {signum: signal.getsignal(signum) for signum in termination_signals}
    try:
        for signum in termination_signals:
            signal.signal(signum, _handle_termination_signal)
        curses.wrapper(main, monitor)
    except KeyboardInterrupt:
        if monitor.status_message.startswith("WARNING: ARP restoration failed"):
            print(monitor.status_message, file=sys.stderr)
        return 130
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        monitor.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main_entry())
