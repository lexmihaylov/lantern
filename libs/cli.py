"""Lantern command startup and cleanup."""
from __future__ import annotations

import curses
import sys

from .network import ArpMonitor
from .ui import main


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
    try:
        curses.wrapper(main, monitor)
    except KeyboardInterrupt:
        return 130
    finally:
        monitor.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main_entry())
