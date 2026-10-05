"""Scrollable text modal for help and device details."""
from __future__ import annotations

import curses

from .modal import make_modal
from .scrollbar import draw_scrollbar
from .wrapping import wrap_lines


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
        display_lines = wrap_lines(lines, w - 5)
        max_top = max(0, len(display_lines) - available)
        top = max(0, min(top, max_top))
        for row, text in enumerate(display_lines[top:top + available], start=1):
            window.addnstr(row, 2, text, max(1, w - 5))
        draw_scrollbar(window, len(display_lines), available, top,
                       y=1, height=available, x=w - 2)
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
