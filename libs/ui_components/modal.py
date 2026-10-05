"""Centered curses modal window construction."""
from __future__ import annotations

import curses

from . import style


def make_modal(stdscr, min_height: int = 9, min_width: int = 58):
    height, width = stdscr.getmaxyx()
    modal_h = max(3, min(min_height, height - 2))
    modal_w = max(3, min(min_width, width - 2))
    top = max(0, (height - modal_h) // 2)
    left = max(0, (width - modal_w) // 2)
    window = curses.newwin(modal_h, modal_w, top, left)
    window.keypad(True)
    window.bkgd(" ", style.MODAL_ATTR)
    window.attrset(style.MODAL_ATTR)
    return window
