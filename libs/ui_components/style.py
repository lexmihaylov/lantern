"""Shared curses colors and attributes."""
from __future__ import annotations

import curses

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
