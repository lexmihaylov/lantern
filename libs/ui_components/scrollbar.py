"""Proportional scrollbars for curses viewports."""
from __future__ import annotations

import curses


def draw_scrollbar(window, total: int, page: int, top: int, *, y: int,
                   height: int, x: int | None = None) -> None:
    """Draw a proportional scrollbar beside a vertically scrollable viewport."""
    if total <= page or page <= 0 or height <= 0:
        return
    _window_height, width = window.getmaxyx()
    x = width - 2 if x is None else x
    max_top = total - page
    top = max(0, min(top, max_top))
    thumb_height = max(1, height * page // total)
    thumb_top = (height - thumb_height) * top // max_top
    for offset in range(height):
        thumb = thumb_top <= offset < thumb_top + thumb_height
        # Use attributed spaces rather than text glyphs for a quiet, solid bar.
        attr = curses.A_REVERSE if thumb else curses.A_DIM
        try:
            window.addch(y + offset, x, " ", attr)
        except curses.error:
            break
