"""Reusable curses widgets and terminal helpers."""
from __future__ import annotations

import curses
import textwrap

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

def render_probe_modal(window, lines: list[str], status: str, follow: bool, scroll: int,
                       title: str = "Device scan — selected host only") -> int:
    window.erase()
    window.box()
    h, w = window.getmaxyx()
    content_width = max(1, w - 5)
    window.addnstr(0, 2, f" {title} ", content_width, curses.A_BOLD)
    rows = max(1, h - 4)
    display_lines = wrap_lines(lines, content_width)
    max_top = max(0, len(display_lines) - rows)
    start = max_top if follow else max(0, min(scroll, max_top))
    for idx, line in enumerate(display_lines[start:start + rows]):
        window.addnstr(1 + idx, 2, line, content_width)
    draw_scrollbar(window, len(display_lines), rows, start,
                   y=1, height=rows, x=w - 2)
    count = min(rows, max(0, len(display_lines) - start))
    footer = f"{status}  Lines {start + 1}-{start + count}/{len(display_lines)}"
    window.addnstr(h - 2, 2, footer, content_width)
    window.refresh()
    return start

def probe_scroll_bottom(window, lines: list[str]) -> int:
    h, w = window.getmaxyx()
    rows = max(1, h - 4)
    return max(0, len(wrap_lines(lines, max(1, w - 5))) - rows)
