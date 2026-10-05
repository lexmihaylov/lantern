"""Scrollable output modal used by ping and Nmap probes."""
from __future__ import annotations

import curses

from .scrollbar import draw_scrollbar
from .wrapping import wrap_lines


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
