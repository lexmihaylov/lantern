"""Helpers for wrapping text to terminal columns."""
from __future__ import annotations

import textwrap


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
