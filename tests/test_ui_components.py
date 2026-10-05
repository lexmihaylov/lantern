import curses
import unittest
from unittest.mock import patch

from lantern.libs.ui_components import style
from lantern.libs.ui_components.scrollbar import draw_scrollbar


class FakeWindow:
    def __init__(self, height, width):
        self.height = height
        self.width = width
        self.cells = []

    def getmaxyx(self):
        return self.height, self.width

    def addch(self, y, x, glyph, attr):
        self.cells.append((y, x, glyph, attr))


class StyleTests(unittest.TestCase):
    def test_initialized_color_attributes_are_read_from_shared_module(self):
        original = style.MODAL_ATTR, style.HEADER_ATTR, style.FOOTER_ATTR
        try:
            with (
                patch("lantern.libs.ui_components.style.curses.has_colors", return_value=True),
                patch("lantern.libs.ui_components.style.curses.start_color"),
                patch("lantern.libs.ui_components.style.curses.init_pair"),
                patch("lantern.libs.ui_components.style.curses.color_pair", side_effect=(10, 20, 30)),
            ):
                style.init_modal_style()

            self.assertEqual(style.MODAL_ATTR, 10)
            self.assertEqual(style.HEADER_ATTR, 20 | curses.A_BOLD)
            self.assertEqual(style.FOOTER_ATTR, 30)
        finally:
            style.MODAL_ATTR, style.HEADER_ATTR, style.FOOTER_ATTR = original


class ScrollbarTests(unittest.TestCase):
    def test_draws_proportional_thumb_at_requested_position(self):
        window = FakeWindow(20, 30)

        draw_scrollbar(window, total=100, page=10, top=45, y=2, height=10, x=27)

        self.assertEqual(len(window.cells), 10)
        self.assertEqual(window.cells[0], (2, 27, " ", curses.A_DIM))
        self.assertEqual(window.cells[4], (6, 27, " ", curses.A_REVERSE))
        self.assertEqual(window.cells[-1], (11, 27, " ", curses.A_DIM))

    def test_does_not_draw_when_content_fits_viewport(self):
        window = FakeWindow(20, 30)

        draw_scrollbar(window, total=10, page=10, top=0, y=1, height=10)

        self.assertEqual(window.cells, [])


if __name__ == "__main__":
    unittest.main()
