#!/usr/bin/env python3
"""Convert SVG diagrams to PNG using PyQt6."""
import sys, os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt6.QtWidgets import QApplication
from PyQt6.QtSvgWidgets import QSvgWidget
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QPixmap, QPainter

app = QApplication(sys.argv)

SCALE = 2
base = os.path.dirname(os.path.abspath(__file__))

SIZES = {
    'encrypt': (580, 420),
    'decrypt': (580, 390),
    'sign':    (580, 400),
    'info':    (580, 380),
}

for name, (w, h) in SIZES.items():
    svg_path = os.path.join(base, f'{name}.svg')
    png_path = os.path.join(base, f'{name}.png')

    pw, ph = w * SCALE, h * SCALE

    widget = QSvgWidget()
    widget.load(svg_path)
    widget.resize(pw, ph)
    widget.setFixedSize(pw, ph)

    pixmap = QPixmap(pw, ph)
    pixmap.fill()  # white background
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    widget.render(painter)
    painter.end()

    ok = pixmap.save(png_path, 'PNG')
    print(f"  {name}.svg -> {name}.png  ({pw}x{ph})  {'OK' if ok else 'FAIL'}")

print("Done.")
