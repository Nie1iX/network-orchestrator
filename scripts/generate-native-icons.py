#!/usr/bin/env python3
"""Convert src/icons.tsx SVG geometry to native vector PDF resources.
Requires reportlab only when icons change; generated PDFs are checked in.
"""
from pathlib import Path
import hashlib
import re
import xml.etree.ElementTree as ET
from reportlab import rl_config
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, PolyLine
from reportlab.graphics.svgpath import SvgPath
from reportlab.graphics import renderPDF
from reportlab.lib.colors import black

rl_config.invariant = 1
root = Path(__file__).resolve().parent.parent
source = (root / 'src/icons.tsx').read_text()
output = root / 'macos/Sources/NetworkOrchestrator/Resources/Icons'
output.mkdir(parents=True, exist_ok=True)
for name, body in re.findall(r'export function (\w+)\([^\n]*\{(.*?)\n\}', source, re.S):
    svg = re.search(r'<svg[^>]*>(.*?)</svg>', body, re.S)
    if not svg:
        continue
    drawing = Drawing(24, 24)
    drawing.transform = (1, 0, 0, -1, 0, 24)
    for node in ET.fromstring('<svg>' + svg[1] + '</svg>'):
        a = node.attrib
        val = lambda k, default=0: float(a.get(k, default))
        if node.tag == 'path':
            shape = SvgPath(a['d'], fillColor=None)
        elif node.tag == 'rect':
            shape = Rect(val('x'), val('y'), val('width'), val('height'), rx=val('rx'), ry=val('rx'), fillColor=None)
        elif node.tag == 'circle':
            shape = Circle(val('cx'), val('cy'), val('r'), fillColor=None)
        elif node.tag == 'line':
            shape = Line(val('x1'), val('y1'), val('x2'), val('y2'))
        elif node.tag == 'polyline':
            shape = PolyLine([float(n) for n in a['points'].split()], fillColor=None)
        else:
            raise ValueError(node.tag)
        shape.strokeColor = black
        shape.strokeWidth = 2
        shape.strokeLineCap = 1
        shape.strokeLineJoin = 1
        drawing.add(shape)
    renderPDF.drawToFile(drawing, str(output / (name + '.pdf')))
(output / 'source.sha256').write_text(hashlib.sha256(source.encode()).hexdigest() + '\n')
