#!/usr/bin/env python3
"""Winterlock's stencil lettering (the Permanent Way identity), drawn as SVG paths: no font file.

Cap height 20 units. Letters: A B C D E F G H I K L M N O R S T U W Y, space and full stop.
Use it for one-line headlines and the wordmark; set everything else in Atkinson Hyperlegible.

usage: python3 docs/brand/stencil.py "TURBULENT TIMES"   # prints an inline <svg> using currentColor
"""
import math
import sys

def f(n):
    s = ("%.2f" % n).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


S, G, H, K = 3.6, 1.3, 20.0, 2.4

def rect(x, y, w, h):
    return [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]

def mirror(poly, w):
    return [(w - x, y) for x, y in reversed(poly)]

def vflip(poly):
    return [(x, H - y) for x, y in reversed(poly)]

def glyph(ch):
    if ch == " ":
        return 5.5, []
    if ch == ".":
        return S, [rect(0, H - S, S, S)]
    if ch == "I":
        return S, [rect(0, 0, S, H)]
    if ch == "L":
        w = 10; return w, [rect(0, 0, S, H), rect(S + G, H - S, w - S - G, S)]
    if ch == "E":
        w = 10; return w, [rect(0, 0, S, H), rect(S + G, 0, w - S - G, S), rect(S + G, 8.2, w - S - G - 1.2, S), rect(S + G, H - S, w - S - G, S)]
    if ch == "F":
        w = 10; return w, [rect(0, 0, S, H), rect(S + G, 0, w - S - G, S), rect(S + G, 8.2, w - S - G - 1.2, S)]
    if ch == "T":
        w = 11; return w, [rect(0, 0, w, S), rect((w - S) / 2, S + G, S, H - S - G)]
    if ch == "H":
        w = 12
        left = [(0, 0), (S, 0), (S, 8.2), (w - S - G, 8.2), (w - S - G, 11.8), (S, 11.8), (S, H), (0, H)]
        return w, [left, rect(w - S, 0, S, H)]
    if ch == "N":
        w, dx = 13, 4.0
        slope = H / (w - dx)
        vg = G / math.cos(math.atan(slope))
        diag = [(0, 0), (dx, 0), (w, H), (w - dx, H)]
        left = [(0, vg), (S, S * slope + vg), (S, H), (0, H)]
        right = [(w, H - vg), (w - S, H - S * slope - vg), (w - S, 0), (w, 0)]
        return w, [diag, left, right]
    if ch == "K":
        w = 12
        chev = [(S + G, 6.4), (w - 4.3, 0), (w, 0), (S + G + 3.1, 10), (w, H), (w - 4.3, H), (S + G, 13.6)]
        return w, [rect(0, 0, S, H), chev]
    if ch == "R":
        w = 12
        bowl = [(S + G, 0), (w - K, 0), (w, K), (w, 11.8 - 1.2), (w - 1.2, 11.8), (S + G, 11.8), (S + G, 8.2), (w - S, 8.2), (w - S, S), (S + G, S)]
        leg = [(5.4, 11.8 + G), (9.2, 11.8 + G), (w, H), (w - 3.8, H)]
        return w, [rect(0, 0, S, H), bowl, leg]
    if ch == "D":
        w = 12
        bowl = [(S + G, 0), (w - K, 0), (w, K), (w, H - K), (w - K, H), (S + G, H), (S + G, H - S), (w - S, H - S), (w - S, S), (S + G, S)]
        return w, [rect(0, 0, S, H), bowl]
    if ch == "B":
        w = 12
        b = [(4.9, 0), (8.6, 0), (11, 2.4), (11, 8.6), (12, 9.8), (12, 17.6), (9.6, 20), (4.9, 20), (4.9, 16.4),
             (8.4, 16.4), (8.4, 11.8), (4.9, 11.8), (4.9, 8.2), (7.4, 8.2), (7.4, 3.6), (4.9, 3.6)]
        return w, [rect(0, 0, S, H), b]
    if ch == "O":
        w = 12; cx = w / 2
        left = [(cx - G / 2, 0), (K, 0), (0, K), (0, H - K), (K, H), (cx - G / 2, H), (cx - G / 2, H - S), (S, H - S), (S, S), (cx - G / 2, S)]
        return w, [left, mirror(left, w)]
    if ch in "CG":
        w = 11 if ch == "C" else 12; c = 6
        left = [(c - G / 2, 0), (K, 0), (0, K), (0, H - K), (K, H), (c - G / 2, H), (c - G / 2, H - S), (S, H - S), (S, S), (c - G / 2, S)]
        top = [(c + G / 2, 0), (w - K, 0), (w, K), (w, 6), (w - S, 6), (w - S, S), (c + G / 2, S)]
        if ch == "C":
            return w, [left, top, vflip(top)]
        bot = [(c + G / 2, H), (c + G / 2, H - S), (w - S, H - S), (w - S, 9 + S), (6.2, 9 + S), (6.2, 9), (w, 9), (w, H - K), (w - K, H)]
        return w, [left, top, bot]
    if ch == "U":
        w = 12; cx = w / 2
        left = [(0, 0), (S, 0), (S, H - S), (cx - G / 2, H - S), (cx - G / 2, H), (K, H), (0, H - K)]
        return w, [left, mirror(left, w)]
    if ch == "A":
        w = 12; cx = w / 2
        a = [(0, H), (0, K), (K, 0), (cx - G / 2, 0), (cx - G / 2, S), (S, S), (S, 8.2), (w - S, 8.2), (w - S, S),
             (cx + G / 2, S), (cx + G / 2, 0), (w - K, 0), (w, K), (w, H), (w - S, H), (w - S, 11.8), (S, 11.8), (S, H)]
        return w, [a]
    if ch == "M":
        w = 16; cx = w / 2
        tee = [(S + G, 0), (w - S - G, 0), (w - S - G, S), (cx + S / 2, S), (cx + S / 2, 13), (cx - S / 2, 13), (cx - S / 2, S), (S + G, S)]
        left = [(0, K), (K, 0), (S, 0), (S, H), (0, H)]
        return w, [left, mirror(left, w), tee]
    if ch == "W":
        w = 16; cx = w / 2
        tee = [(S + G, H), (S + G, H - S), (cx - S / 2, H - S), (cx - S / 2, 7), (cx + S / 2, 7), (cx + S / 2, H - S), (w - S - G, H - S), (w - S - G, H)]
        left = [(0, 0), (S, 0), (S, H), (K, H), (0, H - K)]
        return w, [left, mirror(left, w), tee]
    if ch == "S":
        w = 11
        p1 = [(K, 0), (w, 0), (w, S), (S, S), (S, 8.2 - G), (0, 8.2 - G), (0, K)]
        p2 = [(0, 8.2), (w - K, 8.2), (w, 8.2 + K), (w, H - K), (w - K, H), (0, H), (0, H - S), (w - S, H - S), (w - S, 11.8), (0, 11.8)]
        return w, [p1, p2]
    if ch == "Y":
        w = 12; cx = w / 2
        top = [(0, 0), (S, 0), (S, 8.2), (w - S, 8.2), (w - S, 0), (w, 0), (w, 11.8 - K), (w - K, 11.8), (K, 11.8), (0, 11.8 - K)]
        return w, [top, rect(cx - S / 2, 11.8 + G, S, H - 11.8 - G)]
    raise KeyError(ch)

def stencil(text, track=2.2):
    """Return (width, path d) for text set in the stencil alphabet, cap height 20."""
    x, parts = 0.0, []
    for i, ch in enumerate(text):
        w, polys = glyph(ch)
        for poly in polys:
            parts.append("M" + "L".join("%s %s" % (f(px + x), f(py)) for px, py in poly) + "Z")
        x += w + (track if i < len(text) - 1 else 0)
    return x, "".join(parts)

def stencil_svg(text, cls="", label=None, track=2.2, pad=0.0, hidden=False):
    w, d = stencil(text, track)
    aria = 'aria-hidden="true"' if hidden else 'role="img" aria-label="%s"' % (label or text.title())
    return ('<svg class="%s" viewBox="%s %s %s %s" %s><path fill="currentColor" d="%s"/></svg>'
            % (cls, f(-pad), f(-pad), f(w + 2 * pad), f(H + 2 * pad), aria, d))


if __name__ == "__main__":
    print(stencil_svg(" ".join(sys.argv[1:]).upper() or "WINTERLOCK", cls="stencil"))
