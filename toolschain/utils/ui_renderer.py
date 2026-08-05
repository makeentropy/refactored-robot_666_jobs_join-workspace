"""
ui_renderer.py — Unicode UTF-8 Rich Terminal UI Components
===========================================================
Pure-ANSI + Unicode box-drawing toolkit.  Zero dependencies beyond
stdlib (optionally uses `rich` when available for colour).

Supports:
  • ASCII / Unicode banners (Toolschain Box splash)
  • Table renderer  ┌──┬──┐  style + lightweight sparklines
  • Progress bars  ▓▓▓▓▓░░░  and spinners
  • Status chips   ⬢ OK   ⚠ WARN   ✗ ERR
  • Sparkline      █▂▄▅▇▅▃▁  for inline time series
  • Hex dump viewer
"""

from __future__ import annotations

import shutil
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

# Colour palette (256-colour ANSI).  Graceful fallbacks when output is not a TTY.
_USE_COLOR = sys.stdout.isatty()
_RESET = "\033[0m"
_PAL = {
    "red": "\033[38;5;196m",
    "green": "\033[38;5;46m",
    "yellow": "\033[38;5;226m",
    "blue": "\033[38;5;75m",
    "cyan": "\033[38;5;51m",
    "magenta": "\033[38;5;201m",
    "grey": "\033[38;5;246m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

BANNER_LOGO = r"""
╔══════════════════════════════════════════════════════════════╗
║   ████████╗ ██████╗  ██████╗ ██╗     ███████╗ ██████╗██╗  ██╗║
║   ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝██╔════╝██║  ██║║
║      ██║   ██║   ██║██║   ██║██║     ███████╗██║     ███████║║
║      ██║   ██║   ██║██║   ██║██║     ╚════██║██║     ██╔══██║║
║      ██║   ╚██████╔╝╚██████╔╝███████╗███████║╚██████╗██║  ██║║
║      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝║
║                « Toolschain Box · v1.0.0 »                    ║
╚══════════════════════════════════════════════════════════════╝
"""

SPARK_CHARS = "▁▂▃▄▅▆▇█"
BAR_FULL, BAR_PART, BAR_EMPTY = "▓", "▒", "░"
SPIN_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _c(s: str, color: Optional[str]) -> str:
    if not _USE_COLOR or not color:
        return s
    return f"{_PAL.get(color, '')}{s}{_RESET}"


# ---------------------------------------------------------------------------
# Banner / splash
# ---------------------------------------------------------------------------
def banner(title: str = "TOOLSCHAIN BOX", subtitle: str = "Security · Finance · Data Toolkit") -> str:
    w = shutil.get_terminal_size((100, 24)).columns
    w = min(w, 96)
    top = "╔" + "═" * (w - 2) + "╗"
    mid = f"║{title:^{w-2}}║"
    sub = f"║{subtitle:^{w-2}}║"
    bot = "╚" + "═" * (w - 2) + "╝"
    return _c("\n".join([top, _c(mid, "cyan"), _c(sub, "grey"), bot]), "bold")


# ---------------------------------------------------------------------------
# Chip badges
# ---------------------------------------------------------------------------
def chip(label: str, level: str = "info") -> str:
    """Render a small status chip.  Levels: ok / warn / err / info / sim."""
    style = {
        "ok":   ("  ⬢  ", "green"),
        "warn": ("  ⚠  ", "yellow"),
        "err":  ("  ✗  ", "red"),
        "info": ("  ℹ  ", "blue"),
        "sim":  ("  ⚙  ", "magenta"),
    }.get(level, ("  ℹ  ", "blue"))
    icon, color = style
    return _c(f"{icon}{label}", color)


# ---------------------------------------------------------------------------
# Unicode table renderer
# ---------------------------------------------------------------------------
@dataclass
class TableSpec:
    headers: List[str]
    rows: List[List[str]]
    title: Optional[str] = None
    number_first_col: bool = False


def render_table(spec: TableSpec, min_width: int = 80) -> str:
    """Render a table using UTF-8 box glyphs.

    ┌──┬──┬──┐
    │Hd│Hd│Hd│
    ├──┼──┼──┤
    │r │r │r │
    └──┴──┴──┘
    """
    hdr = spec.headers[:]
    if spec.number_first_col:
        hdr = ["#"] + hdr
    rows = [list(r) for r in spec.rows]
    if spec.number_first_col:
        rows = [[str(i + 1)] + list(r) for i, r in enumerate(spec.rows)]

    def _widen(xs: List[str], extra: int) -> List[str]:
        return xs + [""] * max(0, extra - len(xs))

    ncols = max(len(hdr), max((len(r) for r in rows), default=0))
    hdr = _widen(hdr, ncols)
    rows = [_widen(r, ncols) for r in rows]
    cols_widths = [0] * ncols
    for row in [hdr] + rows:
        for i, cell in enumerate(row):
            cols_widths[i] = max(cols_widths[i], len(str(cell)))
    total_pad = 2 * ncols + ncols + 1  # padding + borders
    current = sum(cols_widths) + total_pad
    if current < min_width:
        # Distribute extra width to last column (usually amount/value)
        extra = min_width - current
        cols_widths[-1] += extra

    def _hr(kind):
        # kind: top | mid | bot
        left, mid, right, bar = {
            "top": ("┌", "┬", "┐", "─"),
            "mid": ("├", "┼", "┤", "─"),
            "bot": ("└", "┴", "┘", "─"),
        }[kind]
        return (
            left
            + mid.join(bar * (cw + 2) for cw in cols_widths)
            + right
        )

    def _row(cells: Sequence[str], bold: bool = False, color: Optional[str] = None):
        parts = []
        for i, c in enumerate(cells):
            c = str(c)
            # Alignment: numeric right-justify, text left-justify
            stripped = c.replace(",", "").replace("%", "").rstrip()
            try:
                float(stripped)
                cell = f" {c:>{cols_widths[i]}} "
            except ValueError:
                cell = f" {c:<{cols_widths[i]}} "
            if bold:
                cell = _c(cell, "bold")
            if color:
                cell = _c(cell, color)
            parts.append(cell)
        return "│" + "│".join(parts) + "│"

    out: List[str] = []
    if spec.title:
        w = sum(cols_widths) + 2 * ncols + ncols + 1
        out.append("╔" + "═" * (w - 2) + "╗")
        out.append(f"║{_c(spec.title[:w-2], 'cyan'):^{w-2}}║")
        out.append(_hr("top").replace("┌", "╟").replace("┐", "╢").replace("─", "─").replace("┬", "┼"))
    else:
        out.append(_hr("top"))
    out.append(_row(hdr, bold=True))
    out.append(_hr("mid"))
    for r in rows:
        # Colour rows with +/- pct
        color = None
        for cell in r:
            s = str(cell)
            if s.startswith("+"):
                color = "green"
            elif s.startswith("-"):
                color = "red"
        out.append(_row(r, color=color))
    out.append(_hr("bot"))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Sparkline / bar / progress
# ---------------------------------------------------------------------------
def sparkline(values: Sequence[float], width: int = 30) -> str:
    if not values:
        return ""
    vmin, vmax = min(values), max(values)
    if vmax == vmin:
        return SPARK_CHARS[4] * width
    step = (vmax - vmin) / (len(SPARK_CHARS) - 1) or 1
    out = []
    # Resample to `width` points
    n = len(values)
    for i in range(width):
        idx = min(n - 1, int(i * n / max(width, 1)))
        v = values[idx]
        bucket = min(len(SPARK_CHARS) - 1, int((v - vmin) / step))
        out.append(SPARK_CHARS[bucket])
    return "".join(out)


def progress(pct: float, width: int = 28) -> str:
    pct = max(0.0, min(1.0, pct))
    filled = int(pct * width)
    bar = BAR_FULL * filled + BAR_EMPTY * (width - filled)
    return f"[{bar}] {pct*100:5.1f}%"


def spinner_frame(i: int) -> str:
    return SPIN_FRAMES[i % len(SPIN_FRAMES)]


# ---------------------------------------------------------------------------
# Hex dump viewer
# ---------------------------------------------------------------------------
def hexdump(data: bytes, offset: int = 0, limit: Optional[int] = None) -> str:
    if limit is not None:
        data = data[:limit]
    lines: List[str] = []
    n = len(data)
    for i in range(0, n, 16):
        chunk = data[i:i + 16]
        addr = f"{offset + i:08x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<47}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {_c(addr, 'dim')}  {_c(hex_part, 'blue')}  {_c('│' + ascii_part + '│', 'grey')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section header (for CLI sub-panels)
# ---------------------------------------------------------------------------
def section(title: str, bar: str = "━") -> str:
    w = shutil.get_terminal_size((100, 24)).columns
    w = min(w, 96)
    right = bar * max(3, w - len(title) - 3)
    return _c(f"\n{title} {right}", "bold") + "\n"


# ---------------------------------------------------------------------------
# KV list renderer
# ---------------------------------------------------------------------------
def kv_pairs(items: Iterable[Tuple[str, str]], indent: int = 2) -> str:
    items = list(items)
    if not items:
        return ""
    pad = max(len(k) for k, _ in items)
    lines = []
    for k, v in items:
        lines.append(f"{' ' * indent}{_c(k.ljust(pad), 'cyan')}  {v}")
    return "\n".join(lines)
