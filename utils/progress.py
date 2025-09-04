# utils/progress.py
from __future__ import annotations
import sys
import shutil
import time

# pick a safe block char; terminals that can't render will just show '#'
BLOCK = "█"
ASCII_BLOCK = "#"

def _term_width(default: int = 60) -> int:
    try:
        w = shutil.get_terminal_size((default, 20)).columns
    except Exception:
        w = default
    return max(20, min(w, 120))

def render_progress(current: int, total: int, prefix: str = "", width: int | None = None, ascii_only: bool = False) -> None:
    """
    Draw an in-place progress bar:
      [██████------] 60% (600/1000)  prefix
    """
    if total <= 0:
        return
    width = width or _term_width()
    barw = max(10, min(40, width - len(prefix) - 28))
    ratio = min(max(float(current) / float(total), 0.0), 1.0)
    filled = int(barw * ratio)
    bar_char = ASCII_BLOCK if ascii_only else BLOCK
    bar = bar_char * filled + "-" * (barw - filled)
    msg = f"\r[{bar}] {int(ratio*100):3d}% ({current}/{total})  {prefix}"
    sys.stdout.write(msg[:width])
    sys.stdout.flush()

def render_counter(current: int, prefix: str = "") -> None:
    """
    For unknown totals (e.g., JSONL streams), show a simple counter:
      processed: 12345  prefix
    """
    sys.stdout.write(f"\rprocessed: {current}  {prefix}")
    sys.stdout.flush()

def end_line() -> None:
    sys.stdout.write("\n")
    sys.stdout.flush()
