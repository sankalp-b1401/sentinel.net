#!/usr/bin/env python3
"""
UI helpers and banner for sentinel.net

- print_banner()
- semantic printers: info, warn, err, ok
- prompt_hint_and_input(prefix, prompt_text, color_name) -> str
  (prints a single colored '[?] Prompt: ' and returns input)
- ask_yes_no(prompt, default) -> bool
- select_pcap_interactive(capture_dir) -> Path | None
Uses `humanize` for sizes when available, otherwise falls back to a simple formatter.
"""
from __future__ import annotations
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path

# Detect whether ANSI should be used
_USE_ANSI = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

RESET = "\033[0m"
CODES = {
    "green": "92",
    "yellow": "93",
    "red": "91",
    "cyan": "96",
    "bold": "1",
}


def _ansi(text: str, code: str) -> str:
    if not _USE_ANSI or not code:
        return text
    return f"\033[{code}m{text}{RESET}"


def color(text: str, name: str) -> str:
    code = CODES.get(name, "")
    return _ansi(text, code)


def info(msg: str) -> None:
    print(color(f"[info] {msg}", "green"))


def warn(msg: str) -> None:
    print(color(f"[warn] {msg}", "yellow"))


def err(msg: str) -> None:
    print(color(f"[err] {msg}", "red"))


def ok(msg: str) -> None:
    print(color(f"[ok] {msg}", "cyan"))


# ---------------- Banner -----------------
def _ansi_rgb(r: int, g: int, b: int) -> str:
    return f"\x1b[38;2;{r};{g};{b}m"


def _ansi_reset() -> str:
    return "\x1b[0m"


def _center(line: str, width: int) -> str:
    line = line.rstrip("\n")
    pad = max(0, (width - len(line)) // 2)
    return " " * pad + line


def _dynamic_rule(padding: int = 10, min_len: int = 40, max_len: int = 0) -> str:
    cols = shutil.get_terminal_size((100, 24)).columns
    if max_len and max_len > 0:
        length = max(min_len, min(max_len, cols - padding))
    else:
        length = max(min_len, cols - padding)
    return "─" * max(1, length)


def print_banner() -> None:
    """
    Print the multi-line ASCII banner centered as a single block,
    color each line with a subtle gradient, and center the 'sentinel.net'
    label under the banner using the banner block width.
    """
    cols = shutil.get_terminal_size((100, 24)).columns
    banner = r"""
   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
""".rstrip("\n")

    # Split preserving leading spaces
    lines = banner.splitlines()
    if not lines:
        return

    # Determine banner block width (the widest line length)
    banner_width = max(len(line) for line in lines)

    # Compute left padding so the entire block is centered in the terminal
    left_pad = max(0, (cols - banner_width) // 2)

    use_color = _USE_ANSI

    # Gradient colors from `start` to `end`
    if use_color:
        start = (0, 230, 255)
        end = (0, 150, 200)
        n = max(1, len(lines))
        colored = []
        for idx, raw in enumerate(lines):
            t = idx / max(1, n - 1)
            r = int(start[0] + (end[0] - start[0]) * t)
            g = int(start[1] + (end[1] - start[1]) * t)
            b = int(start[2] + (end[2] - start[2]) * t)
            # preserve leading spaces by not stripping/centering the raw line itself,
            # but prefix with left_pad spaces to center the whole block.
            colored_line = " " * left_pad + _ansi_rgb(r, g, b) + raw + _ansi_reset()
            colored.append(colored_line)
        print("\n".join(colored))
        # dynamic rule exactly under the block
        rule = _dynamic_rule(padding=0, min_len=banner_width, max_len=banner_width)
        print(" " * left_pad + _ansi_rgb(0, 180, 200) + rule + _ansi_reset())
    else:
        for raw in lines:
            print(" " * left_pad + raw)
        print(" " * left_pad + _dynamic_rule(padding=0, min_len=banner_width, max_len=banner_width))

    # Now print the sentinel.net label centered relative to the banner block
    label = "sentinel.net"
    label_pad = left_pad + max(0, (banner_width - len(label)) // 2)
    if use_color:
        print(" " * label_pad + _ansi_rgb(0, 200, 220) + label + _ansi_reset())
    else:
        print(" " * label_pad + label)

    print()  # small gap after banner

    # description block (unchanged) - center relative to terminal width (not necessary to match banner)
    description_lines = [
        "A multi-agent network monitoring and automated anomaly detection system.",
        "",
        "[ * ] Real-time packet capture and flow analysis",
        "[ * ] Automated anomaly detection using intelligent agents",
        "[ * ] Flexible operation modes: capture, save, or send flows",
        "[ * ] Extensible and designed for security operations",
        "[ * ] Optimized for performance in large-scale environments",
        "",
        "Author: Sankalp Bansal",
    ]
    block_width = max(len(ln) for ln in description_lines)
    cols_now = shutil.get_terminal_size((100, 24)).columns
    left_pad_desc = max(0, (cols_now - block_width) // 2)

    if use_color:
        cyan = _ansi_rgb(0, 200, 220)
        reset = _ansi_reset()
        for ln in description_lines:
            line_to_print = " " * left_pad_desc + ln.ljust(block_width)
            print(cyan + line_to_print + reset)
    else:
        for ln in description_lines:
            line_to_print = " " * left_pad_desc + ln.ljust(block_width)
            print(line_to_print)

    # trailing rule that spans terminal width
    cols_after = shutil.get_terminal_size((100, 24)).columns
    if use_color:
        print(_ansi_rgb(0, 180, 200) + _center(_dynamic_rule(), cols_after) + _ansi_reset())
    else:
        print(_center(_dynamic_rule(), cols_after))
    print()


# ----------------- size + time helpers --------------------
# Prefer humanize.naturalsize when available (gnu-style), otherwise fallback.
def human_size(n: int) -> str:
    try:
        import humanize  # type: ignore
        # gnu=True gives short units like '77K', '3.2M' similar to `ls -lh`
        return humanize.naturalsize(n, binary=False, gnu=True)
    except Exception:
        # fallback: simple formatter (powers of 1000)
        units = ['B', 'K', 'M', 'G', 'T']
        x = float(n)
        for u in units:
            if x < 1000.0:
                if u == 'B':
                    return f"{int(x)}{u}"
                return f"{x:.1f}{u}"
            x /= 1000.0
        return f"{x:.1f}P"


def fmt_mtime_ls(p: Path) -> str:
    ts = p.stat().st_mtime
    return datetime.fromtimestamp(ts).strftime('%b %d %H:%M')


# ----------------- prompt helpers --------------------
def prompt_hint_and_input(prefix: str, prompt_text: str, color_name: str = "yellow") -> str:
    """
    Print a single colored prefix + prompt and return the user input.
    - prefix: e.g. "[?]"
    - prompt_text: e.g. "Select pcap [0-24]"    (DO NOT include trailing colon)
    The function will print: "[?] Select pcap [0-24]: " (colored) and return input().
    """
    color_code = CODES.get(color_name, "")
    if not _USE_ANSI or not color_code:
        return input(f"{prefix} {prompt_text}: ")

    final = _ansi(prefix, color_code) + " " + _ansi(prompt_text + ": ", color_code)
    sys.stdout.write(final)
    sys.stdout.flush()
    return input("")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    yes_no = "Y/n" if default else "y/N"
    while True:
        raw = prompt_hint_and_input("[?]", f"{prompt} [{yes_no}]", color_name="yellow")
        ans = raw.strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer y or n.")


def select_pcap_interactive(capture_dir: Path) -> Path | None:
    """
    Show an `ls -lh`-style listing with an index column and allow selection.
    Returns Path for selected file or None for 'capture new'.
    """
    capture_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(capture_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        info("No PCAPs in capture_logs. Choose 'Capture new pcap' to create one.")
        return None

    idx_w = 4
    size_w = 8
    date_w = 12
    name_w = max(30, max(len(p.name) for p in files))
    sep = "  "

    hdr = f"{'No.'.ljust(idx_w)}{sep}{'Size'.rjust(size_w)}{sep}{'Modified'.ljust(date_w)}{sep}Name"
    print("\n" + color(hdr, "yellow"))
    print(color("-" * (idx_w + size_w + date_w + name_w + len(sep) + 10), "yellow"))

    for i, p in enumerate(files, start=1):
        size = human_size(p.stat().st_size)
        mtime = fmt_mtime_ls(p)
        name = p.name
        print(f"{str(i).ljust(idx_w)}{sep}{size.rjust(size_w)}{sep}{mtime.ljust(date_w)}{sep}{name}")

    print("\n0) Capture new pcap now")

    while True:
        sel_raw = prompt_hint_and_input("[?]", f"Select pcap [0-{len(files)}]", color_name="yellow").strip()
        try:
            sel = int(sel_raw)
            if 0 <= sel <= len(files):
                return None if sel == 0 else files[sel - 1]
        except ValueError:
            pass
        print("Invalid selection — enter a number.")
