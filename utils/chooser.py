# utils/chooser.py
from __future__ import annotations
from pathlib import Path
from typing import Iterable
import humanize

def _files_in(dir_path: Path, patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pat in patterns:
        files.extend(sorted(Path(dir_path).glob(pat)))
    return [f for f in files if f.is_file()]

def select_file(dir_path: Path, patterns: list[str], title: str) -> Path:
    """
    List files in dir_path matching patterns and let user pick by index.
    Returns the selected Path.
    """
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    files = _files_in(dir_path, patterns)
    if not files:
        raise FileNotFoundError(f"No files matching {patterns} in {dir_path}")

    print(f"\n{title}\n{'='*len(title)}")
    width = max((len(f.name) for f in files), default=10)
    for i, f in enumerate(files, start=1):
        size = humanize.naturalsize(f.stat().st_size, binary=False)  # e.g. "12.3 MB"
        print(f"[{i:>2}] {f.name:<{width}}  {size}")
    while True:
        try:
            choice = int(input(f"Select (1-{len(files)}): "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
        except ValueError:
            pass
        print("Invalid selection. Try again.")
