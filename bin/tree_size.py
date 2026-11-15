#!/usr/bin/env python3
"""Sum regular-file sizes in one process without following directory symlinks."""

import os
from pathlib import Path
import sys


def tree_size_bytes(root):
    if not root:
        raise NotADirectoryError(root)
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(root)
    if root.is_symlink():
        return 0
    pending = [root]
    total = 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
    return total


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: tree_size.py <directory>')
    try:
        print(tree_size_bytes(sys.argv[1]))
    except OSError as error:
        raise SystemExit(f'Cannot measure tree size: {error}') from error
