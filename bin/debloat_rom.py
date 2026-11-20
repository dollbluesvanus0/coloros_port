#!/usr/bin/env python3
"""Remove explicitly listed donor paths without following escaping symlinks."""
import argparse
from pathlib import Path
import shutil


def debloat(root: Path, manifest: Path) -> list[str]:
    root = root.resolve(strict=True)
    targets = set()
    for raw in manifest.read_text(encoding='utf-8').splitlines():
        pattern = raw.strip()
        if not pattern or pattern.startswith('#'):
            continue
        pattern_path = Path(pattern)
        parts = pattern_path.parts
        if len(parts) < 2 or parts[0] not in ('my_product', 'my_stock', 'my_preload', 'system_ext') or '..' in parts or pattern_path.is_absolute() or pattern_path.drive:
            raise ValueError(f'Unsafe debloat path: {pattern}')
        for path in root.glob(pattern):
            # Resolve the parent only: an escaping leaf symlink may be
            # unlinked safely, but an escaping ancestor must never be used.
            path.parent.resolve().relative_to(root)
            targets.add(path)
    removed = []
    for path in sorted(targets, key=lambda p: (len(p.parts), str(p))):
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_dir():
            path.unlink()
        else:
            shutil.rmtree(path)
        relative = str(path.relative_to(root))
        print(f'Debloat: removed {relative}', flush=True)
        removed.append(relative)
    print(f'Debloat: removed {len(removed)} paths', flush=True)
    return removed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('images', type=Path)
    args = parser.parse_args()
    debloat(args.images, Path(__file__).with_name('donor-debloat.txt'))
