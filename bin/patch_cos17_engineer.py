#!/usr/bin/env python3
"""Empty OplusEngineerFwService.onBootPhase(I)V in a decoded services JAR."""
from pathlib import Path
import re
import sys

METHOD = re.compile(r'(?m)^(\.method[^\r\n]*\b(?i:onbootphase)\(I\)V[^\r\n]*\r?\n).*?^\.end method\b', re.DOTALL)


def patch_engineer(root: Path) -> Path:
    candidates = list(root.rglob('OplusEngineerFwService.smali'))
    if len(candidates) != 1:
        raise ValueError(f'Expected one OplusEngineerFwService.smali, found {len(candidates)}')
    target = candidates[0]
    source = target.read_text(encoding='utf-8')
    matches = list(METHOD.finditer(source))
    if len(matches) != 1:
        raise ValueError(f'Expected one onBootPhase(I)V in {target}, found {len(matches)}')
    header = matches[0].group(1)
    if re.search(r'\b(?:abstract|native)\b', header):
        raise ValueError('Cannot replace an abstract/native onBootPhase method')
    result = METHOD.sub(lambda m: m.group(1) + '    .locals 0\n    return-void\n.end method', source, count=1)
    if result != source:
        target.write_text(result, encoding='utf-8', newline='')
    print(f'COS17: OplusEngineerFwService.onBootPhase(I)V -> return-void ({target})')
    return target


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: patch_cos17_engineer.py DECODED_JAR_DIRECTORY')
    patch_engineer(Path(sys.argv[1]))
