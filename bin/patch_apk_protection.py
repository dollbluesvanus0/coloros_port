#!/usr/bin/env python3
"""APK Protection Patch for framework.jar.

Based on Apk-Protection-Patch (Mods-Center):
- In android/util/apk/ApkSignatureVerifier.smali (framework.jar):
  - remakes getMinimumSignatureSchemeVersionForTargetSdk to return 1 (returnTrue)
  - in verifySignaturesInternal, inserts `const/4 p3, 0x0` before invocations of
    `Landroid/util/apk/ApkSignatureVerifier;->verifyV`
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

RETURN_TRUE = """    .locals 1
    const/4 v0, 0x1
    return v0"""


def replace_method(content: str, method_name: str, new_body: str) -> tuple[str, bool]:
    pattern = re.compile(
        r"(?P<header>^[ \t]*\.method[^\n\r]*?[ \t]" + re.escape(method_name) + r"\([^\r\n]*\r?\n)"
        r"(?P<body>.*?)"
        r"(?P<footer>^[ \t]*\.end method)",
        re.DOTALL | re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        return content, False

    header = match.group("header")
    footer = match.group("footer")
    formatted_body = "\n" + new_body.strip("\n") + "\n"
    modified_block = f"{header}{formatted_body}{footer}"
    new_content = content[:match.start()] + modified_block + content[match.end():]
    return new_content, True


def patch_apk_signature_verifier(content: str) -> tuple[str, bool]:
    modified = False

    # 1. getMinimumSignatureSchemeVersionForTargetSdk -> return 1
    new_content, changed = replace_method(content, "getMinimumSignatureSchemeVersionForTargetSdk", RETURN_TRUE)
    if changed:
        content = new_content
        modified = True

    # 2. In verifySignaturesInternal, insert const/4 p3, 0x0 on a new line before verifyV calls
    method_pattern = re.compile(
        r"(?P<header>^[ \t]*\.method[^\n\r]*?[ \t]verifySignaturesInternal\([^\r\n]*\r?\n)"
        r"(?P<body>.*?)"
        r"(?P<footer>^[ \t]*\.end method)",
        re.DOTALL | re.MULTILINE,
    )
    match = method_pattern.search(content)
    if match:
        body = match.group("body")
        lines = body.splitlines(keepends=True)
        new_lines = []
        body_modified = False
        for line in lines:
            if "Landroid/util/apk/ApkSignatureVerifier;->verifyV" in line and "const/4 p3, 0x0" not in body:
                indent = "    "
                m_indent = re.match(r"^(\s*)", line)
                if m_indent:
                    indent = m_indent.group(1)
                new_lines.append(f"{indent}const/4 p3, 0x0\n")
                body_modified = True
            new_lines.append(line)

        if body_modified:
            new_body = "".join(new_lines)
            modified_block = f"{match.group('header')}{new_body}{match.group('footer')}"
            content = content[:match.start()] + modified_block + content[match.end():]
            modified = True

    return content, modified


def patch_apk_protection(decompiled_dir: Path | str) -> dict[str, list[str]]:
    root = Path(decompiled_dir)
    patched_records: dict[str, list[str]] = {}

    if not root.is_dir():
        print(f"[!] Directory not found: {root}")
        return patched_records

    # Target: ApkSignatureVerifier.smali in framework.jar
    for smali_file in root.rglob("ApkSignatureVerifier.smali"):
        text = smali_file.read_text(encoding="utf-8", errors="ignore")
        new_text, changed = patch_apk_signature_verifier(text)
        if changed:
            smali_file.write_text(new_text, encoding="utf-8")
            patched_records.setdefault(str(smali_file), []).append("ApkSignatureVerifier")
            print(f"[+] Patched ApkSignatureVerifier in {smali_file}")

    return patched_records


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply APK Protection patch to framework.jar smali tree")
    parser.add_argument("decompiled_dir", help="Path to decompiled framework.jar directory")
    args = parser.parse_args()

    target = Path(args.decompiled_dir)
    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        return 1

    records = patch_apk_protection(target)
    total_patched = sum(len(methods) for methods in records.values())
    print(f"[*] APK Protection patch finished. Patched {total_patched} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
