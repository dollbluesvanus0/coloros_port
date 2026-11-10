#!/usr/bin/env python3
"""APK Protection and Signature Verification Bypass Patch for services.jar and framework.jar.

Applies comprehensive patches to disable signature verification, app downgrade checks,
and integrity verification for ColorOS / Android 14-17:
- ScanPackageUtils: assertMinSignatureSchemeIsValid -> return-void
- PackageManagerServiceUtils:
    - checkDowngrade -> return-void (bypass version downgrade block)
    - verifySignatures -> return false (bypass PackageManagerException)
    - matchSignaturesCompat / matchSignaturesRecover -> return true (1)
- ApkSignatureVerifier:
    - getMinimumSignatureSchemeVersionForTargetSdk -> return 0
    - verifySignaturesInternal -> inject const/4 p3, 0x0 before verifyV calls (verifyFull=false)
- SigningDetails / PackageParser$SigningDetails:
    - checkCapability / checkCapabilityRecover / hasAncestorOrSelf -> return true (1)
- ParsingPackageUtils:
    - Neutralize ParseResult.isError() after verification checks
- StrictJarVerifier:
    - verifyMessageDigest -> return true (1)
- ReconcilePackageUtils:
    - Force ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS = 1
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

RETURN_VOID = """    .locals 0
    return-void"""

RETURN_TRUE = """    .locals 1
    const/4 v0, 0x1
    return v0"""

RETURN_ZERO = """    .locals 1
    const/4 v0, 0x0
    return v0"""

RETURN_FALSE = RETURN_ZERO


def replace_all_methods(content: str, method_name: str, new_body: str) -> tuple[str, bool]:
    pattern = re.compile(
        r"(?P<header>^[ \t]*\.method[^\n\r]*?[ \t]" + re.escape(method_name) + r"\(.*?)"
        r"(?P<body>.*?)"
        r"(?P<footer>^[ \t]*\.end method)",
        re.DOTALL | re.MULTILINE,
    )
    if not pattern.search(content):
        return content, False

    formatted_body = "\n" + new_body.strip("\n") + "\n"
    new_content = pattern.sub(rf"\g<header>{formatted_body}\g<footer>", content)
    return new_content, True


def patch_scan_package_utils(content: str) -> tuple[str, bool]:
    return replace_all_methods(content, "assertMinSignatureSchemeIsValid", RETURN_VOID)


def patch_pms_utils(content: str) -> tuple[str, bool]:
    modified = False
    for method in ("checkDowngrade",):
        new_content, changed = replace_all_methods(content, method, RETURN_VOID)
        if changed:
            content, modified = new_content, True

    for method in ("matchSignaturesCompat", "matchSignaturesRecover"):
        new_content, changed = replace_all_methods(content, method, RETURN_TRUE)
        if changed:
            content, modified = new_content, True

    for method in ("verifySignatures",):
        new_content, changed = replace_all_methods(content, method, RETURN_FALSE)
        if changed:
            content, modified = new_content, True

    return content, modified


def patch_apk_signature_verifier(content: str) -> tuple[str, bool]:
    modified = False

    # 1. getMinimumSignatureSchemeVersionForTargetSdk -> return 0
    new_content, changed = replace_all_methods(
        content, "getMinimumSignatureSchemeVersionForTargetSdk", RETURN_ZERO
    )
    if changed:
        content, modified = new_content, True

    # 2. In verifySignaturesInternal, set verifyFull (p3) to 0 before verifyV calls
    method_pattern = re.compile(
        r"(?P<header>^[ \t]*\.method[^\n\r]*?verifySignaturesInternal[^\n\r]*)"
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
            if "Landroid/util/apk/ApkSignatureVerifier;->verifyV" in line:
                indent = "    "
                m_indent = re.match(r"^(\s*)", line)
                if m_indent:
                    indent = m_indent.group(1)
                if "const/4 p3, 0x0" not in "".join(new_lines[-3:]):
                    new_lines.append(f"{indent}const/4 p3, 0x0\n")
                    body_modified = True
            new_lines.append(line)

        if body_modified:
            new_body = "".join(new_lines)
            modified_block = f"{match.group('header')}{new_body}{match.group('footer')}"
            content = content[:match.start()] + modified_block + content[match.end():]
            modified = True

    return content, modified


def patch_signing_details(content: str) -> tuple[str, bool]:
    modified = False
    for method in ("checkCapability", "checkCapabilityRecover", "hasAncestorOrSelf"):
        new_content, changed = replace_all_methods(content, method, RETURN_TRUE)
        if changed:
            content, modified = new_content, True
    return content, modified


def patch_parsing_package_utils(content: str) -> tuple[str, bool]:
    modified = False
    lines = content.splitlines(keepends=True)
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        if "Landroid/content/pm/parsing/result/ParseResult;->isError()Z" in line:
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                m = re.search(r"^\s*move-result\s+([vp]\d+)", next_line)
                if m:
                    reg = m.group(1)
                    indent = re.match(r"^(\s*)", next_line).group(1)
                    new_lines.append(next_line)
                    new_lines.append(f"{indent}const/4 {reg}, 0x0\n")
                    i += 2
                    modified = True
                    continue
        i += 1
    if modified:
        return "".join(new_lines), True
    return content, False


def patch_reconcile_package_utils(content: str) -> tuple[str, bool]:
    modified = False
    lines = content.splitlines(keepends=True)
    new_lines = []
    for line in lines:
        m = re.search(
            r"^\s*sput-boolean\s+([vp]\d+),\s*Lcom/android/server/pm/ReconcilePackageUtils;->ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS:Z",
            line,
        )
        if m:
            reg = m.group(1)
            indent = re.match(r"^(\s*)", line).group(1)
            new_lines.append(f"{indent}const/4 {reg}, 0x1\n")
            modified = True
        new_lines.append(line)
    if modified:
        return "".join(new_lines), True
    return content, False


def patch_strict_jar_verifier(content: str) -> tuple[str, bool]:
    return replace_all_methods(content, "verifyMessageDigest", RETURN_TRUE)


def patch_apk_protection(decompiled_dir: Path | str) -> dict[str, list[str]]:
    root = Path(decompiled_dir)
    patched_records: dict[str, list[str]] = {}

    if not root.is_dir():
        print(f"[!] Directory not found: {root}")
        return patched_records

    for smali_file in root.rglob("*.smali"):
        name = smali_file.name
        text = smali_file.read_text(encoding="utf-8", errors="ignore")
        changed = False

        if name == "ScanPackageUtils.smali":
            new_text, changed = patch_scan_package_utils(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("ScanPackageUtils")

        elif name == "PackageManagerServiceUtils.smali":
            new_text, changed = patch_pms_utils(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("PackageManagerServiceUtils")

        elif name == "ApkSignatureVerifier.smali":
            new_text, changed = patch_apk_signature_verifier(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("ApkSignatureVerifier")

        elif name in ("SigningDetails.smali", "PackageParser$SigningDetails.smali"):
            new_text, changed = patch_signing_details(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("SigningDetails")

        elif name == "ParsingPackageUtils.smali":
            new_text, changed = patch_parsing_package_utils(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("ParsingPackageUtils")

        elif name == "ReconcilePackageUtils.smali":
            new_text, changed = patch_reconcile_package_utils(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("ReconcilePackageUtils")

        elif name == "StrictJarVerifier.smali":
            new_text, changed = patch_strict_jar_verifier(text)
            if changed:
                patched_records.setdefault(str(smali_file), []).append("StrictJarVerifier")

        if changed:
            smali_file.write_text(new_text, encoding="utf-8")
            print(f"[+] Patched {patched_records[str(smali_file)]} in {smali_file}")

    return patched_records


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply APK Protection patch to JAR smali tree")
    parser.add_argument("decompiled_dir", help="Path to decompiled services.jar or framework.jar directory")
    args = parser.parse_args()

    target = Path(args.decompiled_dir)
    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        return 1

    records = patch_apk_protection(target)
    total_patched = sum(len(methods) for methods in records.values())
    print(f"[*] APK Protection patch finished. Patched {total_patched} method groups across {len(records)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
