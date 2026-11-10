"""Tests for APK Protection patch in services.jar and framework.jar."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

SAMPLE_SCAN_PACKAGE_UTILS = """\
.class public Lcom/android/server/pm/ScanPackageUtils;
.super Ljava/lang/Object;

.method public static assertMinSignatureSchemeIsValid(Lcom/android/server/pm/pkg/AndroidPackage;I)V
    .locals 2
    new-instance v0, Lcom/android/server/pm/PackageManagerException;
    throw v0
.end method
"""

SAMPLE_PMS_UTILS = """\
.class public Lcom/android/server/pm/PackageManagerServiceUtils;
.super Ljava/lang/Object;

.method public static checkDowngrade(Lcom/android/server/pm/pkg/AndroidPackage;Landroid/content/pm/PackageInfoLite;)V
    .locals 2
    return-void
.end method

.method public static matchSignaturesCompat(Ljava/lang/String;Landroid/content/pm/PackageSignatures;Landroid/content/pm/SigningDetails;)Z
    .locals 3
    const/4 v0, 0x0
    return v0
.end method

.method public static matchSignaturesRecover(Ljava/lang/String;Landroid/content/pm/PackageSignatures;Landroid/content/pm/SigningDetails;I)Z
    .locals 4
    const/4 v0, 0x0
    return v0
.end method

.method public static verifySignatures(Lcom/android/server/pm/PackageSetting;Landroid/content/pm/SigningDetails;)Z
    .locals 2
    const/4 v0, 0x1
    return v0
.end method
"""

SAMPLE_APK_SIGNATURE_VERIFIER = """\
.class public Landroid/util/apk/ApkSignatureVerifier;
.super Ljava/lang/Object;

.method public static getMinimumSignatureSchemeVersionForTargetSdk(I)I
    .locals 1
    const/4 v0, 2
    return v0
.end method

.method private static verifySignaturesInternal(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;IZ)Landroid/content/pm/parsing/result/ParseResult;
    .registers 5
    invoke-static {p0, p1, p3}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;Z)Landroid/content/pm/parsing/result/ParseResult;
    move-result-object v0
    return-object v0
.end method
"""

SAMPLE_SIGNING_DETAILS = """\
.class public Landroid/content/pm/SigningDetails;
.super Ljava/lang/Object;

.method public checkCapability(Landroid/content/pm/SigningDetails;I)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public checkCapabilityRecover(Landroid/content/pm/SigningDetails;I)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public hasAncestorOrSelf(Landroid/content/pm/SigningDetails;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""

SAMPLE_PARSING_PACKAGE_UTILS = """\
.class public Lcom/android/server/pm/pkg/parsing/ParsingPackageUtils;
.super Ljava/lang/Object;

.method public parse(Landroid/content/pm/parsing/result/ParseInput;)Landroid/content/pm/parsing/result/ParseResult;
    .registers 4
    invoke-interface {p1}, Landroid/content/pm/parsing/result/ParseResult;->isError()Z
    move-result v0
    return-object p1
.end method
"""


class ApkProtectionTests(unittest.TestCase):
    def test_patch_apk_protection_modifies_target_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ScanPackageUtils.smali").write_text(SAMPLE_SCAN_PACKAGE_UTILS, encoding="utf-8")
            (root / "PackageManagerServiceUtils.smali").write_text(SAMPLE_PMS_UTILS, encoding="utf-8")
            (root / "ApkSignatureVerifier.smali").write_text(SAMPLE_APK_SIGNATURE_VERIFIER, encoding="utf-8")
            (root / "SigningDetails.smali").write_text(SAMPLE_SIGNING_DETAILS, encoding="utf-8")
            (root / "ParsingPackageUtils.smali").write_text(SAMPLE_PARSING_PACKAGE_UTILS, encoding="utf-8")

            res = subprocess.run(
                ["python3", str(ROOT / "bin" / "patch_apk_protection.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)

            # Check ScanPackageUtils
            scan_content = (root / "ScanPackageUtils.smali").read_text(encoding="utf-8")
            self.assertIn("return-void", scan_content)

            # Check PMS Utils
            pms_content = (root / "PackageManagerServiceUtils.smali").read_text(encoding="utf-8")
            self.assertIn("checkDowngrade", pms_content)
            self.assertIn("matchSignaturesCompat", pms_content)
            self.assertIn("const/4 v0, 0x0", pms_content)  # verifySignatures

            # Check ApkSignatureVerifier
            asv_content = (root / "ApkSignatureVerifier.smali").read_text(encoding="utf-8")
            self.assertIn("const/4 p3, 0x0", asv_content)

            # Check SigningDetails
            sd_content = (root / "SigningDetails.smali").read_text(encoding="utf-8")
            self.assertIn("const/4 v0, 0x1", sd_content)

            # Check ParsingPackageUtils
            parsing_content = (root / "ParsingPackageUtils.smali").read_text(encoding="utf-8")
            self.assertIn("const/4 v0, 0x0", parsing_content)

    def test_patched_smali_assembles_with_smali_jar(self):
        smali_jar = ROOT / "bin" / "apktool" / "smali-3.0.5.jar"
        if not smali_jar.is_file():
            self.skipTest("smali.jar not found")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)

            (src_dir / "ScanPackageUtils.smali").write_text(SAMPLE_SCAN_PACKAGE_UTILS, encoding="utf-8")
            (src_dir / "PackageManagerServiceUtils.smali").write_text(SAMPLE_PMS_UTILS, encoding="utf-8")
            (src_dir / "ApkSignatureVerifier.smali").write_text(SAMPLE_APK_SIGNATURE_VERIFIER, encoding="utf-8")
            (src_dir / "SigningDetails.smali").write_text(SAMPLE_SIGNING_DETAILS, encoding="utf-8")
            (src_dir / "ParsingPackageUtils.smali").write_text(SAMPLE_PARSING_PACKAGE_UTILS, encoding="utf-8")

            subprocess.run(
                ["python3", str(ROOT / "bin" / "patch_apk_protection.py"), str(src_dir)],
                check=True,
                capture_output=True,
            )

            dex_out = root / "classes.dex"
            res = subprocess.run(
                ["java", "-jar", str(smali_jar), "a", "-o", str(dex_out), str(src_dir)],
                capture_output=True,
                text=True,
            )
            out_dex = Path("out.dex")
            if not dex_out.is_file() and out_dex.is_file():
                out_dex.rename(dex_out)
            self.assertEqual(res.returncode, 0, f"Smali assemble failed: {res.stderr}\n{res.stdout}")
            self.assertTrue(dex_out.is_file(), f"classes.dex not generated. stdout: {res.stdout}, stderr: {res.stderr}")
            self.assertGreater(dex_out.stat().st_size, 0)

    def test_empty_or_missing_directory_handled_gracefully(self):
        with tempfile.TemporaryDirectory() as td:
            empty_dir = Path(td) / "empty"
            empty_dir.mkdir()
            res = subprocess.run(
                ["python3", str(ROOT / "bin" / "patch_apk_protection.py"), str(empty_dir)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Patched 0 method groups", res.stdout)


if __name__ == "__main__":
    unittest.main()
