"""Tests for APK Protection patch in services.jar and framework.jar."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

SAMPLE_PARSING_PACKAGE_UTILS = """\
.class public Lcom/android/server/pm/pkg/parsing/ParsingPackageUtils;
.super Ljava/lang/Object;

.method public static getSigningDetails(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;ZZLandroid/content/pm/SigningDetails;I)Landroid/content/pm/parsing/result/ParseResult;
    .registers 10
    const-string v0, "stock"
    return-object p0
.end method
"""

SAMPLE_SCAN_PACKAGE_UTILS = """\
.class public Lcom/android/server/pm/ScanPackageUtils;
.super Ljava/lang/Object;

.method public static assertMinSignatureSchemeIsValid(Lcom/android/server/pm/pkg/AndroidPackage;I)V
    .locals 2
    new-instance v0, Lcom/android/server/pm/PackageManagerException;
    const-string v1, "Signature scheme invalid"
    invoke-direct {v0, v1}, Lcom/android/server/pm/PackageManagerException;-><init>(Ljava/lang/String;)V
    throw v0
.end method
"""

SAMPLE_PMS_UTILS = """\
.class public Lcom/android/server/pm/PackageManagerServiceUtils;
.super Ljava/lang/Object;

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
"""

SAMPLE_APK_SIGNATURE_VERIFIER = """\
.class public Landroid/util/apk/ApkSignatureVerifier;
.super Ljava/lang/Object;

.method public static getMinimumSignatureSchemeVersionForTargetSdk(I)I
    .locals 1
    const/4 v0, 0x2
    return v0
.end method

.method private static verifySignaturesInternal(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;IZ)Landroid/content/pm/parsing/result/ParseResult;
    .registers 5
    invoke-static {p0, p1, p2}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;I)Landroid/content/pm/parsing/result/ParseResult;
    move-result-object v0
    return-object v0
.end method
"""


class ApkProtectionTests(unittest.TestCase):
    def test_patch_apk_protection_modifies_target_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg_dir = root / "smali" / "com" / "android" / "server" / "pm" / "pkg" / "parsing"
            pkg_dir.mkdir(parents=True)
            parsing_smali = pkg_dir / "ParsingPackageUtils.smali"
            parsing_smali.write_text(SAMPLE_PARSING_PACKAGE_UTILS, encoding="utf-8")

            pm_dir = root / "smali" / "com" / "android" / "server" / "pm"
            scan_smali = pm_dir / "ScanPackageUtils.smali"
            scan_smali.write_text(SAMPLE_SCAN_PACKAGE_UTILS, encoding="utf-8")

            pms_smali = pm_dir / "PackageManagerServiceUtils.smali"
            pms_smali.write_text(SAMPLE_PMS_UTILS, encoding="utf-8")

            apk_dir = root / "smali" / "android" / "util" / "apk"
            apk_dir.mkdir(parents=True)
            apk_smali = apk_dir / "ApkSignatureVerifier.smali"
            apk_smali.write_text(SAMPLE_APK_SIGNATURE_VERIFIER, encoding="utf-8")

            res = subprocess.run(
                ["python3", str(ROOT / "bin" / "patch_apk_protection.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)

            # Check ParsingPackageUtils
            parsing_content = parsing_smali.read_text(encoding="utf-8")
            self.assertIn("unsafeGetCertsWithoutVerification", parsing_content)
            self.assertIn("if-eqz p4, :cond_ret_v1", parsing_content)
            self.assertIn("if-eq p4, v2, :cond_ret_v1", parsing_content)

            # Check ScanPackageUtils
            scan_content = scan_smali.read_text(encoding="utf-8")
            self.assertIn("return-void", scan_content)
            self.assertNotIn("PackageManagerException", scan_content)

            # Check PackageManagerServiceUtils (returns true)
            pms_content = pms_smali.read_text(encoding="utf-8")
            self.assertIn("matchSignaturesCompat", pms_content)
            self.assertIn("matchSignaturesRecover", pms_content)
            self.assertIn("const/4 v0, 0x1", pms_content)

            # Check ApkSignatureVerifier
            verifier_content = apk_smali.read_text(encoding="utf-8")
            self.assertIn("getMinimumSignatureSchemeVersionForTargetSdk", verifier_content)
            self.assertIn("const/4 p2, 0x0", verifier_content)

    def test_patched_smali_assembles_with_smali_jar(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)

            (src_dir / "ParsingPackageUtils.smali").write_text(SAMPLE_PARSING_PACKAGE_UTILS, encoding="utf-8")
            (src_dir / "ScanPackageUtils.smali").write_text(SAMPLE_SCAN_PACKAGE_UTILS, encoding="utf-8")
            (src_dir / "PackageManagerServiceUtils.smali").write_text(SAMPLE_PMS_UTILS, encoding="utf-8")
            (src_dir / "ApkSignatureVerifier.smali").write_text(SAMPLE_APK_SIGNATURE_VERIFIER, encoding="utf-8")

            # Apply patch
            subprocess.run(
                ["python3", str(ROOT / "bin" / "patch_apk_protection.py"), str(src_dir)],
                check=True,
                capture_output=True,
            )

            # Assemble into dex
            dex_out = root / "classes.dex"
            res = subprocess.run(
                ["java", "-jar", str(ROOT / "bin" / "apktool" / "smali-3.0.5.jar"), "a", str(src_dir), "-o", str(dex_out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Smali assemble failed: {res.stderr}\n{res.stdout}")
            self.assertTrue(dex_out.is_file())
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
            self.assertIn("Patched 0 methods", res.stdout)


if __name__ == "__main__":
    unittest.main()
