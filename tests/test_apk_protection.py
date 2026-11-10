"""Tests for APK Protection patch in framework.jar."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

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

            # Check ApkSignatureVerifier
            verifier_content = apk_smali.read_text(encoding="utf-8")
            self.assertIn("getMinimumSignatureSchemeVersionForTargetSdk", verifier_content)
            self.assertIn("const/4 v0, 0x1", verifier_content)
            self.assertIn("const/4 p3, 0x0", verifier_content)

    def test_patched_smali_assembles_with_smali_jar(self):
        smali_jar = ROOT / "bin" / "apktool" / "smali-3.0.5.jar"
        if not smali_jar.is_file():
            self.skipTest("smali.jar not found")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / "src"
            src_dir.mkdir(parents=True)

            (src_dir / "ApkSignatureVerifier.smali").write_text(SAMPLE_APK_SIGNATURE_VERIFIER, encoding="utf-8")

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
            self.assertIn("Patched 0 files", res.stdout)


if __name__ == "__main__":
    unittest.main()
