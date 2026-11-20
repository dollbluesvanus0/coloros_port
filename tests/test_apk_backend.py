"""Tests for APK backend resolution and per-artifact overrides in functions.sh."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash'), 'bash is not installed')
class ApkBackendResolutionTests(unittest.TestCase):
    def run_bash_functions(self, script, env_overrides=None):
        env = dict(os.environ)
        if env_overrides:
            env.update(env_overrides)
        full_script = f"""
source "{ROOT}/functions.sh"
{script}
"""
        return subprocess.run(
            ['bash', '-c', full_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

    def test_resolve_backend_for_artifact_defaults(self):
        script = """
        echo "Aod:$(resolve_backend_for_artifact apktool Aod.apk)"
        echo "SystemUI:$(resolve_backend_for_artifact apktool SystemUI.apk)"
        echo "OplusLauncher:$(resolve_backend_for_artifact apktool OplusLauncher.apk)"
        echo "AIUnit:$(resolve_backend_for_artifact apktool AIUnit.apk)"
        echo "HeyTapSpeechAssist:$(resolve_backend_for_artifact apktool HeyTapSpeechAssist.apk)"
        echo "OppoGallery2:$(resolve_backend_for_artifact apktool OppoGallery2.apk)"
        echo "Battery:$(resolve_backend_for_artifact apktool Battery.apk)"
        echo "Settings:$(resolve_backend_for_artifact apktool Settings.apk)"
        echo "Unknown:$(resolve_backend_for_artifact apktool UnknownApp.apk)"
        echo "Empty:$(resolve_backend_for_artifact apktool '')"
        """
        res = self.run_bash_functions(script)
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = dict(line.split(':', 1) for line in res.stdout.strip().splitlines())
        self.assertEqual(lines['Aod'], 'apkeditor')
        self.assertEqual(lines['SystemUI'], 'apkeditor')
        self.assertEqual(lines['OplusLauncher'], 'apkeditor')
        self.assertEqual(lines['AIUnit'], 'apkeditor')
        self.assertEqual(lines['HeyTapSpeechAssist'], 'apkeditor')
        self.assertEqual(lines['OppoGallery2'], 'apkeditor')
        self.assertEqual(lines['Battery'], 'apkeditor')
        self.assertEqual(lines['Settings'], 'apkeditor')
        self.assertEqual(lines['Unknown'], 'apktool')
        self.assertEqual(lines['Empty'], 'apktool')

    def test_resolve_backend_with_user_override(self):
        script = """
        echo "Aod:$(resolve_backend_for_artifact apktool Aod.apk)"
        echo "Unknown:$(resolve_backend_for_artifact apktool UnknownApp.apk)"
        """
        res = self.run_bash_functions(
            script,
            env_overrides={'APK_BACKEND_OVERRIDES': 'Aod.apk=apktool,UnknownApp.apk=apkeditor'},
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = dict(line.split(':', 1) for line in res.stdout.strip().splitlines())
        self.assertEqual(lines['Aod'], 'apktool')
        self.assertEqual(lines['Unknown'], 'apkeditor')

    def test_apk_decode_and_build_select_backend_for_aod(self):
        # Intercept java command to verify whether APKEditor or apktool is called
        script = """
        java() {
            echo "JAVA_CALL:$*"
            return 0
        }
        apk_decode "input.apk" "out_dir" --artifact Aod.apk
        apk_build "in_dir" "output.apk" --artifact Aod.apk
        """
        res = self.run_bash_functions(script)
        self.assertEqual(res.returncode, 0, res.stderr)
        calls = [line for line in res.stdout.strip().splitlines() if line.startswith('JAVA_CALL:')]
        self.assertEqual(len(calls), 2)
        # Verify both decode and build used APKEditor.jar
        self.assertIn('bin/apktool/APKEditor.jar d -f -i input.apk -o out_dir', calls[0])
        self.assertIn('bin/apktool/APKEditor.jar b -f -i in_dir -o output.apk', calls[1])

    def test_apk_decode_and_build_respect_explicit_backend(self):
        script = """
        java() {
            echo "JAVA_CALL:$*"
            return 0
        }
        apk_decode "input.apk" "out_dir" --backend apktool --artifact Aod.apk
        apk_build "in_dir" "output.apk" --backend apktool --artifact Aod.apk
        """
        res = self.run_bash_functions(script)
        self.assertEqual(res.returncode, 0, res.stderr)
        calls = [line for line in res.stdout.strip().splitlines() if line.startswith('JAVA_CALL:')]
        self.assertEqual(len(calls), 2)
        # Explicit --backend apktool must be respected
        self.assertIn('bin/apktool/apktool.jar d -f input.apk -o out_dir', calls[0])
        self.assertIn('bin/apktool/apktool.jar b -f in_dir -o output.apk', calls[1])


if __name__ == '__main__':
    unittest.main()
