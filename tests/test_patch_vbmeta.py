"""Tests for bin/patch-vbmeta.py AVB flag patching and error handling."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'bin' / 'patch-vbmeta.py'


class PatchVbmetaTests(unittest.TestCase):
    def run_patcher(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_valid_vbmeta_sets_disable_flags_at_offset_123(self):
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'vbmeta.img'
            payload = bytearray(b'AVB0' + b'\x00' * 252)
            img.write_bytes(payload)
            res = self.run_patcher(str(img))
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn('Patching successful', res.stdout)
            patched = img.read_bytes()
            self.assertEqual(len(patched), 256)
            self.assertEqual(patched[123], 0x03)

    def test_invalid_magic_exits_cleanly_without_attribute_error(self):
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'not_vbmeta.img'
            original = b'NOPE' + b'\x11' * 252
            img.write_bytes(original)
            res = self.run_patcher(str(img))
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn('AttributeError', res.stderr)
            self.assertIn('not a valid vbmeta image', res.stderr)
            self.assertEqual(img.read_bytes(), original)

    def test_truncated_vbmeta_rejected_without_extending_file(self):
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'short_vbmeta.img'
            original = b'AVB0' + b'\x00' * 32
            img.write_bytes(original)
            res = self.run_patcher(str(img))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn('too small', res.stderr)
            self.assertEqual(img.read_bytes(), original)

    def test_missing_file_and_bad_usage(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / 'absent.img'
            res = self.run_patcher(str(missing))
            self.assertNotEqual(res.returncode, 0)
            self.assertIn('Error reading file', res.stderr)
        usage = self.run_patcher()
        self.assertNotEqual(usage.returncode, 0)
        self.assertIn('Usage:', usage.stderr)


if __name__ == '__main__':
    unittest.main()
