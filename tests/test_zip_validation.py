"""Tests for ZIP validation logic used in CI workflows and ROM verification."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash') and shutil.which('unzip'), 'bash and unzip are required')
class ZipValidationTests(unittest.TestCase):
    def run_validate_zip(self, zip_path):
        script = '''
        validate_zip() {
          local status=0
          unzip -tq "$1" || status=$?
          (( status == 0 || status == 1 ))
        }
        validate_zip "$1"
        '''
        return subprocess.run(
            ['bash', '-c', script, 'bash', str(zip_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            errors='replace',
            text=True,
        )

    def test_valid_zip_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            zip_path = Path(temp) / 'valid.zip'
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('entry.txt', 'test content')
            result = self.run_validate_zip(zip_path)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_zip_with_prefix_warning_exit_code_1_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            zip_path = Path(temp) / 'warning.zip'
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('payload.bin', b'0123456789' * 100)
            data = zip_path.read_bytes()
            # Prepend extra bytes so unzip warns about extra bytes (exit code 1)
            # but detects no errors in compressed data.
            zip_path.write_bytes(b'HEADER_EXTRA_BYTES_FOR_TESTING' + data)

            # Confirm raw unzip returns exit code 1
            raw_unzip = subprocess.run(
                ['unzip', '-tq', str(zip_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                errors='replace',
                text=True,
            )
            self.assertEqual(raw_unzip.returncode, 1)
            self.assertIn('No errors detected in compressed data', raw_unzip.stdout)

            # validate_zip should accept it
            result = self.run_validate_zip(zip_path)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_corrupted_zip_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            zip_path = Path(temp) / 'corrupted.zip'
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('payload.bin', b'abcdefghijklmnopqrstuvwxyz' * 200)
            # Corrupt compressed data inside
            raw_bytes = bytearray(zip_path.read_bytes())
            raw_bytes[40:48] = b'\xff' * 8
            zip_path.write_bytes(bytes(raw_bytes))

            result = self.run_validate_zip(zip_path)
            self.assertNotEqual(result.returncode, 0)

    def test_nonexistent_zip_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            zip_path = Path(temp) / 'does_not_exist.zip'
            result = self.run_validate_zip(zip_path)
            self.assertNotEqual(result.returncode, 0)
