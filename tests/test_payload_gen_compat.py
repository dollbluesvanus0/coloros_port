"""Compatibility and integration tests for Rust payload-gen and AOSP delta_generator."""

import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
KEY_PK8 = ROOT / 'otatools' / 'key' / 'testkey.pk8'
CERT_PEM = ROOT / 'otatools' / 'key' / 'testkey.x509.pem'
DELTA_GEN = ROOT / 'otatools' / 'bin' / 'delta_generator'


def resolve_payload_gen_cmd():
    """Return [exe] or [coloros-tools, 'payload-gen'] if a built Rust binary exists."""
    sys_os = platform.system()
    arch = platform.machine().lower()
    if arch in ('amd64', 'x86_64'):
        arch_dir = 'x86_64'
    elif arch in ('arm64', 'aarch64'):
        arch_dir = 'aarch64'
    else:
        arch_dir = arch

    ext = '.exe' if sys_os == 'Windows' else ''
    candidates = [
        (ROOT / 'bin' / sys_os / arch_dir / f'payload-gen{ext}', []),
        (ROOT / 'bin' / sys_os / arch_dir / f'coloros-tools{ext}', ['payload-gen']),
        (ROOT / 'tools-rust' / 'target' / 'release' / f'payload-gen{ext}', []),
        (ROOT / 'tools-rust' / 'target' / 'release' / f'coloros-tools{ext}', ['payload-gen']),
    ]
    for binary, prefix in candidates:
        if binary.is_file() and (sys_os == 'Windows' or os.access(binary, os.X_OK)):
            return [str(binary), *prefix]

    for name, prefix in (('payload-gen', []), ('coloros-tools', ['payload-gen'])):
        found = shutil.which(name)
        if found:
            return [found, *prefix]
    return None


def parse_properties(path: Path) -> dict[str, str]:
    props = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        k, v = line.split('=', 1)
        props[k.strip()] = v.strip()
    return props


class PayloadGenCompatTests(unittest.TestCase):
    def setUp(self):
        self.cmd = resolve_payload_gen_cmd()
        if self.cmd is None:
            self.skipTest('payload-gen / coloros-tools binary is not built or on PATH')

    def _create_fixture_images(self, root: Path) -> tuple[Path, Path, Path]:
        images = root / 'IMAGES'
        images.mkdir(parents=True)
        # Block-aligned (4096 bytes) images mixing zero blocks (ZERO op) and data blocks
        (images / 'system.img').write_bytes((b'\x00' * 8192) + (b'COS16DATA' * 4096))
        (images / 'vendor.img').write_bytes((b'\x00' * 4096) + (b'VENDORDAT' * 2048))

        dyn_info = root / 'dynamic_partitions_info.txt'
        dyn_info.write_text(
            '\n'.join([
                'super_partition_size=134217728',
                'super_partition_groups=qti_dynamic_partitions',
                'super_qti_dynamic_partitions_group_size=133169152',
                'super_qti_dynamic_partitions_partition_list=system vendor',
                'virtual_ab=true',
                'virtual_ab_compression=true',
            ]) + '\n',
            encoding='utf-8',
        )

        metadata = root / 'metadata'
        metadata.write_text('ota-type=AB\npost-sdk-level=36\n', encoding='utf-8')
        return images, dyn_info, metadata

    def test_generate_verify_and_package_ota_zip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            images, dyn_info, metadata = self._create_fixture_images(root)
            payload_bin = root / 'payload.bin'
            props_txt = root / 'payload_properties.txt'
            ota_zip = root / 'unsigned_ota.zip'

            gen = subprocess.run(
                [
                    *self.cmd,
                    'generate',
                    '--images-dir', str(images),
                    '--partitions', 'system,vendor',
                    '--out-file', str(payload_bin),
                    '--properties-out', str(props_txt),
                    '--dynamic-partitions-info', str(dyn_info),
                    '--private-key', str(KEY_PK8),
                    '--compression', 'fast-xz',
                    '--major-version', '2',
                    '--minor-version', '0',
                    '--ota-zip', str(ota_zip),
                    '--metadata-file', str(metadata),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(gen.returncode, 0, gen.stdout + gen.stderr)

            raw = payload_bin.read_bytes()
            self.assertGreater(len(raw), 24)
            self.assertEqual(raw[:4], b'CrAU')
            major_ver = struct.unpack('>Q', raw[4:12])[0]
            self.assertEqual(major_ver, 2)

            props = parse_properties(props_txt)
            for key in ('FILE_HASH', 'FILE_SIZE', 'METADATA_HASH', 'METADATA_SIZE'):
                self.assertIn(key, props)
                self.assertTrue(props[key])
            self.assertEqual(int(props['FILE_SIZE']), len(raw))

            with zipfile.ZipFile(ota_zip) as zf:
                names = set(zf.namelist())
                self.assertIn('payload.bin', names)
                self.assertIn('payload_properties.txt', names)
                self.assertIn('META-INF/com/android/metadata', names)
                for info in zf.infolist():
                    if info.filename in ('payload.bin', 'payload_properties.txt', 'META-INF/com/android/metadata'):
                        self.assertEqual(info.compress_type, zipfile.ZIP_STORED)

            verify = subprocess.run(
                [
                    *self.cmd,
                    'verify',
                    '--file', str(payload_bin),
                    '--public-key', str(CERT_PEM),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    @unittest.skipUnless(
        sys.platform == 'linux'
        and platform.machine().lower() in ('x86_64', 'amd64')
        and DELTA_GEN.is_file()
        and os.access(DELTA_GEN, os.X_OK),
        'Linux x86_64 otatools/bin/delta_generator is required',
    )
    def test_delta_generator_interoperability(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            images, dyn_info, _ = self._create_fixture_images(root)
            payload_bin = root / 'payload.bin'
            rust_props_path = root / 'rust_properties.txt'
            dg_props_path = root / 'dg_properties.txt'

            gen = subprocess.run(
                [
                    *self.cmd,
                    'generate',
                    '--images-dir', str(images),
                    '--partitions', 'system,vendor',
                    '--out-file', str(payload_bin),
                    '--properties-out', str(rust_props_path),
                    '--dynamic-partitions-info', str(dyn_info),
                    '--private-key', str(KEY_PK8),
                    '--compression', 'fast-xz',
                    '--major-version', '2',
                    '--minor-version', '0',
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(gen.returncode, 0, gen.stdout + gen.stderr)

            env = dict(os.environ)
            lib64 = str(ROOT / 'otatools' / 'lib64')
            env['LD_LIBRARY_PATH'] = f"{lib64}:{env['LD_LIBRARY_PATH']}" if env.get('LD_LIBRARY_PATH') else lib64
            dg = subprocess.run(
                [
                    str(DELTA_GEN),
                    f'--in_file={payload_bin}',
                    f'--properties_file={dg_props_path}',
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(dg.returncode, 0, dg.stdout + dg.stderr)

            rust_props = parse_properties(rust_props_path)
            dg_props = parse_properties(dg_props_path)
            for key in ('FILE_HASH', 'FILE_SIZE', 'METADATA_HASH', 'METADATA_SIZE'):
                self.assertEqual(rust_props[key], dg_props[key], f'Mismatch for {key}')


if __name__ == '__main__':
    unittest.main()
