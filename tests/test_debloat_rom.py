import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from debloat_rom import debloat

MANIFEST = Path(__file__).resolve().parents[1] / 'bin/donor-debloat.txt'


class DebloatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'images'
        self.root.mkdir()

    def put(self, path):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('fixture')
        return target

    def run_debloat(self, manifest=MANIFEST):
        with contextlib.redirect_stdout(io.StringIO()):
            return debloat(self.root, manifest)

    def test_entire_manifest_and_glob(self):
        for pattern in MANIFEST.read_text().splitlines():
            if pattern and not pattern.startswith('#'):
                self.put(pattern.replace('*', 'Device') + '/data.apk')
        keep = [self.put('my_stock/app/Keep/app.apk'), self.put('vendor/app/Browser/app.apk'),
                self.put('my_stock/app/BrowserExtra/app.apk'), self.put('my_product/overlay/Keep/file.apk')]
        removed = self.run_debloat()
        self.assertGreater(len(removed), 40)
        self.assertTrue(all(p.exists() for p in keep))
        self.assertEqual(self.run_debloat(), [])
        for pattern in MANIFEST.read_text().splitlines():
            if pattern and not pattern.startswith('#'):
                self.assertEqual(list(self.root.glob(pattern)), [])

    def test_missing_partitions_are_noop(self):
        self.assertEqual(self.run_debloat(), [])

    def test_parent_symlink_cannot_escape(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (outside / 'del-app').mkdir()
        (outside / 'del-app/keep').write_text('keep')
        (self.root / 'my_product').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run_debloat()
        self.assertTrue((outside / 'del-app/keep').exists())

    def test_leaf_symlink_removed_without_touching_target(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        (self.root / 'my_product').mkdir()
        (self.root / 'my_product/del-app').symlink_to(outside, target_is_directory=True)
        self.run_debloat()
        self.assertTrue((outside / 'keep').exists())
        self.assertFalse((self.root / 'my_product/del-app').is_symlink())

    def test_unsafe_manifest_rejected_before_deletion(self):
        target = self.put('my_stock/app/Browser/file')
        manifest = Path(self.temp.name) / 'unsafe.txt'
        manifest.write_text('my_stock/app/Browser\n../outside\n')
        with self.assertRaises(ValueError):
            self.run_debloat(manifest)
        self.assertTrue(target.exists())

    def test_manifest_includes_case_fixed_and_system_ext_bloat(self):
        manifest_text = MANIFEST.read_text(encoding='utf-8').splitlines()
        for expected in (
            'my_stock/del-app/KeKeUserCenterMember',
            'my_stock/priv-app/KeKeAppDetail',
            'my_stock/priv-app/KeKeMarket',
            'my_stock/priv-app/DCS',
            'my_stock/priv-app/DRS',
            'my_stock/app/MSPService',
            'system_ext/app/LogTrialCommercial',
        ):
            self.assertIn(expected, manifest_text)
        keep_sys_ext = self.put('system_ext/app/PowerMonitor/PowerMonitor.apk')
        drop_sys_ext = self.put('system_ext/app/LogTrialCommercial/LogTrialCommercial.apk')
        self.run_debloat()
        self.assertTrue(keep_sys_ext.exists())
        self.assertFalse(drop_sys_ext.exists())
