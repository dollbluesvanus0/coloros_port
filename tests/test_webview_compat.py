from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import webview_compat as webview


class WebViewCompatTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.images = Path(temp.name)
        self.framework = self.put('system/system/framework/framework-res.apk', webview.AOSP)
        self.apk = self.put('my_product/app/WebViewGoogle64CN/WebViewGoogle64CN.apk', webview.GOOGLE)
        self.overlay = self.images / 'system_ext/overlay/ColorOSWebViewCompat.apk'
        self.config = self.put('system_ext/overlay/config/config.xml', '<config><merge path="common.xml"/></config>')
        self.contexts = self.put('config/system_ext_file_contexts', '/system_ext u:object_r:system_file:s0\n')

    def put(self, relative, contents):
        path = self.images / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding='utf-8')
        return path

    def dump_xml(self, aapt2, kind, apk, flag, resource):
        package = apk.read_text(encoding='utf-8')
        if resource == webview.RESOURCE:
            return '\n'.join(f'      A: packageName="{name}"' for name in package.splitlines())
        return f'  A: package="{package}"\n  A: name="com.android.webview.WebViewLibrary"'

    @staticmethod
    def build(args, *, check):
        action = args[1]
        if action in ('compile', 'link', 'sign'):
            output = args[args.index('--out' if action == 'sign' else '-o') + 1]
            output.write_bytes(action.encode())

    def stage(self, build=None):
        with (patch.object(webview, 'aapt_dump', side_effect=self.dump_xml),
              patch.object(webview.subprocess, 'run', side_effect=build or self.build)):
            return webview.stage_overlay(self.images, 'aapt2', 'apksigner')

    def test_stages_immutable_overlay_when_only_absent_aosp_is_configured(self):
        self.assertTrue(self.stage())
        self.assertTrue(self.stage())
        self.assertEqual(self.overlay.read_bytes(), b'sign')
        entries = list(ET.parse(self.config).getroot())
        self.assertEqual(entries[0].attrib, dict(package=webview.PACKAGE, enabled='true', mutable='false'))
        self.assertEqual(entries[1].get('path'), 'common.xml')
        contexts = self.contexts.read_text(encoding='utf-8')
        self.assertEqual(contexts.count('ColorOSWebViewCompat'), 1)
        self.assertIn('ColorOSWebViewCompat\\.apk u:object_r:vendor_overlay_file:s0', contexts)
        provider = ET.parse(webview.SOURCE / webview.RESOURCE).getroot().find('webviewprovider')
        self.assertEqual(provider.get('packageName'), webview.GOOGLE)
        self.assertEqual(provider.get('availableByDefault'), 'true')

    def test_keeps_bundled_aosp_and_clears_stale_generated_overlay(self):
        self.assertTrue(self.stage())
        self.put('system/system/app/webview/webview.apk', webview.AOSP)
        self.assertFalse(self.stage())
        self.assertFalse(self.overlay.exists())
        self.assertIsNone(ET.parse(self.config).getroot().find('overlay'))

    def test_keeps_donor_configuration_and_ignores_deleted_apps(self):
        self.framework.write_text(f'{webview.GOOGLE}\n{webview.AOSP}', encoding='utf-8')
        self.assertFalse(self.stage())
        self.framework.write_text(webview.AOSP, encoding='utf-8')
        self.apk.unlink()
        self.put('my_product/del-app/WebViewGoogle64CN/WebViewGoogle64CN.apk', webview.GOOGLE)
        self.assertFalse(self.stage())
        self.assertFalse(self.overlay.exists())

    def test_does_not_publish_overlay_if_signing_verification_fails(self):
        def fail_verify(args, *, check):
            if args[1] == 'verify':
                raise subprocess.CalledProcessError(1, args)
            self.build(args, check=check)

        with self.assertRaises(subprocess.CalledProcessError):
            self.stage(build=fail_verify)
        self.assertFalse(self.overlay.exists())
        self.assertIsNone(ET.parse(self.config).getroot().find('overlay'))
