"""Regression coverage for the ColorOS dark-keyguard color-reference crash."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('systemui_color_overlay', ROOT / 'bin/systemui_color_overlay.py')
overlay = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = overlay
spec.loader.exec_module(overlay)

# AAPT2 dump excerpts representing the observed ColorOS 17.0.1 crash.
FRAMEWORK = '''Package name=android id=01
    resource 0x01960018 color/system_on_secondary_fixed_dark PUBLIC STAGED
      () #ff383f51
    resource 0x01960005 color/system_error_dim_dark PUBLIC STAGED
      () #ffc54d4a
    resource 0x01960000 color/system_error_dim_light PUBLIC STAGED
      () #ff67040d
    resource 0x01010098 attr/textColorPrimary PUBLIC
      () (attr) type=color
'''
SYSTEMUI = '''Package name=com.android.systemui id=7f
    resource 0x7f060b11 color/materialColorErrorDim
      () ?0x01960000
      (night) ?0x01960005
    resource 0x7f060b1e color/materialColorOnSecondaryFixed
      () @0x010600ba
      (night) ?0x01960018
'''


class SystemUIColorOverlayTests(unittest.TestCase):
    def test_crashing_night_attribute_becomes_framework_color_reference(self):
        fixes = overlay.find_fixes(SYSTEMUI, FRAMEWORK)
        self.assertEqual(len(fixes), 3)
        self.assertIn(overlay.ColorFix('night', 'color/materialColorOnSecondaryFixed',
                                      'color/system_on_secondary_fixed_dark', 0x01960018), fixes)
        self.assertEqual([fix.qualifier for fix in fixes if fix.resource.endswith('SecondaryFixed')], ['night'])

    def test_preserves_real_attributes_correct_references_and_non_colors(self):
        source = '''    resource 0x7f060001 color/validThemeColor
      () ?0x01010098
    resource 0x7f060002 color/alreadyCorrect
      () @0x01960018
    resource 0x7f060003 color/unknown
      () ?0x0196ffff
    resource 0x7f140001 style/Theme
      () ?0x01960018
'''
        self.assertEqual(overlay.find_fixes(source, FRAMEWORK), [])

    def test_resolves_actual_framework_color_ids_without_hardcoded_type_range(self):
        source = '    resource 0x7f060001 color/example\n      (night-v31) ?0x01bb0012\n'
        framework = '    resource 0x01bb0012 color/new_oem_color PUBLIC\n'
        self.assertEqual(overlay.find_fixes(source, framework), [
            overlay.ColorFix('night-v31', 'color/example', 'color/new_oem_color', 0x01bb0012)])

    def test_rejects_ambiguous_or_conflicting_resource_mapping(self):
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            overlay.find_fixes(SYSTEMUI, FRAMEWORK + '    resource 0x01960018 color/different\n')
        conflict = SYSTEMUI + '    resource 0x7f060b1e color/materialColorOnSecondaryFixed\n      (night) ?0x01960005\n'
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            overlay.find_fixes(conflict, FRAMEWORK)

    def test_rejects_unsafe_configuration_path(self):
        source = '    resource 0x7f060001 color/example\n      (../../escape) ?0x01960018\n'
        with self.assertRaisesRegex(ValueError, 'configuration'):
            overlay.find_fixes(source, FRAMEWORK)

    def test_emits_config_specific_references_and_no_code_or_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            overlay.write_sources(overlay.find_fixes(SYSTEMUI, FRAMEWORK), root)
            day = ET.parse(root / 'res/values/colors.xml').getroot()
            night = ET.parse(root / 'res/values-night/colors.xml').getroot()
            self.assertEqual({item.get('name') for item in day}, {'materialColorErrorDim'})
            self.assertEqual({item.text for item in night}, {
                '@*android:color/system_error_dim_dark', '@*android:color/system_on_secondary_fixed_dark'})
            manifest = ET.parse(root / 'AndroidManifest.xml').getroot()
            android = '{' + overlay.ANDROID_NS + '}'
            self.assertEqual(manifest.find('application').get(android + 'hasCode'), 'false')
            self.assertEqual(manifest.findall('uses-permission'), [])
            self.assertEqual(manifest.find('overlay').get(android + 'targetPackage'), 'com.android.systemui')
            self.assertEqual(manifest.find('uses-sdk').get(android + 'targetSdkVersion'), '28')
            self.assertEqual(len(json.loads((root / 'color-fixes.json').read_text())), 3)

    def test_no_fix_emits_no_manifest_or_resources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            overlay.write_sources([], root)
            self.assertEqual(list(root.iterdir()), [root / 'color-fixes.json'])

    def test_existing_overlay_config_enabled_and_idempotent_preserving_other_entries(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'config.xml'
            path.write_text('<config><!-- keep --><overlay package="other" enabled="true" mutable="false"/>\n'
                            f'<overlay package="{overlay.PACKAGE}" enabled="false" mutable="true"/></config>')
            overlay.update_overlay_config(path, True)
            first = path.read_bytes()
            overlay.update_overlay_config(path, True)
            self.assertEqual(path.read_bytes(), first)
            self.assertIn(b'keep', first)
            entries = ET.parse(path).getroot().findall('overlay')
            self.assertEqual(entries[1].get('package'), 'other')
            self.assertEqual(entries[0].attrib, dict(package=overlay.PACKAGE, enabled='true', mutable='false'))
            overlay.update_overlay_config(path, False)
            self.assertEqual([entry.get('package') for entry in ET.parse(path).getroot()], ['other'])

    def test_immutable_fix_precedes_mutable_and_merged_configuration(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'config.xml'
            path.write_text('<config><merge path="common.xml"/><overlay package="mutable"/></config>')
            overlay.update_overlay_config(path, True)
            entries = list(ET.parse(path).getroot())
            self.assertEqual(entries[0].attrib, dict(package=overlay.PACKAGE, enabled='true', mutable='false'))
            self.assertEqual(entries[1].get('path'), 'common.xml')
            self.assertEqual(entries[2].get('package'), 'mutable')

    def test_does_not_create_partition_config_or_accept_invalid_root(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'config.xml'
            overlay.update_overlay_config(path, True)
            self.assertFalse(path.exists())
            path.write_text('<wrong/>')
            with self.assertRaisesRegex(ValueError, 'root'):
                overlay.update_overlay_config(path, True)


if __name__ == '__main__':
    unittest.main()
