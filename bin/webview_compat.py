#!/usr/bin/env python3
"""Select the bundled Google WebView when the framework only lists absent AOSP WebView."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from systemui_color_overlay import aapt_dump, update_overlay_config

AOSP = 'com.android.webview'
GOOGLE = 'com.google.android.webview'
PACKAGE = 'org.coloros.port.webview'
RESOURCE = 'res/xml/config_webview_packages.xml'
SOURCE = Path(__file__).with_name('webview-overlay')


def bundled_providers(images, aapt2):
    # ColorOS overlays the my_* app directories onto /product/app at boot.
    partitions = [images / name for name in ('system', 'system/system', 'product',
                                             'system_ext', 'vendor', 'odm', 'oem')]
    partitions.extend(images / name for name in ('my_region', 'my_preload', 'my_product',
                                                 'my_heytap', 'my_stock', 'my_engineering'))
    providers = set()
    for partition in partitions:
        for directory in ('app', 'priv-app'):
            app_root = partition / directory
            for apk in app_root.rglob('*.apk'):
                if not any('webview' in part.lower() for part in apk.relative_to(app_root).parts):
                    continue
                manifest = aapt_dump(aapt2, 'xmltree', apk, '--file', 'AndroidManifest.xml')
                package = re.search(r'^\s*A: package="([^"]+)"', manifest, re.MULTILINE)
                if package and '="com.android.webview.WebViewLibrary"' in manifest:
                    providers.add(package[1])
    return providers


def needs_overlay(images, framework, aapt2):
    providers = bundled_providers(images, aapt2)
    if GOOGLE not in providers or AOSP in providers:
        return False
    xml = aapt_dump(aapt2, 'xmltree', framework, '--file', RESOURCE)
    configured = re.findall(r'^\s*A: packageName="([^"]+)"', xml, re.MULTILINE)
    # Keep the donor's provider list when it already declares another provider.
    return configured == [AOSP]


def stage_overlay(images, aapt2, apksigner):
    framework = images / 'system/system/framework/framework-res.apk'
    if not framework.is_file():
        framework = images / 'system/framework/framework-res.apk'
    root = images / 'system_ext/overlay'
    target = root / 'ColorOSWebViewCompat.apk'
    config = root / 'config/config.xml'

    if not needs_overlay(images, framework, aapt2):
        update_overlay_config(config, False, PACKAGE)
        target.unlink(missing_ok=True)
        return False

    root.mkdir(parents=True, exist_ok=True)
    keys = Path('otatools/key')
    with tempfile.TemporaryDirectory(prefix='webview-overlay-', dir=root) as temp:
        temp = Path(temp)
        compiled = temp / 'compiled.zip'
        unsigned = temp / 'unsigned.apk'
        signed = temp / 'signed.apk'
        subprocess.run([aapt2, 'compile', '--dir', SOURCE / 'res', '-o', compiled], check=True)
        subprocess.run([aapt2, 'link', '-o', unsigned, '--manifest', SOURCE / 'AndroidManifest.xml',
                        '-I', framework, '--no-resource-deduping', '--no-resource-removal', compiled],
                       check=True)
        subprocess.run([apksigner, 'sign', '--in', unsigned, '--out', signed,
                        '--key', keys / 'testkey.pk8', '--cert', keys / 'testkey.x509.pem',
                        '--min-sdk-version', '28', '--v1-signing-enabled', 'false',
                        '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true'], check=True)
        subprocess.run([apksigner, 'verify', '--verbose', signed], check=True)
        signed.chmod(0o644)
        signed.replace(target)

    update_overlay_config(config, True, PACKAGE)
    rule = r'/system_ext/overlay/ColorOSWebViewCompat\.apk u:object_r:vendor_overlay_file:s0'
    for contexts in (images / 'config/system_ext_file_contexts',
                     images / 'system_ext/etc/selinux/system_ext_file_contexts'):
        if contexts.is_file() and rule not in contexts.read_text(encoding='utf-8').splitlines():
            with contexts.open('a', encoding='utf-8', newline='\n') as output:
                output.write(f'\n{rule}\n')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('images', type=Path)
    parser.add_argument('--aapt2', type=Path, default=Path('otatools/bin/aapt2'))
    parser.add_argument('--apksigner', type=Path, default=Path('otatools/bin/apksigner'))
    args = parser.parse_args()
    try:
        if stage_overlay(args.images, args.aapt2, args.apksigner):
            print(f'WebView compatibility overlay staged for {GOOGLE}')
    except (OSError, ValueError, ET.ParseError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'WebView compatibility failed: {error}\n')


if __name__ == '__main__':
    main()
