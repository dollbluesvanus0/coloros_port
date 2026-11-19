#!/usr/bin/env python3
"""Generate a resource-only RRO for SystemUI colors encoded as framework attributes.

ColorOS 17.0.1 can ship ?0x01960018 where framework-res defines that ID as
color/system_on_secondary_fixed_dark. The dark keyguard then crashes in
TypedArray.getColorStateList. Resolve IDs against the actual framework instead
of assuming a type-ID range, and keep both APKs and their signatures untouched.
"""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

PACKAGE = 'org.coloros.port.systemui.colors'
RESOURCE = re.compile(r'^\s*resource (0x[0-9a-fA-F]{8}) ([\w.]+/[\w.]+)(?:\s|$)')
VALUE = re.compile(r'^\s+\(([^)]*)\) (\?0x[0-9a-fA-F]{8})\s*$')
ANDROID_NS = 'http://schemas.android.com/apk/res/android'
ET.register_namespace('android', ANDROID_NS)


@dataclass(frozen=True, order=True)
class ColorFix:
    qualifier: str
    resource: str
    framework_resource: str
    framework_id: int


def find_fixes(systemui_dump, framework_dump):
    """Keep valid attributes, references, non-colors and unrelated IDs unchanged."""
    framework_colors = {}
    for line in framework_dump.splitlines():
        match = RESOURCE.match(line)
        if match and match[2].startswith('color/'):
            resource_id = int(match[1], 16)
            if resource_id >> 24 != 1:
                continue
            previous = framework_colors.setdefault(resource_id, match[2])
            if previous != match[2]:
                raise ValueError(f'Ambiguous framework color ID {match[1]}')

    resource = None
    fixes = {}
    for line in systemui_dump.splitlines():
        match = RESOURCE.match(line)
        if match:
            resource = match[2]
            continue
        match = VALUE.fullmatch(line)
        if not match or not resource or not resource.startswith('color/'):
            continue
        reference = int(match[2][1:], 16)
        framework_resource = framework_colors.get(reference)
        if framework_resource is None:
            continue
        qualifier = match[1]
        if qualifier and not re.fullmatch(r'[A-Za-z0-9+]+(?:-[A-Za-z0-9+]+)*', qualifier):
            raise ValueError(f'Invalid resource configuration: {qualifier!r}')
        fix = ColorFix(qualifier, resource, framework_resource, reference)
        previous = fixes.setdefault((qualifier, resource), fix)
        if previous != fix:
            raise ValueError(f'Conflicting color definitions: {resource} ({qualifier})')
    return sorted(fixes.values())


def write_sources(fixes, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'color-fixes.json').write_text(
        json.dumps([asdict(fix) for fix in fixes], indent=2) + '\n', encoding='utf-8')
    if not fixes:
        return
    for qualifier in sorted({fix.qualifier for fix in fixes}):
        directory = output / 'res' / ('values' + ('-' + qualifier if qualifier else ''))
        directory.mkdir(parents=True, exist_ok=True)
        resources = ET.Element('resources')
        for fix in fixes:
            if fix.qualifier == qualifier:
                item = ET.SubElement(resources, 'item', type='color', name=fix.resource.split('/')[1])
                item.text = '@*android:' + fix.framework_resource
        ET.ElementTree(resources).write(directory / 'colors.xml', encoding='utf-8', xml_declaration=True)

    android = lambda key: '{' + ANDROID_NS + '}' + key
    manifest = ET.Element('manifest', {'package': PACKAGE, android('versionCode'): '1',
                                       android('versionName'): '1.0'})
    # A preinstalled pre-Q RRO can target OEM resources without an overlayable
    # contract. It has no code, components or permissions. Using a separate RRO
    # preserves the platform-signed SystemUI APK and its shared UID permissions.
    ET.SubElement(manifest, 'uses-sdk', {android('minSdkVersion'): '28', android('targetSdkVersion'): '28'})
    ET.SubElement(manifest, 'application', {android('hasCode'): 'false',
                                           android('label'): 'ColorOS SystemUI colors'})
    ET.SubElement(manifest, 'overlay', {android('targetPackage'): 'com.android.systemui',
                                      android('isStatic'): 'true', android('priority'): '999'})
    ET.ElementTree(manifest).write(output / 'AndroidManifest.xml', encoding='utf-8', xml_declaration=True)


def update_overlay_config(path, enabled, package=PACKAGE):
    """OverlayConfig overrides manifest isStatic/priority when it exists."""
    path = Path(path)
    if not path.is_file():
        return
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    tree = ET.parse(path, parser=parser)
    root = tree.getroot()
    if root.tag != 'config':
        raise ValueError(f'Unexpected overlay config root: {root.tag}')
    matches = [child for child in root if child.tag == 'overlay' and child.get('package') == package]
    if enabled and len(matches) == 1 and matches[0] is list(root)[0] and (
            matches[0].get('enabled'), matches[0].get('mutable')) == ('true', 'false'):
        return
    if not enabled and not matches:
        return
    for child in matches:
        root.remove(child)
    if enabled:
        # Android requires immutable entries before all mutable ones, including
        # those inside <merge> files. Prepending preserves every existing order.
        root.insert(0, ET.Element('overlay', package=package, enabled='true', mutable='false'))
    tree.write(path, encoding='utf-8', xml_declaration=True)


def aapt_dump(aapt2, kind, apk, *args):
    result = subprocess.run([str(aapt2), 'dump', kind, str(apk), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
    if result.returncode:
        raise ValueError(f'AAPT2 could not inspect {apk}: {result.stderr.strip()}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--systemui', required=True, type=Path)
    parser.add_argument('--framework', required=True, type=Path)
    parser.add_argument('--aapt2', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--overlay-config', type=Path)
    args = parser.parse_args()
    try:
        for apk, package in ((args.systemui, 'com.android.systemui'), (args.framework, 'android')):
            if aapt_dump(args.aapt2, 'packagename', apk).strip() != package:
                raise ValueError(f'{apk} is not {package}')
        fixes = find_fixes(aapt_dump(args.aapt2, 'resources', args.systemui),
                           aapt_dump(args.aapt2, 'resources', args.framework))
        # A private, empty output directory prevents stale resource qualifiers.
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise ValueError('Output directory must be empty')
        write_sources(fixes, args.output_dir)
        if args.overlay_config:
            update_overlay_config(args.overlay_config, bool(fixes))
        print(f'SystemUI color compatibility: {len(fixes)} invalid attribute reference(s)')
    except (OSError, ValueError, ET.ParseError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'SystemUI color compatibility failed: {error}\n')


if __name__ == '__main__':
    main()
