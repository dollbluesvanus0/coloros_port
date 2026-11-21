"""Regression tests for port.sh bugfixes, Rust tool wrappers, parallelism, and CI alignment."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PORT_SH = ROOT / 'port.sh'
FUNCTIONS_SH = ROOT / 'functions.sh'
SETUP_SH = ROOT / 'setup.sh'
PERF_SH = ROOT / 'bin' / 'port_performance.sh'
PORT_CONFIG = ROOT / 'bin' / 'port_config'


class PortScriptStaticRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port_text = PORT_SH.read_text(encoding='utf-8')
        cls.functions_text = FUNCTIONS_SH.read_text(encoding='utf-8')
        cls.setup_text = SETUP_SH.read_text(encoding='utf-8')
        cls.perf_text = PERF_SH.read_text(encoding='utf-8')
        cls.config_text = PORT_CONFIG.read_text(encoding='utf-8')

    def test_port_sh_variable_and_typo_bugfixes(self):
        # Missing $ on base_brand and port_vendor_brand
        self.assertIn('elif [[ "$base_brand" == "realme" ]];then', self.port_text)
        self.assertNotIn('"base_brand" == "realme"', self.port_text)
        self.assertIn('[[ "$port_vendor_brand" != "realme" ]]', self.port_text)
        self.assertIsNone(re.search(r'\[\[\s*port_vendor_brand\b', self.port_text))

        # SDK comparison must check $base_android_sdk, not $base_android_version
        self.assertIn('if [[ $base_android_sdk -lt 33 ]];then', self.port_text)
        self.assertNotIn('$base_android_version -lt 33', self.port_text)

        # Invalid mv -rfv flag removed
        self.assertNotIn('mv -rfv', self.port_text)

        # vbmeta_system.img and $custom_bootimg_file typo fixes
        self.assertIn('vbmeta_system.img', self.port_text)
        self.assertNotIn('vbmeta_sytem.img', self.port_text)
        self.assertIn('$custom_bootimg_file', self.port_text)
        self.assertNotIn('$custom_botimg_file', self.port_text)

        # Duplicate BTFM elif removed
        self.assertEqual(
            len(re.findall(r'elif\s+\[\[\s+\$\{fwimg\}\s+==\s+"BTFM"\s+\]\]', self.port_text)),
            1,
        )

    def test_port_sh_guards_and_no_duplicate_overwrites_or_a17_compat(self):
        # No active overwrite of my_product/etc/permissions/*.xml from baserom
        active_lines = [
            line for line in self.port_text.splitlines()
            if not line.lstrip().startswith('#')
        ]
        active_text = '\n'.join(active_lines)
        # Only the initial baserom permissions copy before selective donor restore
        # should remain; the duplicate post-restore overwrite must be gone.
        perm_glob = 'build/baserom/images/my_product/etc/permissions/*.xml'
        self.assertEqual(active_text.count(perm_glob), 1)
        self.assertLess(
            active_text.index(perm_glob),
            active_text.index('find tmp/etc/permissions/'),
        )

        # Optional device asset directories must be guarded with -d
        self.assertIn('if [[ -d devices/common/via ]]; then', self.port_text)
        self.assertIn('[[ -d devices/common/super_computing ]]', self.port_text)

        # A17 compat deduplication: single source of truth in functions.sh
        self.assertIsNone(
            re.search(r'^a17_patch_vendor_context_file\s*\(\)', self.port_text, re.MULTILINE)
        )
        self.assertIn('_port::stage_postdata_compat', self.port_text)
        self.assertIn('a17_patch_vendor_context_file()', self.functions_text)
        self.assertIn('_port::stage_postdata_compat()', self.functions_text)

    def test_port_sh_dependencies_and_parallel_wiring(self):
        self.assertRegex(self.port_text, re.compile(r'^check\b.*\bjq\b', re.MULTILINE))
        self.assertIn('check unix2dos', self.port_text)

        # Parallel baserom extraction & parallel APK patching
        self.assertIn('_port::extract_baserom_worker', self.port_text)
        self.assertIn('port_extract_job_count', self.port_text)
        self.assertIn('_port::patch_apk_worker', self.port_text)
        self.assertIn('port_patch_job_count', self.port_text)
        self.assertIn('PORT_PATCH_JOBS', self.port_text)
        self.assertIn('patch_jobs=auto', self.config_text)

        # Rust accelerators wired with 127 fallback
        for helper in ('run_rom_ops', 'run_xml_tool', 'run_prop_tool'):
            self.assertIn(helper, self.port_text)
            self.assertIn(f'{helper}()', self.functions_text)

    def test_ota_payload_gen_and_parallel_map_wiring(self):
        self.assertIn('ota_engine=auto', self.config_text)
        self.assertIn('payload_compression=fast-xz', self.config_text)
        self.assertIn('PORT_OTA_ENGINE', self.port_text)
        self.assertIn('PORT_PAYLOAD_COMPRESSION', self.port_text)
        self.assertIn('_port::generate_map_file', self.port_text)
        self.assertIn('_port::generate_map_file()', self.functions_text)
        self.assertIn('LC_ALL=C sort', self.port_text)
        for fn_name in (
            'run_payload_gen',
            '_port::write_ota_metadata',
            '_port::sign_ota_zip',
            '_port::package_and_sign_ota_zip',
            '_port::build_ab_ota_rust',
            '_port::build_ab_ota_delta',
        ):
            self.assertIn(f'{fn_name}()', self.functions_text)
        self.assertIn('_port::build_ab_ota_rust', self.port_text)
        self.assertIn('_port::build_ab_ota_delta', self.port_text)
        self.assertIn('PORT_DISABLE_PAYLOAD_GEN', self.functions_text)

    def test_setup_sh_installs_jq_and_dos2unix_on_all_platforms(self):
        for line_marker in ('x86_64', 'aarch64', 'Darwin'):
            self.assertIn(line_marker, self.setup_text)
        apt_lines = [
            line for line in self.setup_text.splitlines()
            if line.lstrip().startswith(('apt install', 'brew install'))
        ]
        self.assertEqual(len(apt_lines), 3)
        for line in apt_lines:
            self.assertIn('jq', line)
            self.assertIn('dos2unix', line)

    def test_ci_workflows_align_with_rust_tools_and_tests(self):
        expected_aliases = (
            'rom-fs-patcher',
            'dex-patcher',
            'smali-patcher',
            'prop-tool',
            'xml-tool',
            'rom-ops',
            'payload-gen',
        )
        port_rom_yml = (ROOT / '.github/workflows/port-rom.yml').read_text(encoding='utf-8')
        rust_tools_yml = (ROOT / '.github/workflows/rust-tools.yml').read_text(encoding='utf-8')
        script_checks_yml = (ROOT / '.github/workflows/script-checks.yml').read_text(encoding='utf-8')

        self.assertIn('jq', port_rom_yml)
        self.assertIn('actions/cache@v4', port_rom_yml)
        self.assertIn('tools-rust/target', port_rom_yml)
        for alias in expected_aliases:
            self.assertIn(alias, port_rom_yml)
            self.assertIn(alias, rust_tools_yml)

        for script in (
            'port.sh',
            'functions.sh',
            'setup.sh',
            'bin/port_performance.sh',
            'bin/systemui_color_compat.sh',
            'bin/getSuperSize.sh',
        ):
            self.assertIn(script, script_checks_yml)
        self.assertIn('python3 -m unittest discover -s tests -v', script_checks_yml)


@unittest.skipUnless(shutil.which('bash'), 'bash is not installed')
class PortScriptShellBehaviorTests(unittest.TestCase):
    def run_bash(self, script, env_overrides=None):
        env = dict(os.environ)
        for key in (
            'PORT_DISABLE_DEX_PATCHER',
            'PORT_DISABLE_PROP_TOOL',
            'PORT_DISABLE_XML_TOOL',
            'PORT_DISABLE_ROM_OPS',
            'PORT_DISABLE_PAYLOAD_GEN',
            'PORT_EXTRACT_JOBS',
            'PORT_PATCH_JOBS',
            'PORT_OTA_ENGINE',
            'PORT_PAYLOAD_COMPRESSION',
        ):
            env.pop(key, None)
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            ['bash', '-c', script],
            cwd=ROOT,
            env=env,
            text=True,
            encoding='utf-8',
            errors='replace',
            capture_output=True,
            timeout=30,
        )

    def test_shell_syntax_all_scripts(self):
        scripts = (
            'port.sh',
            'functions.sh',
            'setup.sh',
            'bin/port_performance.sh',
            'bin/systemui_color_compat.sh',
            'bin/getSuperSize.sh',
        )
        for script in scripts:
            with self.subTest(script=script):
                res = self.run_bash(f'bash -n "{script}"')
                self.assertEqual(res.returncode, 0, res.stderr)

    def test_rust_wrappers_resolve_aliases_and_fallback_to_127(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / 'bin'
            bin_dir.mkdir()
            for tool in ('xml-tool', 'rom-ops', 'prop-tool', 'dex-patcher', 'payload-gen'):
                exe = bin_dir / tool
                exe.write_text(f'#!/usr/bin/env bash\necho "{tool}:$*"\n', encoding='utf-8')
                exe.chmod(0o755)

            res = self.run_bash(
                f'''
                tools_dir="{bin_dir.as_posix()}"
                PATH="{bin_dir.as_posix()}:$PATH"
                source functions.sh
                run_xml_tool add-features --stdin
                run_rom_ops tree-size /tmp
                run_prop_tool batch-dir --dir /tmp
                run_dex_patcher stub-method --file app.apk
                run_payload_gen generate --images-dir /tmp
                ''',
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = res.stdout.strip().splitlines()
            self.assertIn('xml-tool:add-features --stdin', lines)
            self.assertIn('rom-ops:tree-size /tmp', lines)
            self.assertIn('prop-tool:batch-dir --dir /tmp', lines)
            self.assertIn('dex-patcher:stub-method --file app.apk', lines)
            self.assertIn('payload-gen:generate --images-dir /tmp', lines)

            # Disabled flags must force exit 127 for transparent legacy fallback
            res_disabled = self.run_bash(
                '''
                source functions.sh
                for fn in run_xml_tool run_rom_ops run_prop_tool run_dex_patcher run_payload_gen _port::build_ab_ota_rust; do
                    "$fn" --help
                    echo "$fn:$?"
                done
                ''',
                env_overrides={
                    'PORT_DISABLE_XML_TOOL': 'true',
                    'PORT_DISABLE_ROM_OPS': 'true',
                    'PORT_DISABLE_PROP_TOOL': 'true',
                    'PORT_DISABLE_DEX_PATCHER': 'true',
                    'PORT_DISABLE_PAYLOAD_GEN': 'true',
                },
            )
            self.assertEqual(res_disabled.returncode, 0, res_disabled.stderr)
            self.assertEqual(
                res_disabled.stdout.strip().splitlines(),
                [
                    'run_xml_tool:127',
                    'run_rom_ops:127',
                    'run_prop_tool:127',
                    'run_dex_patcher:127',
                    'run_payload_gen:127',
                    '_port::build_ab_ota_rust:127',
                ],
            )

    def test_coloros_tools_multicall_fallback_and_tree_size_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            (root / 'sample').mkdir()
            (root / 'sample/a.bin').write_bytes(b'12345')
            multicall = bin_dir / 'coloros-tools'
            multicall.write_text('#!/usr/bin/env bash\necho "multicall:$*"\n', encoding='utf-8')
            multicall.chmod(0o755)

            res = self.run_bash(
                f'''
                PATH="{bin_dir.as_posix()}:$PATH"
                _port::resolve_rust_bin() {{
                    [[ "$1" == coloros-tools ]] && printf '%s\\n' "{multicall.as_posix()}" && return 0
                    return 1
                }}
                source functions.sh
                # Re-define after sourcing to isolate PATH from host repo bin/
                _port::resolve_rust_bin() {{
                    [[ "$1" == coloros-tools ]] && printf '%s\\n' "{multicall.as_posix()}" && return 0
                    return 1
                }}
                run_xml_tool delete-elements --tag foo
                run_rom_ops strip-non-ascii file.txt
                run_payload_gen verify --file p.bin
                if command -v python3 >/dev/null 2>&1; then
                    PORT_DISABLE_ROM_OPS=true port_tree_size_bytes "{(root / 'sample').as_posix()}"
                else
                    echo 5
                fi
                ''',
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = res.stdout.strip().splitlines()
            self.assertIn('multicall:xml-tool delete-elements --tag foo', lines)
            self.assertIn('multicall:rom-ops strip-non-ascii file.txt', lines)
            self.assertIn('multicall:payload-gen verify --file p.bin', lines)
            self.assertIn('5', lines)

    def test_write_ota_metadata_helper(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tf = root / 'target_files'
            (tf / 'SYSTEM').mkdir(parents=True)
            (tf / 'SYSTEM/build.prop').write_text(
                '\n'.join([
                    'ro.build.fingerprint=OnePlus/PJZ110/OP5CF9L1:16/UKQ1.231108.001/T.1:user/release-keys',
                    'ro.build.version.incremental=16.0.0.100',
                    'ro.build.version.sdk=36',
                    'ro.build.version.security_patch=2026-08-05',
                    'ro.build.date.utc=1755000000',
                    'ro.product.device=RE54E4L1',
                ]) + '\n',
                encoding='utf-8',
            )
            out_meta = root / 'metadata'
            res = self.run_bash(
                f'''
                source functions.sh
                _port::write_ota_metadata "{tf.as_posix()}" "{out_meta.as_posix()}"
                '''
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            meta = dict(
                line.split('=', 1)
                for line in out_meta.read_text(encoding='utf-8').splitlines()
                if '=' in line
            )
            self.assertEqual(meta['ota-type'], 'AB')
            self.assertEqual(meta['ota-required-cache'], '0')
            self.assertEqual(meta['post-sdk-level'], '36')
            self.assertEqual(meta['post-security-patch-level'], '2026-08-05')
            self.assertEqual(meta['post-timestamp'], '1755000000')
            self.assertEqual(meta['pre-device'], 'RE54E4L1')

    def test_extract_and_patch_job_count_validation(self):
        res = self.run_bash(
            '''
            source bin/port_performance.sh
            [[ "$(port_extract_job_count 8)" == 4 ]] || exit 1
            [[ "$(port_extract_job_count 2)" == 2 ]] || exit 2
            [[ "$(port_patch_job_count 8)" -le 4 ]] || exit 3
            PORT_EXTRACT_JOBS=6
            [[ "$(port_extract_job_count 8)" == 6 ]] || exit 4
            PORT_PATCH_JOBS=3
            [[ "$(port_patch_job_count 8)" == 3 ]] || exit 5
            for bad in 0 33 01 abc; do
                PORT_EXTRACT_JOBS="$bad"
                if port_extract_job_count 4 2>/dev/null; then exit 6; fi
                PORT_PATCH_JOBS="$bad"
                if port_patch_job_count 4 2>/dev/null; then exit 7; fi
            done
            '''
        )
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_rom_optimization_and_camera_unit_sdk_permission_helpers(self):
        port_text = PORT_SH.read_text(encoding='utf-8')
        self.assertIn('ensure_oplus_camera_unit_sdk_permission', port_text)
        self.assertIn('_port::restore_stock_oplus_camera', port_text)
        self.assertIn('_port::stage_rom_optimizations', port_text)
        self.assertIn('debug.sf.oplus_display_trace.enable', port_text)
        self.assertIn('ro.audio.voiplog.on', port_text)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            img = root / 'build' / 'portrom' / 'images'
            jar = img / 'my_product' / 'product_overlay' / 'framework' / 'com.oplus.camera.unit.sdk.jar'
            jar.parent.mkdir(parents=True, exist_ok=True)
            jar.write_bytes(b'jar')
            cfg = img / 'config'
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / 'my_product_file_contexts').write_text('', encoding='utf-8')
            (cfg / 'my_product_fs_config').write_text('', encoding='utf-8')
            (cfg / 'system_ext_file_contexts').write_text('', encoding='utf-8')
            (cfg / 'system_ext_fs_config').write_text('', encoding='utf-8')
            sys_prop = img / 'system' / 'system' / 'build.prop'
            sys_prop.parent.mkdir(parents=True, exist_ok=True)
            sys_prop.write_text('dalvik.vm.usap_pool_enabled=false\n', encoding='utf-8')
            (img / 'system_ext' / 'etc').mkdir(parents=True, exist_ok=True)
            post_boot = img / 'vendor' / 'bin' / 'init.kernel.post_boot-taro.sh'
            post_boot.parent.mkdir(parents=True, exist_ok=True)
            post_boot.write_text(
                'function configure_read_ahead_kb_values() {\n'
                '    if [ $MemTotal -le 3145728 ]; then\n'
                '        ra_kb=128\n'
                '    else\n'
                '        ra_kb=512\n'
                '    fi\n'
                '}\n',
                encoding='utf-8',
            )

            res = self.run_bash(
                f'''
                source "{FUNCTIONS_SH.as_posix()}" || exit 1
                cd "{root.as_posix()}" || exit 1
                _port::stage_rom_optimizations || exit 2
                # Idempotent second pass
                _port::stage_rom_optimizations || exit 3
                '''
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            cam_xml = (img / 'my_product' / 'etc' / 'permissions' / 'com.oplus.camera.unit.sdk.xml').read_text(encoding='utf-8')
            self.assertIn('name="com.oplus.camera.unit.sdk"', cam_xml)
            self.assertIn('/product/framework/com.oplus.camera.unit.sdk.jar', cam_xml)
            cam_ctx = (cfg / 'my_product_file_contexts').read_text(encoding='utf-8')
            self.assertEqual(cam_ctx.count('com\\.oplus\\.camera\\.unit\\.sdk\\.xml'), 1)

            self.assertIn('dalvik.vm.usap_pool_enabled=true', sys_prop.read_text(encoding='utf-8'))
            rc_text = (img / 'system_ext' / 'etc' / 'init' / 'coloros_port_tuning.rc').read_text(encoding='utf-8')
            self.assertIn('write /proc/sys/vm/swappiness 80', rc_text)
            self.assertIn('write /sys/block/dm-0/queue/read_ahead_kb 128', rc_text)
            se_ctx = (cfg / 'system_ext_file_contexts').read_text(encoding='utf-8')
            self.assertEqual(se_ctx.count('coloros_port_tuning\\.rc'), 1)
            se_fs = (cfg / 'system_ext_fs_config').read_text(encoding='utf-8')
            self.assertEqual(se_fs.count('system_ext/etc/init/coloros_port_tuning.rc'), 1)

            pb_text = post_boot.read_text(encoding='utf-8')
            self.assertNotIn('ra_kb=512', pb_text)
            self.assertIn('ra_kb=128', pb_text)
            self.assertEqual(pb_text.count('# coloros_port_io_tuning'), 1)

    def test_restore_stock_oplus_camera_purges_donor_and_restores_stock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / 'build' / 'baserom' / 'images'
            port = root / 'build' / 'portrom' / 'images'

            # Stock OplusCamera in product/app/OplusCamera plus camera cfg & unit SDK jar
            stock_apk = base / 'product' / 'app' / 'OplusCamera' / 'OplusCamera.apk'
            stock_apk.parent.mkdir(parents=True, exist_ok=True)
            stock_apk.write_bytes(b'stock-camera')
            (base / 'my_product' / 'etc' / 'camera').mkdir(parents=True, exist_ok=True)
            (base / 'my_product' / 'etc' / 'camera' / 'cfg.xml').write_text('stock-cfg', encoding='utf-8')
            stock_jar = base / 'my_product' / 'product_overlay' / 'framework' / 'com.oplus.camera.unit.sdk.jar'
            stock_jar.parent.mkdir(parents=True, exist_ok=True)
            stock_jar.write_bytes(b'stock-sdk')

            # Donor OplusCamera shadows across multiple partitions + stale donor jar
            for rel in ('my_product/app/OplusCamera', 'my_stock/priv-app/OplusCamera', 'product/priv-app/OplusCamera'):
                donor_apk = port / rel / 'OplusCamera.apk'
                donor_apk.parent.mkdir(parents=True, exist_ok=True)
                donor_apk.write_bytes(b'donor-camera')
            stale_jar = port / 'my_product' / 'product_overlay' / 'framework' / 'com.oplus.camera.donor.jar'
            stale_jar.parent.mkdir(parents=True, exist_ok=True)
            stale_jar.write_bytes(b'donor-jar')

            res = self.run_bash(
                f'''
                source "{FUNCTIONS_SH.as_posix()}" || exit 1
                cd "{root.as_posix()}" || exit 1
                _port::restore_stock_oplus_camera || exit 2
                '''
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            self.assertEqual((port / 'product' / 'app' / 'OplusCamera' / 'OplusCamera.apk').read_bytes(), b'stock-camera')
            self.assertFalse((port / 'my_product' / 'app' / 'OplusCamera').exists())
            self.assertFalse((port / 'my_stock' / 'priv-app' / 'OplusCamera').exists())
            self.assertFalse((port / 'product' / 'priv-app' / 'OplusCamera').exists())
            self.assertFalse(stale_jar.exists())
            self.assertEqual((port / 'my_product' / 'product_overlay' / 'framework' / 'com.oplus.camera.unit.sdk.jar').read_bytes(), b'stock-sdk')
            self.assertEqual((port / 'my_product' / 'etc' / 'camera' / 'cfg.xml').read_text(encoding='utf-8'), 'stock-cfg')
            self.assertTrue((port / 'my_product' / 'etc' / 'permissions' / 'com.oplus.camera.unit.sdk.xml').exists())

    def test_install_preinstalled_apps_via_phonesky_and_kernelsu(self):
        port_text = PORT_SH.read_text(encoding='utf-8')
        config_text = PORT_CONFIG.read_text(encoding='utf-8')
        self.assertIn('_port::install_preinstalled_apps', port_text)
        for key in ('install_via=true', 'install_play_store=true', 'install_kernelsu=true'):
            self.assertIn(key, config_text)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = root / 'build' / 'portrom' / 'images'
            (port / 'product').mkdir(parents=True, exist_ok=True)
            (port / 'my_product' / 'priv-app' / 'GooglePlayServicesUpdater').mkdir(parents=True, exist_ok=True)
            (port / 'my_product' / 'priv-app' / 'GooglePlayServicesUpdater' / 'GooglePlayServicesUpdater.apk').write_bytes(b'stub')
            cn_gms = port / 'my_product' / 'etc' / 'permissions' / 'oplus_google_cn_gms_features.xml'
            cn_gms.parent.mkdir(parents=True, exist_ok=True)
            cn_gms.write_text(
                '<permissions>\n'
                '    <feature name="cn.google.services" />\n'
                '    <feature name="com.google.android.feature.services_updater" />\n'
                '</permissions>\n',
                encoding='utf-8',
            )

            apps_src = root / 'devices' / 'common' / 'apps'
            for app, extra in (('Via', None), ('Phonesky', None), ('KernelSU', 'lib/arm64-v8a/libksud.so')):
                apk_path = apps_src / app / f'{app}.apk'
                apk_path.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(apk_path, 'w') as zf:
                    zf.writestr('AndroidManifest.xml', f'<manifest package="{app}"/>')
                    if extra:
                        zf.writestr(extra, b'elf-so')

            res = self.run_bash(
                f'''
                source "{FUNCTIONS_SH.as_posix()}" || exit 1
                cd "{root.as_posix()}" || exit 1
                _port::install_preinstalled_apps || exit 2
                '''
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            self.assertTrue((port / 'product' / 'app' / 'Via' / 'Via.apk').is_file())
            self.assertTrue((port / 'product' / 'priv-app' / 'Phonesky' / 'Phonesky.apk').is_file())
            self.assertFalse((port / 'my_product' / 'priv-app' / 'GooglePlayServicesUpdater').exists())
            self.assertNotIn('services_updater', cn_gms.read_text(encoding='utf-8'))
            self.assertIn('cn.google.services', cn_gms.read_text(encoding='utf-8'))
            priv_xml = port / 'product' / 'etc' / 'permissions' / 'privapp-permissions-phonesky.xml'
            self.assertTrue(priv_xml.is_file())
            self.assertIn('com.android.vending', priv_xml.read_text(encoding='utf-8'))
            self.assertTrue((port / 'product' / 'app' / 'KernelSU' / 'KernelSU.apk').is_file())
            self.assertEqual((port / 'product' / 'app' / 'KernelSU' / 'lib' / 'arm64' / 'libksud.so').read_bytes(), b'elf-so')

    def test_download_valid_apk_passes_output_flag_before_double_dash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample_zip = root / 'sample.apk'
            with zipfile.ZipFile(sample_zip, 'w') as zf:
                zf.writestr('AndroidManifest.xml', '<manifest/>')
                zf.writestr('pad.bin', b'x' * 70000)

            dest = root / 'out' / 'Via.apk'
            res = self.run_bash(
                f'''
                source "{FUNCTIONS_SH.as_posix()}" || exit 1
                curl() {{
                    local out="" after_dash=false expect_out="" arg
                    for arg in "$@"; do
                        if [[ "$after_dash" == true ]]; then
                            [[ "$arg" != "-o" ]] || return 64
                            continue
                        fi
                        if [[ "$arg" == "--" ]]; then
                            after_dash=true
                            continue
                        fi
                        if [[ -n "$expect_out" ]]; then
                            out="$arg"
                            expect_out=""
                        elif [[ "$arg" == "-o" ]]; then
                            expect_out=1
                        fi
                    done
                    [[ -n "$out" ]] || return 65
                    cp -f "{sample_zip.as_posix()}" "$out"
                }}
                _port::download_valid_apk "https://example.invalid/via.apk" "{dest.as_posix()}" 1024 || exit 2
                '''
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue(dest.is_file())


if __name__ == '__main__':
    unittest.main()
