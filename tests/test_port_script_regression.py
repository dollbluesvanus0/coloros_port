"""Regression tests for port.sh bugfixes, Rust tool wrappers, parallelism, and CI alignment."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

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
            'PORT_EXTRACT_JOBS',
            'PORT_PATCH_JOBS',
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
            for tool in ('xml-tool', 'rom-ops', 'prop-tool', 'dex-patcher'):
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
                ''',
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = res.stdout.strip().splitlines()
            self.assertIn('xml-tool:add-features --stdin', lines)
            self.assertIn('rom-ops:tree-size /tmp', lines)
            self.assertIn('prop-tool:batch-dir --dir /tmp', lines)
            self.assertIn('dex-patcher:stub-method --file app.apk', lines)

            # Disabled flags must force exit 127 for transparent legacy fallback
            res_disabled = self.run_bash(
                '''
                source functions.sh
                for fn in run_xml_tool run_rom_ops run_prop_tool run_dex_patcher; do
                    "$fn" --help
                    echo "$fn:$?"
                done
                ''',
                env_overrides={
                    'PORT_DISABLE_XML_TOOL': 'true',
                    'PORT_DISABLE_ROM_OPS': 'true',
                    'PORT_DISABLE_PROP_TOOL': 'true',
                    'PORT_DISABLE_DEX_PATCHER': 'true',
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
            self.assertIn('5', lines)

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


if __name__ == '__main__':
    unittest.main()
