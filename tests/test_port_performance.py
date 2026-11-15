"""Packing concurrency, cache isolation and filesystem-size regression tests."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
from tree_size import tree_size_bytes


class TreeSizeTests(unittest.TestCase):
    def test_logical_size_counts_each_regular_path_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'nested dir').mkdir()
            regular = root / 'nested dir' / 'file\nname'
            # Windows filenames cannot contain newlines.
            if os.name == 'nt':
                regular = regular.with_name('file name')
            regular.write_bytes(b'abc')
            os.link(regular, root / 'hard link')
            sparse = root / 'sparse'
            with sparse.open('wb') as file:
                file.truncate(1024 * 1024)
            (root / 'file link').symlink_to(regular)
            (root / 'directory link').symlink_to(root / 'nested dir', target_is_directory=True)
            (root / 'dangling link').symlink_to(root / 'absent')
            self.assertEqual(tree_size_bytes(root), 1024 * 1024 + 6)
            self.assertEqual(tree_size_bytes(root / 'directory link'), 0)

    def test_missing_or_non_directory_root_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            file = root / 'file'
            file.touch()
            for invalid in (file, root / 'absent', ''):
                with self.assertRaises(NotADirectoryError):
                    tree_size_bytes(invalid)
            self.assertEqual(tree_size_bytes(root), 0)


@unittest.skipUnless(shutil.which('bash'), 'bash is not installed')
class PerformanceShellTests(unittest.TestCase):
    def run_bash(self, script, root, **extra_env):
        env = dict(os.environ)
        for key in ('PORT_PACK_JOBS', 'PORT_COPY_MODE', 'PORT_LOW_DISK',
                    'PORT_LOG_FILE', 'RAYON_NUM_THREADS'):
            env.pop(key, None)
        env.update(TEST_ROOT=Path(root).as_posix(), LANG='en_US.UTF-8', **extra_env)
        source = shlex.quote((ROOT / 'functions.sh').as_posix())
        return subprocess.run(
            ['bash', '-c', f'source {source} || exit $?\n{script}'],
            cwd=ROOT, env=env, text=True, encoding='utf-8', errors='replace',
            capture_output=True, timeout=30,
        )

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_refills_free_slot_and_respects_concurrency_limit(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.run_bash(r'''
                worker() {
                    printf 'start %s\n' "$1" >> "$TEST_ROOT/events"
                    case "$1" in
                        first)
                            for ((i=0; i<100; i++)); do
                                [[ ! -e "$TEST_ROOT/gate" ]] || break
                                sleep 0.05
                            done
                            [[ -e "$TEST_ROOT/gate" ]] || return 9
                            ;;
                        second) sleep 0.1 ;;
                        third) touch "$TEST_ROOT/gate" ;;
                    esac
                    printf 'end %s\n' "$1" >> "$TEST_ROOT/events"
                }
                port_run_jobs 2 "$TEST_ROOT/logs" worker first second third
            ''', td)
            self.assert_ok(result)
            active = set()
            maximum = 0
            for line in (Path(td) / 'events').read_text().splitlines():
                event, name = line.split()
                if event == 'start':
                    active.add(name)
                    maximum = max(maximum, len(active))
                else:
                    active.remove(name)
            self.assertFalse(active)
            self.assertEqual(maximum, 2)

    def test_failure_stops_queue_and_waits_for_running_writer(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.run_bash(r'''
                worker() {
                    case "$1" in
                        broken) echo 'expected failure'; return 7 ;;
                        running) sleep 0.3; touch "$TEST_ROOT/finished" ;;
                        queued) touch "$TEST_ROOT/unexpected" ;;
                    esac
                }
                port_run_jobs 2 "$TEST_ROOT/logs" worker broken running queued
            ''', td)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('broken failed (exit 7)', result.stderr)
            self.assertTrue((Path(td) / 'finished').exists())
            self.assertFalse((Path(td) / 'unexpected').exists())
            self.assertIn('expected failure', (Path(td) / 'logs/broken.log').read_text())

    def test_copies_do_not_share_mutable_contents_with_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'cache').mkdir()
            (root / 'cache/system image.img').write_bytes(b'original')
            result = self.run_bash(r'''
                port_copy_images "$TEST_ROOT/cache" "$TEST_ROOT/work" || exit $?
                printf changed > "$TEST_ROOT/work/system image.img"
            ''', td)
            self.assert_ok(result)
            self.assertEqual((root / 'cache/system image.img').read_bytes(), b'original')
            self.assertEqual((root / 'work/system image.img').read_bytes(), b'changed')

    def test_low_disk_mode_does_not_write_disposable_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'images').mkdir()
            (root / 'images/system.img').write_bytes(b'image')
            result = self.run_bash(r'''
                port_copy_image() { return 99; }
                PORT_LOW_DISK=true
                port_cache_store_images "$TEST_ROOT/cache" "$TEST_ROOT/images" abcdef0123456789
            ''', td)
            self.assert_ok(result)
            self.assertFalse((root / 'cache').exists())

    def test_pack_limits(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.run_bash(r'''
                [[ "$(port_pack_job_count 1)" == 1 ]] || exit 1
                for value in 1 4 32; do
                    PORT_PACK_JOBS="$value"
                    [[ "$(port_pack_job_count 8)" == "$value" ]] || exit 1
                done
                for value in 0 33 01 invalid; do
                    PORT_PACK_JOBS="$value"
                    if port_pack_job_count 8; then exit 1; fi
                done
            ''', td)
            self.assert_ok(result)

    def test_browser_is_needed_only_for_nonempty_model_queries(self):
        with tempfile.TemporaryDirectory() as td:
            result = self.run_bash(r'''
                if port_requires_browser ' https://example.com/base.zip ' \
                    $'\thttp://example.com/port.zip\n' ' '; then exit 1; fi
                port_requires_browser 'OnePlus 13' https://example.com/port.zip '' || exit 2
                port_requires_browser https://example.com/base.zip ' RMX3300 ' '' || exit 3
                port_requires_browser https://example.com/base.zip https://example.com/port.zip \
                    'OnePlus 12' || exit 4
            ''', td)
            self.assert_ok(result)

    def test_parallel_erofs_packing_skips_size_walk_and_preserves_a17_contexts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            images = root / 'build/portrom/images'
            (images / 'config').mkdir(parents=True)
            for part in ('system', 'vendor'):
                (images / part).mkdir()
                for suffix in ('fs_config', 'file_contexts'):
                    (images / 'config' / f'{part}_{suffix}').touch()
            result = self.run_bash(r'''
                work_dir="$TEST_ROOT"
                pack_type=EROFS
                port_android_version=17
                PORT_PACK_JOBS=2
                port_cpu_count() { echo 4; }
                port_tree_size_bytes() { echo 'unexpected size walk' >&2; return 99; }
                run_fs_and_context_patch() { printf metadata > "$3"; }
                a17_patch_vendor_context_file() {
                    [[ "$(cat "$1")" == metadata ]] || return 8
                    printf '\na17' >> "$1"
                }
                mkfs.erofs() {
                    if [[ "$1" == --help ]]; then echo ' --workers=#'; return; fi
                    local previous='' last='' arg
                    for arg in "$@"; do previous="$last"; last="$arg"; done
                    [[ " $* " == *' --workers=2 '* ]] || return 6
                    if [[ "${last##*/}" == vendor ]]; then
                        grep -q a17 "$last/../config/vendor_file_contexts" || return 5
                    fi
                    printf '%s\n' "${last##*/}" >> "$TEST_ROOT/pack.calls"
                    printf packed > "$previous"
                }
                trap 'touch "$TEST_ROOT/parent-cleanup"' EXIT
                port_pack_images system vendor system absent || exit $?
                [[ ! -e "$TEST_ROOT/parent-cleanup" ]] || exit 12
            ''', td)
            self.assert_ok(result)
            for part in ('system', 'vendor'):
                self.assertEqual((images / f'{part}.img').read_bytes(), b'packed')
                self.assertTrue((root / 'build/logs/pack' / f'{part}.log').exists())
            self.assertFalse((images / 'absent.img').exists())
            self.assertEqual(sorted((root / 'pack.calls').read_text().splitlines()), ['system', 'vendor'])

    def test_ext4_uses_logical_size_and_failed_erofs_keeps_previous_image(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            images = root / 'build/portrom/images'
            (images / 'config').mkdir(parents=True)
            (images / 'system').mkdir()
            (images / 'system/file').write_bytes(b'abc')
            for suffix in ('fs_config', 'file_contexts'):
                (images / 'config' / f'system_{suffix}').touch()
            result = self.run_bash(r'''
                work_dir="$TEST_ROOT"
                pack_type=EXT
                run_fs_and_context_patch() { :; }
                _port::pack_partition_ext4() { printf '%s' "$6" > "$5"; }
                port_pack_one_image system || exit $?
                [[ "$(cat "$TEST_ROOT/build/portrom/images/system.img")" == 3 ]] || exit 9
                mkfs.erofs() {
                    local previous='' last='' arg
                    for arg in "$@"; do previous="$last"; last="$arg"; done
                    printf partial > "$previous"
                    return 7
                }
                if _port::pack_partition_erofs system "$TEST_ROOT/build/portrom/images/system" \
                    ignored ignored "$TEST_ROOT/build/portrom/images/system.img"; then exit 8; fi
            ''', td)
            self.assert_ok(result)
            self.assertEqual((images / 'system.img').read_bytes(), b'3')
            self.assertEqual(list(images.glob('*.tmp.*')), [])


if __name__ == '__main__':
    unittest.main()
