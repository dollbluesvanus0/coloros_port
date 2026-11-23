"""Tests for firmware installers (Windows .bat, macOS/Linux .sh, recovery update-binary) and port.sh generation."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PORT_SH = ROOT / "port.sh"
BAT_SCRIPT = ROOT / "bin" / "flash" / "windows_flash_script.bat"
SH_SCRIPT = ROOT / "bin" / "flash" / "mac_linux_flash_script.sh"
UPDATE_BINARY = ROOT / "bin" / "flash" / "update-binary"


def _find_bash() -> str | None:
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if git_bash.is_file():
        return str(git_bash)
    candidate = shutil.which("bash")
    if candidate:
        probe = subprocess.run([candidate, "-c", "echo ok"], capture_output=True, text=True)
        if probe.returncode == 0 and "ok" in probe.stdout:
            return candidate
    return None


BASH_EXE = _find_bash()


class FlashInstallerStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port_text = PORT_SH.read_text(encoding="utf-8")
        cls.bat_text = BAT_SCRIPT.read_text(encoding="utf-8")
        cls.sh_text = SH_SCRIPT.read_text(encoding="utf-8")
        cls.ub_text = UPDATE_BINARY.read_text(encoding="utf-8")

    def test_windows_bat_uses_delayed_errorlevel_and_bootloader_before_product(self):
        self.assertIn('if not "!errorlevel!" == "0"', self.bat_text)
        self.assertNotIn('if not "%errorlevel%" == "0"', self.bat_text)
        self.assertLess(self.bat_text.index("is-userspace"), self.bat_text.index("getvar product"))
        self.assertNotIn("boot_tv.img", self.bat_text)
        self.assertIn("boot_ksu.img", self.bat_text)
        for cmd in ("erase userdata", "erase metadata", "set_active a", "reboot"):
            matching = [l for l in self.bat_text.splitlines() if f"fastboot.exe %* {cmd}" in l]
            self.assertTrue(matching, f"Expected %* on fastboot {cmd}")

    def test_mac_linux_sh_fixes_brew_fastbootd_and_input_validation(self):
        self.assertNotIn("sudo brew", self.sh_text)
        self.assertLess(self.sh_text.index("get_fb_var is-userspace"), self.sh_text.index("get_fb_var product"))
        self.assertNotIn('[ "$input" -eq "2" ]', self.sh_text)
        self.assertIn('[ "$input" = "2" ]', self.sh_text)
        self.assertIn("boot_ksu.img", self.sh_text)
        self.assertNotIn("boot_tv.img", self.sh_text)

    def test_update_binary_is_posix_and_flashes_modern_ab_partitions(self):
        self.assertIsNone(re.search(r"(^|\s)\[\[", self.ub_text), "POSIX /sbin/sh must not use bash [[")
        for part in ("vbmeta_vendor", "vendor_boot", "init_boot", "recovery", "my_company_a", "my_stock_a"):
            self.assertIn(part, self.ub_text)
        self.assertIn("bootctl set-active-boot-slot 0", self.ub_text)
        self.assertIn("twrp set_active a", self.ub_text)

    def test_port_sh_fixes_init_boot_ksu_and_boot_placeholders(self):
        self.assertIn("init_boot-kernelsu.img", self.port_text)
        self.assertNotIn("boot_tv.img", self.port_text)
        self.assertNotIn("dtbo_tv.img", self.port_text)
        self.assertNotIn("OFFICAL_BOOT_START", self.port_text)
        # Critical partitions must be optional in mac_linux_flash_script.sh as well as .bat
        self.assertIn('Skipped ${fwimg}_a', self.port_text)
        # Non-A/B must also strip _a/_b from windows_flash_script.bat
        self.assertIn('sed -i "/_b/d" out/${os_type}_${rom_version}/windows_flash_script.bat', self.port_text)


@unittest.skipUnless(BASH_EXE, "Working bash is not available")
class FlashInstallerBehaviorTests(unittest.TestCase):
    def _extract_port_sh_gen_block(self) -> str:
        lines = PORT_SH.read_text(encoding="utf-8").splitlines()
        start = next(i for i, l in enumerate(lines) if "mkdir -p out/${os_type}_${rom_version}/META-INF/com/google/android/" in l)
        end = next(i for i, l in enumerate(lines[start:], start) if "unix2dos out/${os_type}_${rom_version}/windows_flash_script.bat" in l)
        return "\n".join(lines[start : end + 1])

    def test_shell_syntax_check(self):
        for script in (PORT_SH, SH_SCRIPT):
            res = subprocess.run([BASH_EXE, "-n", str(script)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
        sh_bin = shutil.which("sh") or BASH_EXE
        res = subprocess.run([sh_bin, "-n", str(UPDATE_BINARY)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_port_sh_installer_generation_ab_and_non_ab(self):
        gen_block = self._extract_port_sh_gen_block()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel in ("bin/flash", "devices/ferrarri", "build/baserom/images", "build/portrom/images"):
                (root / rel).mkdir(parents=True, exist_ok=True)
            shutil.copy2(BAT_SCRIPT, root / "bin/flash/windows_flash_script.bat")
            shutil.copy2(SH_SCRIPT, root / "bin/flash/mac_linux_flash_script.sh")
            shutil.copy2(UPDATE_BINARY, root / "bin/flash/update-binary")
            (root / "bin/flash/zstd").write_bytes(b"zstd")
            (root / "bin/flash/platform-tools-windows").mkdir(parents=True, exist_ok=True)
            (root / "bin/flash/platform-tools-windows/fastboot.exe").write_bytes(b"fb")

            for img in ("boot", "dtbo", "vendor_boot", "recovery", "vbmeta", "vbmeta_system", "vbmeta_vendor", "abl", "tz", "init_boot-kernelsu"):
                data = bytearray(256)
                if img.startswith("vbmeta"):
                    data[:4] = b"AVB0"
                (root / f"build/baserom/images/{img}.img").write_bytes(bytes(data))
            (root / "build/portrom/super.zst").write_bytes(b"superzst")
            (root / "devices/ferrarri/ferrarri_boot_ksu.img").write_bytes(b"ksu")

            script = f"""
            set -e
            cd "{root.as_posix()}"
            blue() {{ :; }}
            run_rom_ops() {{ return 127; }}
            python3() {{ :; }}
            unix2dos() {{ :; }}
            os_type="ColorOS"
            rom_version="V15"
            base_product_device="ferrarri"
            base_device_code="216AC"
            regionmark="RU"
            port_rom_version="15.0"
            base_rom_version="15.0"
            port_android_version="15"
            is_ab_device="true"
            {gen_block}
            """
            script_file = root / "run_gen.sh"
            script_file.write_text(script, encoding="utf-8", newline="\n")
            res = subprocess.run([BASH_EXE, script_file.as_posix()], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            out_dir = root / "out/ColorOS_V15"
            bat = (out_dir / "windows_flash_script.bat").read_text(encoding="utf-8")
            sh = (out_dir / "mac_linux_flash_script.sh").read_text(encoding="utf-8")
            ub = (out_dir / "META-INF/com/google/android/update-binary").read_text(encoding="utf-8")

            # No corrupted escape sequences from sed (\x0c form feed / stripped backslashes)
            self.assertNotIn("\x0c", bat)
            self.assertIn(r"bin\windows\fastboot.exe %* flash vendor_boot_a firmware-update/vendor_boot.img", bat)
            self.assertIn(r"bin\windows\fastboot.exe %* --disable-verity --disable-verification flash vbmeta_vendor_a firmware-update/vbmeta_vendor.img", bat)
            self.assertNotIn("device_code", bat)
            self.assertNotIn("device_code", sh)

            # init_boot-kernelsu must have been normalized to init_boot
            self.assertTrue((out_dir / "firmware-update/init_boot.img").is_file())
            self.assertNotIn("init_boot-kernelsu", bat)
            self.assertNotIn("init_boot-kernelsu", sh)
            self.assertIn("init_boot_a", bat)
            self.assertIn("init_boot_a", sh)

            # Critical partitions must warn instead of exiting in both .bat and .sh
            self.assertIn("Skipped abl_a", bat)
            self.assertIn("Skipped abl_a", sh)

            # KSU boot image renamed cleanly, while dtbo stays dtbo.img because dtbo_ksu.img wasn't provided
            self.assertIn("ferrarri_boot_ksu.img", bat)
            self.assertIn("ferrarri_boot_ksu.img", sh)
            self.assertIn("ferrarri_boot_ksu.img", ub)
            self.assertIn('expected_device="ferrarri"', ub)
            self.assertIn('"device_""code"', ub)
            self.assertIn('dtbo_image="firmware-update/dtbo.img"', ub)

            # Also verify non-A/B generation strips _a/_b from all three installers cleanly
            non_ab_root = Path(td) / "non_ab"
            for rel in ("bin/flash", "devices/op8t", "build/baserom/firmware-update", "build/portrom"):
                (non_ab_root / rel).mkdir(parents=True, exist_ok=True)
            shutil.copy2(BAT_SCRIPT, non_ab_root / "bin/flash/windows_flash_script.bat")
            shutil.copy2(SH_SCRIPT, non_ab_root / "bin/flash/mac_linux_flash_script.sh")
            shutil.copy2(UPDATE_BINARY, non_ab_root / "bin/flash/update-binary")
            (non_ab_root / "bin/flash/zstd").write_bytes(b"zstd")
            (non_ab_root / "bin/flash/platform-tools-windows").mkdir(parents=True, exist_ok=True)
            (non_ab_root / "bin/flash/platform-tools-windows/fastboot.exe").write_bytes(b"fb")
            for img in ("boot", "dtbo", "modem", "vbmeta"):
                data = bytearray(256)
                if img.startswith("vbmeta"):
                    data[:4] = b"AVB0"
                (non_ab_root / f"build/baserom/firmware-update/{img}.img").write_bytes(bytes(data))
            (non_ab_root / "build/portrom/super.zst").write_bytes(b"superzst")

            non_ab_script = f"""
            set -e
            cd "{non_ab_root.as_posix()}"
            blue() {{ :; }}
            run_rom_ops() {{ return 127; }}
            python3() {{ :; }}
            unix2dos() {{ :; }}
            os_type="ColorOS"
            rom_version="V15"
            base_product_device="op8t"
            base_device_code="19805"
            regionmark="CN"
            port_rom_version="15.0"
            base_rom_version="15.0"
            port_android_version="15"
            is_ab_device="false"
            {gen_block}
            """
            non_ab_sh = non_ab_root / "run_non_ab.sh"
            non_ab_sh.write_text(non_ab_script, encoding="utf-8", newline="\n")
            res2 = subprocess.run([BASH_EXE, non_ab_sh.as_posix()], capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            nb_dir = non_ab_root / "out/ColorOS_V15"
            nb_bat = (nb_dir / "windows_flash_script.bat").read_text(encoding="utf-8")
            nb_sh = (nb_dir / "mac_linux_flash_script.sh").read_text(encoding="utf-8")
            nb_ub = (nb_dir / "META-INF/com/google/android/update-binary").read_text(encoding="utf-8")
            for txt in (nb_bat, nb_sh, nb_ub):
                self.assertNotIn("boot_a", txt)
                self.assertNotIn("boot_b", txt)
                self.assertNotIn("dtbo_a", txt)
                self.assertNotIn("dtbo_b", txt)
            self.assertNotIn("set_active a", nb_bat)
            self.assertNotIn("set_active a", nb_sh)
            self.assertNotIn("set-active-boot-slot", nb_ub)

    def test_mac_linux_script_transitions_fastbootd_to_bootloader_and_flashes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "pkg"
            bin_dir = root / "mock_bin"
            pkg.mkdir()
            bin_dir.mkdir()
            (pkg / "firmware-update").mkdir()
            (pkg / "boot_official.img").write_bytes(b"boot")
            (pkg / "firmware-update/dtbo.img").write_bytes(b"dtbo")
            (pkg / "firmware-update/abl.img").write_bytes(b"abl")
            (pkg / "super.zst").write_bytes(b"zst")

            sh_text = SH_SCRIPT.read_text(encoding="utf-8").replace("device_code", "taro")
            lines = sh_text.splitlines()
            idx = next(i for i, l in enumerate(lines) if l.strip() == "# firmware")
            lines.insert(idx + 1, 'fb flash abl_a firmware-update/abl.img || echo "[WARN] Skipped abl_a"')
            (pkg / "mac_linux_flash_script.sh").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

            state_file = root / "userspace"
            state_file.write_text("yes", encoding="utf-8", newline="\n")
            log_file = root / "fb.log"

            (bin_dir / "zstd").write_text(
                '#!/usr/bin/env bash\ncp "$2" "$4"\n', encoding="utf-8", newline="\n"
            )
            (bin_dir / "fastboot").write_text(
                f"""#!/usr/bin/env bash
echo "$*" >> "{log_file.as_posix()}"
if [[ "$*" == *"getvar is-userspace"* ]]; then
  echo "is-userspace: $(cat "{state_file.as_posix()}")"
  exit 0
fi
if [[ "$*" == *"reboot bootloader"* ]]; then
  echo "no" > "{state_file.as_posix()}"
  exit 0
fi
if [[ "$*" == *"getvar product"* ]]; then
  if [[ "$(cat "{state_file.as_posix()}")" == "yes" ]]; then
    echo "product: ossi"
  else
    echo "(bootloader) product: taro"
  fi
  exit 0
fi
if [[ "$*" == *"flash abl_a"* ]]; then
  echo "FAILED (remote: 'Flashing is not allowed for Critical Partitions.')" >&2
  exit 1
fi
exit 0
""",
                encoding="utf-8",
                newline="\n",
            )
            (bin_dir / "clear").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
            for tool in ("zstd", "fastboot", "clear"):
                (bin_dir / tool).chmod(0o755)

            env = dict(os.environ)
            env["PATH"] = f"{bin_dir.as_posix()}:{env['PATH']}"
            env["LANG"] = "en_US.UTF-8"
            res = subprocess.run(
                [BASH_EXE, (pkg / "mac_linux_flash_script.sh").as_posix(), "-s", "9c81e796"],
                input="1\n",
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertIn("-s 9c81e796 reboot bootloader", calls)
            self.assertIn("-s 9c81e796 flash boot_a boot_official.img", calls)
            self.assertIn("-s 9c81e796 flash super super.img", calls)
            self.assertIn("-s 9c81e796 set_active a", calls)
            self.assertIn("-s 9c81e796 reboot", calls)

    def test_update_binary_sideload_flashes_vbmeta_vendor_and_sets_slot_a(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg_zip = root / "sideload_package.zip"
            with zipfile.ZipFile(pkg_zip, "w") as zf:
                zf.writestr("META-INF/zstd", "#!/bin/sh\ncat\n")
                zf.writestr("boot_ksu.img", b"BOOTKSU")
                zf.writestr("firmware-update/dtbo.img", b"DTBO")
                zf.writestr("firmware-update/vendor_boot.img", b"VNDRBOOT")
                zf.writestr("firmware-update/vbmeta.img", b"VBMETA")
                zf.writestr("firmware-update/vbmeta_system.img", b"VBMSYS")
                zf.writestr("firmware-update/vbmeta_vendor.img", b"VBMVND")
                zf.writestr("super.zst", b"SUPERDATA")

            dev_dir = root / "dev/block/bootdevice/by-name"
            map_dir = root / "dev/block/mapper"
            dev_dir.mkdir(parents=True)
            map_dir.mkdir(parents=True)
            for part in (
                "boot_a", "boot_b", "dtbo_a", "dtbo_b", "vendor_boot_a", "vendor_boot_b",
                "vbmeta_a", "vbmeta_b", "vbmeta_system_a", "vbmeta_system_b",
                "vbmeta_vendor_a", "vbmeta_vendor_b", "super",
            ):
                (dev_dir / part).write_bytes(b"")
            for mp in ("system_a", "my_company_a", "my_stock_a"):
                (map_dir / mp).write_bytes(b"")

            ub_text = UPDATE_BINARY.read_text(encoding="utf-8")
            ub_text = ub_text.replace("device_code", "RED8ACL1").replace("PROJECT_CODE", "216AC")
            ub_text = ub_text.replace("/dev/block/bootdevice/by-name", dev_dir.as_posix())
            ub_text = ub_text.replace("/dev/block/mapper", map_dir.as_posix())
            ub_text = ub_text.replace("/dev/tmp", (root / "dev_tmp").as_posix())
            ub_path = root / "update-binary"
            ub_path.write_text(ub_text, encoding="utf-8", newline="\n")

            bin_dir = root / "mock_bin"
            bin_dir.mkdir()
            actions_log = root / "actions.log"
            (bin_dir / "getprop").write_text(
                '#!/bin/sh\ncase "$1" in\n  ro.product.device) echo RED8ACL1;;\n  ro.boot.prjname) echo 216AC;;\nesac\n',
                encoding="utf-8",
                newline="\n",
            )
            (bin_dir / "bootctl").write_text(
                f'#!/bin/sh\necho "bootctl $*" >> "{actions_log.as_posix()}"\n', encoding="utf-8", newline="\n"
            )
            (bin_dir / "twrp").write_text(
                f'#!/bin/sh\necho "twrp $*" >> "{actions_log.as_posix()}"\n', encoding="utf-8", newline="\n"
            )
            (bin_dir / "lptools").write_text(
                f'#!/bin/sh\necho "lptools $*" >> "{actions_log.as_posix()}"\n', encoding="utf-8", newline="\n"
            )
            (bin_dir / "unzip").write_text(
                f"""#!{Path(sys.executable).as_posix()}
import sys, zipfile
args = sys.argv[1:]
mode = args[0] if args else ''
zpath = args[1] if len(args) > 1 else ''
with zipfile.ZipFile(zpath) as zf:
    if mode == '-t':
        sys.exit(0)
    elif mode == '-l':
        print("  Length      Date    Time    Name")
        print("---------  ---------- -----   ----")
        for info in zf.infolist():
            print(f"{{info.file_size:9d}}  2026-01-01 00:00   {{info.filename}}")
    elif mode == '-p':
        sys.stdout.buffer.write(zf.read(args[2]))
""",
                encoding="utf-8",
                newline="\n",
            )
            for tool in ("getprop", "bootctl", "twrp", "lptools", "unzip"):
                (bin_dir / tool).chmod(0o755)

            env = dict(os.environ)
            env["PATH"] = f"{bin_dir.as_posix()}:{env['PATH']}"
            env["BOOTMODE"] = "true"
            res = subprocess.run(
                [BASH_EXE, ub_path.as_posix(), "3", "1", pkg_zip.as_posix()],
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual((dev_dir / "boot_a").read_bytes(), b"BOOTKSU")
            self.assertEqual((dev_dir / "vendor_boot_a").read_bytes(), b"VNDRBOOT")
            self.assertEqual((dev_dir / "vbmeta_vendor_a").read_bytes(), b"VBMVND")
            self.assertEqual((dev_dir / "super").read_bytes(), b"SUPERDATA")

            acts = actions_log.read_text(encoding="utf-8").splitlines()
            self.assertIn("lptools map my_company_a", acts)
            self.assertIn("lptools map my_stock_a", acts)
            self.assertIn("bootctl set-active-boot-slot 0", acts)
            self.assertIn("twrp set_active a", acts)


if __name__ == "__main__":
    unittest.main()
