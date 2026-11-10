"""Tests for firmware pack_method (OTA vs Fastboot) resolution and configuration."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackMethodTests(unittest.TestCase):
    def resolve_pack_method(self, pack_method_env=None, config_val=None):
        """Helper to invoke port.sh pack_method resolution logic in a bash subshell."""
        with tempfile.TemporaryDirectory() as td:
            config_file = Path(td) / "port_config"
            if config_val is not None:
                config_file.write_text(f"pack_method={config_val}\n", encoding="utf-8")
            else:
                config_file.write_text("", encoding="utf-8")

            script = f"""
            port_config_get() {{
                local key="$1"
                local default_value="${{2:-}}"
                local value
                value="$(awk -F= -v key="${{key}}" '
                    /^[[:space:]]*#/ || index($0, "=") == 0 {{ next }}
                    {{
                        lhs=$1; sub(/^[[:space:]]+/, "", lhs); sub(/[[:space:]]+$/, "", lhs)
                        if (lhs == key) {{ value=substr($0, index($0, "=")+1); sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); print value; exit }}
                    }}
                ' "{config_file}" 2>/dev/null)"
                [[ -n "${{value}}" ]] && printf '%s\\n' "${{value}}" || printf '%s\\n' "${{default_value}}"
            }}

            green() {{ :; }}
            error() {{ echo "Error: $1" >&2; }}

            pack_method="${{PACK_METHOD:-$(port_config_get pack_method stock)}}"
            _norm_pack_method="$(printf '%s' "${{pack_method}}" | tr '[:upper:]' '[:lower:]')"
            if [[ "${{_norm_pack_method}}" == "fastboot" ]]; then
                pack_method="fastboot"
            elif [[ "${{_norm_pack_method}}" == "ota" || "${{_norm_pack_method}}" == "stock" ]]; then
                pack_method="stock"
            else
                error "pack_method 必须为 ota 或 fastboot"
                exit 2
            fi
            printf '%s' "${{pack_method}}"
            """
            env = {}
            if pack_method_env is not None:
                env["PACK_METHOD"] = pack_method_env

            res = subprocess.run(
                ["bash", "-c", script],
                env=env,
                capture_output=True,
                text=True,
            )
            return res.returncode, res.stdout, res.stderr

    def test_default_config_resolves_to_stock_ota(self):
        ret, stdout, _ = self.resolve_pack_method(config_val="ota")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "stock")

    def test_stock_config_resolves_to_stock(self):
        ret, stdout, _ = self.resolve_pack_method(config_val="stock")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "stock")

    def test_fastboot_config_resolves_to_fastboot(self):
        ret, stdout, _ = self.resolve_pack_method(config_val="fastboot")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "fastboot")

    def test_env_override_ota(self):
        ret, stdout, _ = self.resolve_pack_method(pack_method_env="ota", config_val="fastboot")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "stock")

    def test_env_override_fastboot(self):
        ret, stdout, _ = self.resolve_pack_method(pack_method_env="fastboot", config_val="ota")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "fastboot")

    def test_case_insensitivity(self):
        ret, stdout, _ = self.resolve_pack_method(pack_method_env="FaStBoOt")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "fastboot")

        ret, stdout, _ = self.resolve_pack_method(pack_method_env="OTA")
        self.assertEqual(ret, 0)
        self.assertEqual(stdout, "stock")

    def test_invalid_pack_method_fails(self):
        ret, _, stderr = self.resolve_pack_method(pack_method_env="invalid_value")
        self.assertEqual(ret, 2)
        self.assertIn("pack_method", stderr)


if __name__ == "__main__":
    unittest.main()
