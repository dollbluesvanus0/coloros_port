//! Stage 2: Direct DEX bytecode & APK/JAR patcher without JVM/Apktool.
//!
//! Provides direct binary parsing and mutation of Dalvik Executable (`.dex`) files
//! and in-memory patching of `.apk` / `.jar` ZIP containers with automatic
//! SHA-1 signature + Adler32 checksum recalculation and 4-byte `zipalign` alignment.

pub mod arsc;
pub mod builder;
pub mod container;
pub mod dex;
pub mod patch;
pub mod relocate;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use container::patch_file_or_container;
use patch::{
    hook_move_result_after_string, patch_apk_protection_dex, patch_inspiration_aod_gate_dex,
    patch_services_dex, replace_sget_with_const_string, replace_string, stub_method, ReturnSpec,
};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "dex-patcher",
    about = "Direct DEX bytecode and APK/JAR patcher without JVM/Apktool"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Stub a method in a DEX/APK/JAR file (`--return true|false`, `--return-void`, `--return-int <val>`)
    StubMethod {
        /// Path to APK, JAR, or DEX file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional path to APK, JAR, or DEX file if `--file` is omitted
        #[arg(value_name = "FILE")]
        pos_file: Option<PathBuf>,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Target class descriptor or name (e.g. `Landroid/util/apk/ApkSignatureVerifier;` or `OplusBgSceneManager`)
        #[arg(short, long)]
        class: Option<String>,

        /// Target method name (or `name(proto)ret`, e.g. `onBootPhase(I)V`)
        #[arg(short, long)]
        method: String,

        /// Optional method prototype descriptor filter (e.g. `(I)V` or `()Z`)
        #[arg(short, long)]
        proto: Option<String>,

        /// Return value (`true`, `false`, `void`, or integer literal)
        #[arg(short = 'r', long = "return", allow_hyphen_values = true)]
        return_val: Option<String>,

        /// Stub method to return void (`return-void`)
        #[arg(long = "return-void")]
        return_void: bool,

        /// Stub method to return an integer (`const/4` or `const/16` + `return v0`)
        #[arg(long = "return-int", allow_hyphen_values = true)]
        return_int: Option<String>,

        /// Fail with non-zero error if zero methods matched across all DEX images
        #[arg(long, visible_alias = "fail-if-missing")]
        require: bool,
    },

    /// Replace a string table entry or `const-string` reference in a DEX/APK/JAR file
    ReplaceString {
        /// Path to APK, JAR, or DEX file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional path to APK, JAR, or DEX file if `--file` is omitted
        #[arg(value_name = "FILE")]
        pos_file: Option<PathBuf>,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Original string to find
        #[arg(long, visible_alias = "from")]
        old: String,

        /// Replacement string
        #[arg(long, visible_alias = "to")]
        new: String,

        /// Optional class descriptor/name filter
        #[arg(short, long)]
        class: Option<String>,

        /// Optional method name filter
        #[arg(short, long)]
        method: Option<String>,

        /// Fail with non-zero error if zero occurrences were patched
        #[arg(long)]
        require: bool,
    },

    /// Apply APK Protection patch (`ApkSignatureVerifier` in `framework.jar`, `.dex`, or decompiled dir)
    PatchApkProtection {
        /// Path to `framework.jar`, `.dex`, or decompiled directory
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Positional path to `framework.jar`, `.dex`, or decompiled directory
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Optional output path (when patching a file)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Fail if zero items matched
        #[arg(long)]
        require: bool,
    },

    /// Replace `sget-object vX, <class>-><field>:Ljava/lang/String;` with `const-string vX, "<value>"`
    ReplaceSget {
        /// Path to APK, JAR, or DEX file
        #[arg(short, long)]
        file: PathBuf,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Target field class (default: `Landroid/os/Build;`)
        #[arg(long, default_value = "Landroid/os/Build;")]
        field_class: String,

        /// Target static field name (default: `MODEL`)
        #[arg(long, default_value = "MODEL")]
        field_name: String,

        /// Constant string value to load instead (e.g. `PLG110`)
        #[arg(long)]
        value: String,

        /// Optional class filter where replacement should occur
        #[arg(short, long)]
        class: Option<String>,

        /// Fail if zero instructions matched
        #[arg(long)]
        require: bool,
    },

    /// Hook `move-result vX` after `const-string` matching a keyword/regex, replacing it with `const/16 vX, <value>`
    HookAfterString {
        /// Path to APK, JAR, or DEX file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional path to APK, JAR, or DEX file if `--file` is omitted
        #[arg(value_name = "FILE")]
        pos_file: Option<PathBuf>,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// String content or regex to search for in `const-string` (e.g. `ro.product.first_api_level`)
        #[arg(long, visible_alias = "keyword")]
        string: String,

        /// Integer value to assign to the `move-result` register (default: `0x22`)
        #[arg(long, default_value = "0x22", allow_hyphen_values = true)]
        value: String,

        /// Optional class descriptor/name filter
        #[arg(short, long)]
        class: Option<String>,

        /// Optional method name/proto filter
        #[arg(short, long)]
        method: Option<String>,

        /// Fail if zero instructions matched
        #[arg(long)]
        require: bool,
    },

    /// Apply `services.jar` signature and shared-UID patches (`ScanPackageUtils`, `ReconcilePackageUtils`, `getMinimumSignatureSchemeVersionForTargetSdk`)
    PatchServices {
        /// Path to `services.jar` or `.dex`
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Positional path to `services.jar` or `.dex`
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Optional output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Fail if zero items matched
        #[arg(long)]
        require: bool,
    },

    /// Apply ColorOS 16 inspiration-AOD capability gate patch (`oplus_keyguard_workshop_aod_support` in `Aod.apk` / `Wallpapers.apk`)
    PatchInspirationAodGate {
        /// Path to `Aod.apk`, `Wallpapers.apk`, or `.dex`
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Positional path to `Aod.apk`, `Wallpapers.apk`, or `.dex`
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Optional output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Succeed with exit code 0 if no gate is found in the target
        #[arg(long)]
        optional: bool,
    },

    /// Apply multiple DEX patches to a single `.apk`/`.jar`/`.dex` in one ZIP/DEX pass
    Batch {
        /// Path to APK, JAR, or DEX file
        #[arg(short, long)]
        file: PathBuf,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Stub method (`[Class::]method[(proto)ret]=true|false|void|<int>`), repeatable
        #[arg(long = "stub")]
        stubs: Vec<String>,

        /// Required stub method (fail if 0 matched across all DEXs): `[Class::]method[(proto)ret]=true|false|void|<int>`
        #[arg(long = "require-stub")]
        require_stubs: Vec<String>,

        /// Replace sget-object string field (`[Class->]FIELD=VALUE`, default class `Landroid/os/Build;`), repeatable
        #[arg(long = "replace-sget")]
        replace_sgets: Vec<String>,

        /// Replace string literal (`OLD=NEW`), repeatable
        #[arg(long = "replace-string")]
        replace_strings: Vec<String>,

        /// Hook move-result after const-string (`STRING=INT_VAL`), repeatable
        #[arg(long = "hook-after-string")]
        hooks: Vec<String>,

        /// Also apply `patch-apk-protection`
        #[arg(long)]
        apk_protection: bool,

        /// Also apply `patch-services`
        #[arg(long)]
        services: bool,

        /// Also apply `patch-inspiration-aod-gate`
        #[arg(long)]
        inspiration_aod_gate: bool,

        /// Do not fail if `--inspiration-aod-gate` finds 0 matches
        #[arg(long)]
        optional_aod_gate: bool,
    },

    /// Fix invalid TYPE_ATTRIBUTE references in resources.arsc (e.g. 0x0196xxxx dynamic color tokens)
    #[command(visible_aliases = ["patch-arsc", "arsc-fix", "fixarsc"])]
    FixArsc {
        /// Path to APK, ZIP, or resources.arsc file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Positional path to APK, ZIP, or resources.arsc file if `--file` is omitted
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Optional output path (defaults to in-place modification)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Fail if zero attributes were patched
        #[arg(long)]
        require: bool,
    },
}

fn parse_stub_spec(raw: &str) -> Result<(Option<String>, String, ReturnSpec)> {
    let (lhs, rhs) = raw
        .split_once('=')
        .with_context(|| format!("Invalid --stub spec '{}' (expected [Class::]method=val)", raw))?;
    let spec = ReturnSpec::parse_str(rhs)
        .with_context(|| format!("Invalid return spec '{}' in '{}'", rhs, raw))?;
    if let Some((cls, method)) = lhs.split_once("::") {
        Ok((Some(cls.trim().to_string()), method.trim().to_string(), spec))
    } else if let Some((cls, method)) = lhs.split_once("->") {
        Ok((Some(cls.trim().to_string()), method.trim().to_string(), spec))
    } else {
        Ok((None, lhs.trim().to_string(), spec))
    }
}

fn parse_sget_spec(raw: &str) -> Result<(String, String, String)> {
    let (lhs, val) = raw
        .split_once('=')
        .with_context(|| format!("Invalid --replace-sget spec '{}' (expected [Class->]FIELD=VALUE)", raw))?;
    if let Some((cls, field)) = lhs.split_once("->") {
        Ok((cls.trim().to_string(), field.trim().to_string(), val.to_string()))
    } else if let Some((cls, field)) = lhs.split_once("::") {
        Ok((cls.trim().to_string(), field.trim().to_string(), val.to_string()))
    } else {
        Ok(("Landroid/os/Build;".to_string(), lhs.trim().to_string(), val.to_string()))
    }
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::StubMethod {
            file,
            pos_file,
            output,
            class,
            method,
            proto,
            return_val,
            return_void,
            return_int,
            require,
        } => {
            let target_file = file
                .or(pos_file)
                .context("Missing target file (pass --file <PATH> or positional <FILE>)")?;

            let spec = if return_void {
                ReturnSpec::Void
            } else if let Some(int_str) = return_int {
                let v = patch::parse_int_literal(&int_str)
                    .with_context(|| format!("Invalid --return-int value: {}", int_str))?;
                ReturnSpec::Int(v)
            } else if let Some(ret_str) = return_val {
                ReturnSpec::parse_str(&ret_str)
                    .with_context(|| format!("Invalid --return value: {}", ret_str))?
            } else {
                ReturnSpec::True
            };

            let count = patch_file_or_container(
                &target_file,
                output.as_deref(),
                |_entry_name, dex| {
                    stub_method(
                        dex,
                        class.as_deref(),
                        &method,
                        proto.as_deref(),
                        spec,
                    )
                },
            )?;

            if require && count == 0 {
                bail!(
                    "stub-method --require: no method matching '{}{}' found in {}",
                    class.as_deref().map(|c| format!("{}::", c)).unwrap_or_default(),
                    method,
                    target_file.display()
                );
            }

            println!(
                "[+] stub-method: patched {} method(s) matching '{}' in {}",
                count,
                method,
                target_file.display()
            );
            Ok(())
        }

        Commands::ReplaceString {
            file,
            pos_file,
            output,
            old,
            new,
            class,
            method,
            require,
        } => {
            let target_file = file
                .or(pos_file)
                .context("Missing target file (pass --file <PATH> or positional <FILE>)")?;

            let count = patch_file_or_container(
                &target_file,
                output.as_deref(),
                |_entry_name, dex| {
                    replace_string(
                        dex,
                        &old,
                        &new,
                        class.as_deref(),
                        method.as_deref(),
                    )
                },
            )?;

            if require && count == 0 {
                bail!("replace-string --require: '{}' not found in {}", old, target_file.display());
            }

            println!(
                "[+] replace-string: patched {} occurrence(s) ('{}' -> '{}') in {}",
                count,
                old,
                new,
                target_file.display()
            );
            Ok(())
        }

        Commands::PatchApkProtection {
            file,
            target,
            output,
            require,
        } => {
            let target_path = file
                .or(target)
                .context("Missing target path for patch-apk-protection")?;

            let count = patch_apk_protection_target(&target_path, output.as_deref())?;
            if require && count == 0 {
                bail!(
                    "patch-apk-protection --require: no ApkSignatureVerifier targets patched in {}",
                    target_path.display()
                );
            }
            println!(
                "[*] APK Protection patch finished. Patched {} item(s) in {}.",
                count,
                target_path.display()
            );
            Ok(())
        }

        Commands::ReplaceSget {
            file,
            output,
            field_class,
            field_name,
            value,
            class,
            require,
        } => {
            let count = patch_file_or_container(&file, output.as_deref(), |_entry_name, dex| {
                replace_sget_with_const_string(
                    dex,
                    &field_class,
                    &field_name,
                    &value,
                    class.as_deref(),
                )
            })?;

            if require && count == 0 {
                bail!(
                    "replace-sget --require: no sget-object {}->{} found in {}",
                    field_class,
                    field_name,
                    file.display()
                );
            }

            println!(
                "[+] replace-sget: patched {} instruction(s) ({}->{} => \"{}\") in {}",
                count,
                field_class,
                field_name,
                value,
                file.display()
            );
            Ok(())
        }

        Commands::HookAfterString {
            file,
            pos_file,
            output,
            string,
            value,
            class,
            method,
            require,
        } => {
            let target_file = file
                .or(pos_file)
                .context("Missing target file (pass --file <PATH> or positional <FILE>)")?;
            let int_val = patch::parse_int_literal(&value)
                .with_context(|| format!("Invalid --value integer literal: {}", value))?;

            let count = patch_file_or_container(&target_file, output.as_deref(), |_name, dex| {
                hook_move_result_after_string(
                    dex,
                    &string,
                    int_val,
                    class.as_deref(),
                    method.as_deref(),
                )
            })?;

            if require && count == 0 {
                bail!(
                    "hook-after-string --require: no move-result after '{}' found in {}",
                    string,
                    target_file.display()
                );
            }

            println!(
                "[+] hook-after-string: patched {} occurrence(s) (string='{}' -> 0x{:x}) in {}",
                count,
                string,
                int_val,
                target_file.display()
            );
            Ok(())
        }

        Commands::PatchServices {
            file,
            target,
            output,
            require,
        } => {
            let target_path = file
                .or(target)
                .context("Missing target path for patch-services")?;
            let count = patch_file_or_container(&target_path, output.as_deref(), |_name, dex| {
                patch_services_dex(dex)
            })?;
            if require && count == 0 {
                bail!("patch-services --require: no targets patched in {}", target_path.display());
            }
            println!(
                "[*] services.jar patch finished. Patched {} item(s) in {}.",
                count,
                target_path.display()
            );
            Ok(())
        }

        Commands::PatchInspirationAodGate {
            file,
            target,
            output,
            optional,
        } => {
            let target_path = file
                .or(target)
                .context("Missing target path for patch-inspiration-aod-gate")?;
            let count = patch_file_or_container(&target_path, output.as_deref(), |_name, dex| {
                patch_inspiration_aod_gate_dex(dex)
            })?;
            if count == 0 && !optional {
                bail!("----> no ColorOS 16 inspiration AOD gate found; refusing a silent no-op");
            }
            println!(
                "[*] Inspiration AOD gate patch finished. Patched {} method(s) in {}.",
                count,
                target_path.display()
            );
            Ok(())
        }

        Commands::Batch {
            file,
            output,
            stubs,
            require_stubs,
            replace_sgets,
            replace_strings,
            hooks,
            apk_protection,
            services,
            inspiration_aod_gate,
            optional_aod_gate,
        } => {
            let parsed_stubs: Vec<_> = stubs
                .iter()
                .map(|s| parse_stub_spec(s))
                .collect::<Result<Vec<_>>>()?;
            let parsed_req_stubs: Vec<_> = require_stubs
                .iter()
                .map(|s| parse_stub_spec(s))
                .collect::<Result<Vec<_>>>()?;
            let parsed_sgets: Vec<_> = replace_sgets
                .iter()
                .map(|s| parse_sget_spec(s))
                .collect::<Result<Vec<_>>>()?;
            let parsed_strings: Vec<(&str, &str)> = replace_strings
                .iter()
                .map(|s| {
                    s.split_once('=')
                        .with_context(|| format!("Invalid --replace-string '{}' (expected OLD=NEW)", s))
                })
                .collect::<Result<Vec<_>>>()?;
            let parsed_hooks: Vec<(String, i32)> = hooks
                .iter()
                .map(|s| {
                    let (pat, val_str) = s
                        .split_once('=')
                        .with_context(|| format!("Invalid --hook-after-string '{}' (expected STRING=INT)", s))?;
                    let v = patch::parse_int_literal(val_str)
                        .with_context(|| format!("Invalid integer '{}' in '{}'", val_str, s))?;
                    Ok((pat.to_string(), v))
                })
                .collect::<Result<Vec<_>>>()?;

            let mut req_counts = vec![0usize; parsed_req_stubs.len()];
            let mut aod_gate_count = 0usize;

            let total = patch_file_or_container(&file, output.as_deref(), |_entry, dex| {
                let mut local = 0usize;
                for (cls, meth, spec) in &parsed_stubs {
                    local += stub_method(dex, cls.as_deref(), meth, None, *spec)?;
                }
                for (i, (cls, meth, spec)) in parsed_req_stubs.iter().enumerate() {
                    let c = stub_method(dex, cls.as_deref(), meth, None, *spec)?;
                    req_counts[i] += c;
                    local += c;
                }
                for (cls, field, val) in &parsed_sgets {
                    local += replace_sget_with_const_string(dex, cls, field, val, None)?;
                }
                for &(old_s, new_s) in &parsed_strings {
                    local += replace_string(dex, old_s, new_s, None, None)?;
                }
                for (pat, val) in &parsed_hooks {
                    local += hook_move_result_after_string(dex, pat, *val, None, None)?;
                }
                if apk_protection {
                    local += patch_apk_protection_dex(dex)?;
                }
                if services {
                    local += patch_services_dex(dex)?;
                }
                if inspiration_aod_gate {
                    let c = patch_inspiration_aod_gate_dex(dex)?;
                    aod_gate_count += c;
                    local += c;
                }
                Ok(local)
            })?;

            for (i, cnt) in req_counts.iter().enumerate() {
                if *cnt == 0 {
                    bail!(
                        "batch --require-stub '{}' matched 0 methods in {}",
                        require_stubs[i],
                        file.display()
                    );
                }
            }
            if inspiration_aod_gate && !optional_aod_gate && aod_gate_count == 0 {
                bail!("----> no ColorOS 16 inspiration AOD gate found; refusing a silent no-op");
            }

            println!("[+] batch: applied {} total modification(s) to {}", total, file.display());
            Ok(())
        }

        Commands::FixArsc {
            file,
            target,
            output,
            require,
        } => run_fix_arsc(file, target, output, require),
    }
}

/// Run the `fix-arsc` command against a file or container.
pub fn run_fix_arsc(
    file: Option<PathBuf>,
    target: Option<PathBuf>,
    output: Option<PathBuf>,
    require: bool,
) -> Result<()> {
    let target_file = file
        .or(target)
        .context("Missing target file (pass --file <PATH> or positional <TARGET>)")?;

    let count = container::patch_arsc_in_container(&target_file, output.as_deref())?;

    if require && count == 0 {
        bail!(
            "fix-arsc --require: no invalid TYPE_ATTRIBUTE references found in {}",
            target_file.display()
        );
    }

    println!(
        "[+] fix-arsc: patched {} attribute reference(s) (TYPE_ATTRIBUTE -> TYPE_REFERENCE) in {}",
        count,
        target_file.display()
    );
    Ok(())
}

/// Apply APK Protection patch to either a `.jar`/`.apk`/`.dex` file or a decompiled directory.
pub fn patch_apk_protection_target(target: &Path, output: Option<&Path>) -> Result<usize> {
    if target.is_file() {
        return patch_file_or_container(target, output, |_name, dex| {
            patch_apk_protection_dex(dex)
        });
    }

    if target.is_dir() {
        let mut total = 0usize;
        // 1. Patch any .dex files under the directory
        let dex_files = coloros_common::collect_files_with_ext(target, "dex", true);
        for df in dex_files {
            total += patch_file_or_container(&df, None, |_name, dex| {
                patch_apk_protection_dex(dex)
            })?;
        }
        // 2. Patch any ApkSignatureVerifier.smali files under the directory (compatibility with decompiled dirs)
        let smali_files = coloros_common::collect_files_with_ext(target, "smali", true);
        for sf in smali_files {
            if sf
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "ApkSignatureVerifier.smali")
                .unwrap_or(false)
            {
                let content = fs::read_to_string(&sf)?;
                let (new_content, changed) = patch_apk_signature_verifier_smali(&content);
                if changed {
                    fs::write(&sf, new_content)?;
                    println!("[+] Patched ApkSignatureVerifier in {}", sf.display());
                    total += 1;
                }
            }
        }
        return Ok(total);
    }

    bail!("Target not found: {}", target.display())
}

/// Smali fallback for `ApkSignatureVerifier.smali` when `patch-apk-protection` is passed a decompiled directory.
pub fn patch_apk_signature_verifier_smali(content: &str) -> (String, bool) {
    let mut modified = false;
    let mut current = content.to_string();

    // 1. getMinimumSignatureSchemeVersionForTargetSdk -> return 1
    let min_sig_re = Regex::new(
        r"(?ms)^(?P<header>[ \t]*\.method[^\n\r]*?[ \t]getMinimumSignatureSchemeVersionForTargetSdk\([^\r\n]*\r?\n)(?P<body>.*?)(?P<footer>^[ \t]*\.end method)",
    )
    .unwrap();
    if let Some(m) = min_sig_re.captures(&current) {
        let full = m.get(0).unwrap();
        let replacement = format!(
            "{}\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n{}",
            &m["header"], &m["footer"]
        );
        current.replace_range(full.range(), &replacement);
        modified = true;
    }

    // 2. verifySignaturesInternal -> insert const/4 p3, 0x0 before Landroid/util/apk/ApkSignatureVerifier;->verifyV
    let verify_re = Regex::new(
        r"(?ms)^(?P<header>[ \t]*\.method[^\n\r]*?[ \t]verifySignaturesInternal\([^\r\n]*\r?\n)(?P<body>.*?)(?P<footer>^[ \t]*\.end method)",
    )
    .unwrap();
    if let Some(m) = verify_re.captures(&current) {
        let full = m.get(0).unwrap();
        let body = &m["body"];
        if !body.contains("const/4 p3, 0x0") {
            let mut new_lines = String::with_capacity(body.len() + 64);
            let mut body_changed = false;
            for line in body.split_inclusive('\n') {
                if line.contains("Landroid/util/apk/ApkSignatureVerifier;->verifyV") {
                    let indent: String = line.chars().take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n').collect();
                    let indent = if indent.is_empty() { "    " } else { &indent };
                    new_lines.push_str(indent);
                    new_lines.push_str("const/4 p3, 0x0\n");
                    body_changed = true;
                }
                new_lines.push_str(line);
            }
            if body_changed {
                let replacement = format!("{}{}{}", &m["header"], new_lines, &m["footer"]);
                current.replace_range(full.range(), &replacement);
                modified = true;
            }
        }
    }

    (current, modified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{encode_single_try_catch_all, DexBuilder, MethodSpec};
    use crate::container::{inspect_zip_data_offsets, patch_zip_bytes, verify_zip_alignment_4};
    use crate::dex::{insert_insns_at, CodeItem, DexFile, ACC_STATIC};
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// Build a synthetic `framework.jar`-like DEX containing `Landroid/util/apk/ApkSignatureVerifier;`
    /// and a second class `Lcom/oplus/TestClass;`.
    fn build_sample_dex() -> Vec<u8> {
        let mut b = DexBuilder::new();
        let verifier_class = "Landroid/util/apk/ApkSignatureVerifier;";
        let parse_input = "Landroid/content/pm/parsing/result/ParseInput;";
        let parse_result = "Landroid/content/pm/parsing/result/ParseResult;";
        let string_t = "Ljava/lang/String;";

        b.add_class(verifier_class, "Ljava/lang/Object;");
        // Callee method reference: verifyV1Signature(ParseInput, String, int)ParseResult
        b.add_method_ref(
            verifier_class,
            "verifyV1Signature",
            &[parse_input, string_t, "I"],
            parse_result,
        );

        // Method 1: getMinimumSignatureSchemeVersionForTargetSdk(I)I
        // Original body: const/4 v0, 0x2 (0x2012); return v0 (0x000f)
        b.add_method(MethodSpec {
            class_desc: verifier_class.to_string(),
            name: "getMinimumSignatureSchemeVersionForTargetSdk".to_string(),
            params: vec!["I".to_string()],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            insns: vec![0x2012, 0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        // First build once to find exact method_idx of verifyV1Signature
        let mut temp_b = b.clone();
        temp_b.add_method(MethodSpec {
            class_desc: verifier_class.to_string(),
            name: "verifySignaturesInternal".to_string(),
            params: vec![
                parse_input.to_string(),
                string_t.to_string(),
                "I".to_string(),
                "Z".to_string(),
            ],
            return_type: parse_result.to_string(),
            access_flags: 0x0002 | ACC_STATIC,
            is_direct: true,
            registers_size: 5,
            ins_size: 4,
            outs_size: 3,
            insns: vec![0x000e],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let parsed_tmp = DexFile::parse(temp_b.build()).unwrap();
        let verify_v1_idx = (0..parsed_tmp.methods.len())
            .find(|&i| {
                parsed_tmp
                    .get_method_signature(i as u32)
                    .map(|(_, n, _)| n == "verifyV1Signature")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        // Method 2: verifySignaturesInternal(ParseInput, String, I, Z)ParseResult
        // .registers 5 (v0 local, p0=v1, p1=v2, p2=v3, p3=v4)
        // invoke-static {v1, v2, v3}, verifyV1Signature -> [0x3071, verify_v1_idx, 0x0321]
        // move-result-object v0 -> [0x000c]
        // return-object v0 -> [0x0011]
        b.add_method(MethodSpec {
            class_desc: verifier_class.to_string(),
            name: "verifySignaturesInternal".to_string(),
            params: vec![
                parse_input.to_string(),
                string_t.to_string(),
                "I".to_string(),
                "Z".to_string(),
            ],
            return_type: parse_result.to_string(),
            access_flags: 0x0002 | ACC_STATIC,
            is_direct: true,
            registers_size: 5,
            ins_size: 4,
            outs_size: 3,
            insns: vec![0x3071, verify_v1_idx, 0x0321, 0x000c, 0x0011],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        b.build()
    }

    #[test]
    fn test_dex_hashes_and_roundtrip() {
        let raw = build_sample_dex();
        let mut dex = DexFile::parse(raw).expect("valid synthetic DEX");
        assert!(dex.verify_hashes(), "initial DEX hashes should be valid");

        // Corrupt a byte in header checksum and verify it fails
        dex.data[8] ^= 0xff;
        assert!(!dex.verify_hashes(), "corrupted checksum must fail verification");

        // Recalculate hashes and verify it passes again
        dex.update_hashes();
        assert!(dex.verify_hashes(), "recalculated hashes must pass verification");
    }

    #[test]
    fn test_stub_method_true_false_void_int() {
        let mut b = DexBuilder::new();
        let cls = "Lcom/oplus/TestTarget;";
        b.add_class(cls, "Ljava/lang/Object;");
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "isGmsRestricted".to_string(),
            params: vec![],
            return_type: "Z".to_string(),
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            insns: vec![0x1012, 0x000f], // originally returns true
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "isSupportFullAod".to_string(),
            params: vec![],
            return_type: "Z".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0012, 0x000f], // originally returns false
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "onBootPhase".to_string(),
            params: vec!["I".to_string()],
            return_type: "V".to_string(),
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 3,
            ins_size: 2,
            outs_size: 1,
            insns: vec![0x1012, 0x2012, 0x000e],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "getFirstApiLevel".to_string(),
            params: vec![],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0012, 0x000f], // only 2 code units initially!
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mut dex = DexFile::parse(b.build()).unwrap();

        // 1. Stub isGmsRestricted -> false (`const/4 v0, 0x0; return v0`)
        let n1 = stub_method(&mut dex, Some("TestTarget"), "isGmsRestricted", None, ReturnSpec::False).unwrap();
        assert_eq!(n1, 1);

        // 2. Stub isSupportFullAod -> true (`const/4 v0, 0x1; return v0`)
        let n2 = stub_method(&mut dex, Some(cls), "isSupportFullAod", None, ReturnSpec::True).unwrap();
        assert_eq!(n2, 1);

        // 3. Stub onBootPhase(I)V -> void (`return-void`)
        let n3 = stub_method(&mut dex, Some("TestTarget"), "onBootPhase(I)V", None, ReturnSpec::Void).unwrap();
        assert_eq!(n3, 1);

        // 4. Stub getFirstApiLevel -> int 0x22 (34) (`const/16 v0, 0x22; return v0` - grows from 2 to 3 units!)
        let n4 = stub_method(&mut dex, Some(cls), "getFirstApiLevel", None, ReturnSpec::Int(0x22)).unwrap();
        assert_eq!(n4, 1);

        assert!(dex.verify_hashes(), "DEX hashes must be valid after all stub operations");

        // Re-parse from mutated bytes and verify instructions of each method
        let reparsed = DexFile::parse(dex.data).unwrap();
        let cd = reparsed.read_class_data(reparsed.class_defs[0].class_data_off).unwrap();
        for em in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            let (_, name, _) = reparsed.get_method_signature(em.method_idx).unwrap();
            let code = reparsed.read_code_item(em.code_off).unwrap();
            match name.as_str() {
                "isGmsRestricted" => assert_eq!(code.insns, vec![0x0012, 0x000f]),
                "isSupportFullAod" => assert_eq!(code.insns, vec![0x1012, 0x000f]),
                "onBootPhase" => assert_eq!(code.insns, vec![0x000e]),
                "getFirstApiLevel" => assert_eq!(code.insns, vec![0x0013, 0x0022, 0x000f]),
                other => panic!("unexpected method {}", other),
            }
        }
    }

    #[test]
    fn test_replace_string_short_and_long() {
        let mut b = DexBuilder::new();
        let cls = "Lcom/heytap/AiCallCommonBean;";
        b.add_class(cls, "Ljava/lang/Object;");
        b.add_string("OLD_MODEL");
        b.add_string("VERY_LONG_REPLACEMENT_MODEL_STRING_1234567890");

        // Build once to get string index of "OLD_MODEL"
        let mut tmp_b = b.clone();
        tmp_b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "getModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x001a, 0x0000, 0x0011],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let tmp_dex = DexFile::parse(tmp_b.build()).unwrap();
        let old_str_idx = tmp_dex.strings.iter().position(|s| s == "OLD_MODEL").unwrap() as u16;

        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "getModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x001a, old_str_idx, 0x0011], // const-string v0, "OLD_MODEL"; return-object v0
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mut dex = DexFile::parse(b.build()).unwrap();

        // 1. Replace with shorter string "PLG110" (fits in-place)
        let c1 = replace_string(&mut dex, "OLD_MODEL", "PLG110", None, None).unwrap();
        assert!(c1 >= 1);
        assert!(dex.verify_hashes());
        let dex2 = DexFile::parse(dex.data.clone()).unwrap();
        assert_eq!(dex2.get_string(old_str_idx as u32), Some("PLG110"));

        // 2. Replace "PLG110" with a much longer string (appends to data section)
        let long_str = "CPH2745_EXTENDED_SUPER_LONG_DEVICE_MODEL_IDENTIFIER";
        let c2 = replace_string(&mut dex, "PLG110", long_str, None, None).unwrap();
        assert!(c2 >= 1);
        assert!(dex.verify_hashes());
        let dex3 = DexFile::parse(dex.data).unwrap();
        assert_eq!(dex3.get_string(old_str_idx as u32), Some(long_str));
    }

    #[test]
    fn test_patch_apk_protection_dex_and_idempotency() {
        let raw = build_sample_dex();
        let mut dex = DexFile::parse(raw).unwrap();

        let count = patch_apk_protection_dex(&mut dex).unwrap();
        assert_eq!(count, 2, "should patch both getMinimumSignatureSchemeVersionForTargetSdk and verifySignaturesInternal");
        assert!(dex.verify_hashes());

        // Re-parse and verify instructions
        let mut reparsed = DexFile::parse(dex.data).unwrap();
        assert!(reparsed.verify_hashes());

        let cd = reparsed
            .read_class_data(reparsed.class_defs[0].class_data_off)
            .unwrap();
        for em in &cd.direct_methods {
            let (_, name, _) = reparsed.get_method_signature(em.method_idx).unwrap();
            let code = reparsed.read_code_item(em.code_off).unwrap();
            if name == "getMinimumSignatureSchemeVersionForTargetSdk" {
                // Must be stubbed to const/4 v0, 0x1; return v0
                assert_eq!(code.insns, vec![0x1012, 0x000f]);
            } else if name == "verifySignaturesInternal" {
                // With .registers 5 and ins_size 4, p3 is v4 -> const/4 v4, 0x0 is 0x0412
                assert_eq!(
                    code.insns[0], 0x0412,
                    "first instruction before invoke-static verifyV1Signature must be const/4 p3(v4), 0x0"
                );
                assert_eq!(code.insns.len(), 6);
            }
        }

        // Running a second time must not duplicate `const/4 p3, 0x0`
        let count2 = patch_apk_protection_dex(&mut reparsed).unwrap();
        assert_eq!(count2, 1, "only stub_method runs; verifySignaturesInternal is already patched");
        let cd2 = reparsed
            .read_class_data(reparsed.class_defs[0].class_data_off)
            .unwrap();
        for em in &cd2.direct_methods {
            let (_, name, _) = reparsed.get_method_signature(em.method_idx).unwrap();
            if name == "verifySignaturesInternal" {
                let code = reparsed.read_code_item(em.code_off).unwrap();
                assert_eq!(code.insns.len(), 6, "verifySignaturesInternal must not grow on second run");
            }
        }
    }

    #[test]
    fn test_branch_and_try_adjustment_on_insert() {
        let mut b = DexBuilder::new();
        let verifier_class = "Landroid/util/apk/ApkSignatureVerifier;";
        b.add_class(verifier_class, "Ljava/lang/Object;");
        b.add_method_ref(verifier_class, "verifyV2", &["I"], "I");

        // Build once to get method_idx of verifyV2
        let mut tmp = b.clone();
        tmp.add_method(MethodSpec {
            class_desc: verifier_class.to_string(),
            name: "verifySignaturesInternal".to_string(),
            params: vec!["I".to_string(), "I".to_string(), "I".to_string(), "Z".to_string()],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 5,
            ins_size: 4,
            outs_size: 1,
            insns: vec![0x000e],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let tmp_dex = DexFile::parse(tmp.build()).unwrap();
        let verify_v2_idx = (0..tmp_dex.methods.len())
            .find(|&i| {
                tmp_dex
                    .get_method_signature(i as u32)
                    .map(|(_, n, _)| n == "verifyV2")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        // Instructions before insertion:
        // pc=0 (len 2): if-eqz v4, +6 (target pc=6) -> [0x0438, 0x0006]
        // pc=2 (len 3): invoke-static {v1}, verifyV2 -> [0x1071, verify_v2_idx, 0x0001]
        // pc=5 (len 1): move-result v0 -> [0x000a]
        // pc=6 (len 1): return v0 -> [0x000f]
        // Try block covering pc 0..6 with catch-all at pc 6
        let tries_raw = encode_single_try_catch_all(0, 6, 6);
        b.add_method(MethodSpec {
            class_desc: verifier_class.to_string(),
            name: "verifySignaturesInternal".to_string(),
            params: vec!["I".to_string(), "I".to_string(), "I".to_string(), "Z".to_string()],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 5,
            ins_size: 4,
            outs_size: 1,
            insns: vec![0x0438, 0x0006, 0x1071, verify_v2_idx, 0x0001, 0x000a, 0x000f],
            tries_size: 1,
            tries_and_handlers: tries_raw,
        });

        let mut dex = DexFile::parse(b.build()).unwrap();
        let patched = patch_apk_protection_dex(&mut dex).unwrap();
        assert_eq!(patched, 1);
        assert!(dex.verify_hashes());

        let reparsed = DexFile::parse(dex.data).unwrap();
        let cd = reparsed
            .read_class_data(reparsed.class_defs[0].class_data_off)
            .unwrap();
        let code = reparsed.read_code_item(cd.direct_methods[0].code_off).unwrap();
        // After inserting 1 unit at pc=2, the branch at pc=0 targeting old pc=6 must now have offset +7!
        assert_eq!(code.insns[0], 0x0438);
        assert_eq!(code.insns[1], 0x0007, "branch offset across inserted instruction must be incremented from 6 to 7");
        assert_eq!(code.insns[2], 0x0412, "inserted const/4 v4, 0x0 at pc=2");
    }

    #[test]
    fn test_replace_sget_with_const_string() {
        let mut b = DexBuilder::new();
        let cls = "Lcom/oplus/aiunit/UnitConfig;";
        let build_cls = "Landroid/os/Build;";
        b.add_class(cls, "Ljava/lang/Object;");
        b.add_field_ref(build_cls, "MODEL", "Ljava/lang/String;");

        // Build once to get field_idx of Build->MODEL
        let mut tmp = b.clone();
        tmp.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "checkModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0062, 0x0000, 0x0011],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let tmp_dex = DexFile::parse(tmp.build()).unwrap();
        let model_field_idx = (0..tmp_dex.fields.len())
            .find(|&i| {
                tmp_dex
                    .get_field_signature(i as u32)
                    .map(|(_, n, _)| n == "MODEL")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "checkModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 2,
            ins_size: 0,
            outs_size: 0,
            // sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String; (0x0162, model_field_idx)
            // return-object v1 (0x0111)
            insns: vec![0x0162, model_field_idx, 0x0111],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mut dex = DexFile::parse(b.build()).unwrap();
        let count = replace_sget_with_const_string(
            &mut dex,
            "Landroid/os/Build;",
            "MODEL",
            "PLG110",
            None,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert!(dex.verify_hashes());

        let reparsed = DexFile::parse(dex.data).unwrap();
        let cd = reparsed
            .read_class_data(reparsed.class_defs[0].class_data_off)
            .unwrap();
        let code = reparsed.read_code_item(cd.direct_methods[0].code_off).unwrap();
        // 0x011a = const-string v1, string@BBBB
        assert_eq!(code.insns[0], 0x011a);
        let str_val = reparsed.get_string(code.insns[1] as u32).unwrap();
        assert_eq!(str_val, "PLG110");
    }

    #[test]
    fn test_apk_jar_zip_container_and_4byte_alignment() {
        let dex1 = build_sample_dex();
        let dex2 = build_sample_dex();

        // Create an unaligned APK/JAR container with classes.dex, classes2.dex, resources.arsc, and AndroidManifest.xml
        let mut zip_buf = Vec::new();
        {
            let mut zw = ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zw.start_file("META-INF/MANIFEST.MF", deflated).unwrap();
            zw.write_all(b"Manifest-Version: 1.0\r\n").unwrap();

            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("resources.arsc", stored).unwrap();
            zw.write_all(&[0x02, 0x00, 0x0c, 0x00, 0x11, 0x22, 0x33, 0x44]).unwrap();

            zw.start_file("classes.dex", stored).unwrap();
            zw.write_all(&dex1).unwrap();

            zw.start_file("classes2.dex", stored).unwrap();
            zw.write_all(&dex2).unwrap();

            zw.start_file("res/xml/config.xml", deflated).unwrap();
            zw.write_all(b"<config/>").unwrap();

            zw.finish().unwrap();
        }

        let (patched_zip, total_patched) =
            patch_zip_bytes(&zip_buf, |_name, dex| patch_apk_protection_dex(dex)).unwrap();
        assert_eq!(total_patched, 4, "2 patches in classes.dex + 2 patches in classes2.dex");

        // Verify 4-byte alignment of all Stored entries (resources.arsc, classes.dex, classes2.dex)
        verify_zip_alignment_4(&patched_zip).expect("All Stored entries must be 4-byte aligned");

        let offsets = inspect_zip_data_offsets(&patched_zip).unwrap();
        for (name, offset, method) in &offsets {
            if *method == CompressionMethod::Stored {
                assert_eq!(
                    offset % 4,
                    0,
                    "Entry {} at offset {} is not 4-byte aligned",
                    name,
                    offset
                );
            }
        }

        // Verify CLI round-trip on an APK file on disk
        let tmp = TempDir::new().unwrap();
        let apk_path = tmp.path().join("framework.jar");
        fs::write(&apk_path, &zip_buf).unwrap();

        run_cli(Cli {
            command: Commands::PatchApkProtection {
                file: Some(apk_path.clone()),
                target: None,
                output: None,
                require: false,
            },
        })
        .unwrap();

        let disk_zip = fs::read(&apk_path).unwrap();
        verify_zip_alignment_4(&disk_zip).unwrap();
    }

    #[test]
    fn test_patch_services_dex_and_inspiration_aod_gate() {
        let mut b = DexBuilder::new();
        let scan_cls = "Lcom/android/server/pm/ScanPackageUtils;";
        let reconcile_cls = "Lcom/android/server/pm/ReconcilePackageUtils;";
        let aod_cls = "Lcom/oplus/aod/util/CommonUtils;";

        b.add_class(scan_cls, "Ljava/lang/Object;");
        b.add_class(reconcile_cls, "Ljava/lang/Object;");
        b.add_class(aod_cls, "Ljava/lang/Object;");

        b.add_method_ref(
            "Landroid/util/apk/ApkSignatureVerifier;",
            "getMinimumSignatureSchemeVersionForTargetSdk",
            &["I"],
            "I",
        );
        b.add_field_ref(
            reconcile_cls,
            "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS",
            "Z",
        );
        b.add_string("oplus_keyguard_workshop_aod_support");
        b.add_method_ref(
            "Landroid/provider/Settings$Secure;",
            "getInt",
            &["Landroid/content/ContentResolver;", "Ljava/lang/String;", "I"],
            "I",
        );
        // Pre-register all method signatures so string/method table indices are identical
        b.add_method_ref(scan_cls, "assertMinSignatureSchemeIsValid", &[], "V");
        b.add_method_ref(scan_cls, "checkMinSig", &["I"], "I");
        b.add_method_ref(reconcile_cls, "<clinit>", &[], "V");
        b.add_method_ref(aod_cls, "isInspirationAodEnabled", &[], "I");

        let tmp_dex = DexFile::parse(b.build()).unwrap();
        let get_min_sig_idx = (0..tmp_dex.methods.len())
            .find(|&i| {
                tmp_dex
                    .get_method_signature(i as u32)
                    .map(|(_, n, _)| n == "getMinimumSignatureSchemeVersionForTargetSdk")
                    .unwrap_or(false)
            })
            .unwrap() as u16;
        let allow_shared_idx = (0..tmp_dex.fields.len())
            .find(|&i| {
                tmp_dex
                    .get_field_signature(i as u32)
                    .map(|(_, n, _)| n == "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS")
                    .unwrap_or(false)
            })
            .unwrap() as u16;
        let aod_str_idx = tmp_dex
            .strings
            .iter()
            .position(|s| s == "oplus_keyguard_workshop_aod_support")
            .unwrap() as u16;
        let get_int_idx = (0..tmp_dex.methods.len())
            .find(|&i| {
                tmp_dex
                    .get_method_signature(i as u32)
                    .map(|(_, n, _)| n == "getInt")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        // 1. ScanPackageUtils.assertMinSignatureSchemeIsValid
        b.add_method(MethodSpec {
            class_desc: scan_cls.to_string(),
            name: "assertMinSignatureSchemeIsValid".to_string(),
            params: vec![],
            return_type: "V".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x1012, 0x000e],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        // 2. ScanPackageUtils.checkMinSig calling getMinimumSignatureSchemeVersionForTargetSdk + move-result v2
        b.add_method(MethodSpec {
            class_desc: scan_cls.to_string(),
            name: "checkMinSig".to_string(),
            params: vec!["I".to_string()],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 3,
            ins_size: 1,
            outs_size: 1,
            insns: vec![0x1071, get_min_sig_idx, 0x0002, 0x020a, 0x020f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        // 3. ReconcilePackageUtils.<clinit> doing sput-boolean v0, ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS
        b.add_method(MethodSpec {
            class_desc: reconcile_cls.to_string(),
            name: "<clinit>".to_string(),
            params: vec![],
            return_type: "V".to_string(),
            access_flags: 0x10008,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0012, 0x006a, allow_shared_idx, 0x000e],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        // 4. CommonUtils.isInspirationAodEnabled checking oplus_keyguard_workshop_aod_support via Settings.Secure.getInt
        b.add_method(MethodSpec {
            class_desc: aod_cls.to_string(),
            name: "isInspirationAodEnabled".to_string(),
            params: vec![],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 3,
            ins_size: 0,
            outs_size: 3,
            // const-string v1, "oplus_keyguard_workshop_aod_support" (0x011a, aod_str_idx)
            // invoke-static {v0, v1, v2}, Settings$Secure->getInt (0x3071, get_int_idx, 0x0210)
            // move-result v0 (0x000a)
            // return v0 (0x000f)
            insns: vec![0x011a, aod_str_idx, 0x3071, get_int_idx, 0x0210, 0x000a, 0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mut dex = DexFile::parse(b.build()).unwrap();
        let svc_count = patch_services_dex(&mut dex).unwrap();
        assert_eq!(svc_count, 3);
        let aod_count = patch_inspiration_aod_gate_dex(&mut dex).unwrap();
        assert_eq!(aod_count, 1);
        assert!(dex.verify_hashes());
    }

    #[test]
    fn test_leb128_roundtrip_and_return_spec_encodings() {
        for &u in &[0u32, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x0fff_ffff] {
            let mut buf = Vec::new();
            dex::write_uleb128(&mut buf, u);
            let (decoded, len) = dex::read_uleb128(&buf, 0).unwrap();
            assert_eq!(decoded, u);
            assert_eq!(len, buf.len());
        }

        for &s in &[0i32, 1, -1, 63, 64, -64, -65, 8191, -8192, 100_000, -100_000] {
            let mut buf = Vec::new();
            dex::write_sleb128(&mut buf, s);
            let (decoded, len) = dex::read_sleb128(&buf, 0).unwrap();
            assert_eq!(decoded, s);
            assert_eq!(len, buf.len());
        }

        // ReturnSpec encoding checks:
        assert_eq!(ReturnSpec::True.encode_insns(), vec![0x1012, 0x000f]);
        assert_eq!(ReturnSpec::False.encode_insns(), vec![0x0012, 0x000f]);
        assert_eq!(ReturnSpec::Void.encode_insns(), vec![0x000e]);
        assert_eq!(ReturnSpec::Int(-1).encode_insns(), vec![0xf012, 0x000f]);
        assert_eq!(ReturnSpec::Int(7).encode_insns(), vec![0x7012, 0x000f]);
        assert_eq!(ReturnSpec::Int(0x22).encode_insns(), vec![0x0013, 0x0022, 0x000f]);
        assert_eq!(
            ReturnSpec::Int(0x1234_5678).encode_insns(),
            vec![0x0014, 0x5678, 0x1234, 0x000f]
        );
    }

    #[test]
    fn test_zip_alignment_across_all_filename_lengths_mod_4() {
        let dex_bytes = build_sample_dex();
        let mut zip_buf = Vec::new();
        {
            let mut zw = ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            // Names with lengths 0, 1, 2, 3 (mod 4) and odd payload lengths
            for (name, payload) in [
                ("a.arsc", &[1u8, 2, 3][..]),
                ("ab.so", &[1u8, 2, 3, 4, 5][..]),
                ("abc.so", &[1u8][..]),
                ("abcd.so", &[1u8, 2][..]),
                ("classes.dex", dex_bytes.as_slice()),
                ("classes2.dex", dex_bytes.as_slice()),
                ("classes10.dex", dex_bytes.as_slice()),
                ("resources.arsc", &[0u8; 17][..]),
            ] {
                zw.start_file(name, stored).unwrap();
                zw.write_all(payload).unwrap();
            }
            zw.finish().unwrap();
        }

        let (repacked_zip, patched_count) =
            patch_zip_bytes(&zip_buf, |_name, dex| patch_apk_protection_dex(dex)).unwrap();
        assert_eq!(patched_count, 6);
        verify_zip_alignment_4(&repacked_zip).unwrap();
    }

    #[test]
    fn test_cli_subcommands_and_smali_dir_fallback() {
        let tmp = TempDir::new().unwrap();

        // 1. Test CLI commands on a .dex file
        let dex_path = tmp.path().join("classes.dex");
        fs::write(&dex_path, build_sample_dex()).unwrap();

        let cli_stub_true = Cli::parse_from([
            "dex-patcher",
            "stub-method",
            "--file",
            dex_path.to_str().unwrap(),
            "--class",
            "ApkSignatureVerifier",
            "--method",
            "getMinimumSignatureSchemeVersionForTargetSdk",
            "--return",
            "true",
        ]);
        run_cli(cli_stub_true).unwrap();

        let cli_stub_int = Cli::parse_from([
            "dex-patcher",
            "stub-method",
            "--file",
            dex_path.to_str().unwrap(),
            "--class",
            "ApkSignatureVerifier",
            "--method",
            "getMinimumSignatureSchemeVersionForTargetSdk",
            "--return-int",
            "0x22",
        ]);
        run_cli(cli_stub_int).unwrap();

        let cli_replace_str = Cli::parse_from([
            "dex-patcher",
            "replace-string",
            "--file",
            dex_path.to_str().unwrap(),
            "--old",
            "verifyV1Signature",
            "--new",
            "verifyV1SigPatched",
        ]);
        run_cli(cli_replace_str).unwrap();

        let parsed_after = DexFile::parse(fs::read(&dex_path).unwrap()).unwrap();
        assert!(parsed_after.verify_hashes());
        assert!(parsed_after.strings.iter().any(|s| s == "verifyV1SigPatched"));

        // 2. Test patch-apk-protection on a decompiled smali directory (matching tests/test_apk_protection.py)
        let smali_dir = tmp.path().join("smali").join("android").join("util").join("apk");
        fs::create_dir_all(&smali_dir).unwrap();
        let smali_file = smali_dir.join("ApkSignatureVerifier.smali");
        let sample_smali = "\
.class public Landroid/util/apk/ApkSignatureVerifier;
.super Ljava/lang/Object;

.method public static getMinimumSignatureSchemeVersionForTargetSdk(I)I
    .locals 1
    const/4 v0, 0x2
    return v0
.end method

.method private static verifySignaturesInternal(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;IZ)Landroid/content/pm/parsing/result/ParseResult;
    .registers 5
    invoke-static {p0, p1, p2}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;I)Landroid/content/pm/parsing/result/ParseResult;
    move-result-object v0
    return-object v0
.end method
";
        fs::write(&smali_file, sample_smali).unwrap();

        let cli_apk_prot = Cli::parse_from([
            "dex-patcher",
            "patch-apk-protection",
            tmp.path().join("smali").to_str().unwrap(),
        ]);
        run_cli(cli_apk_prot).unwrap();

        let patched_smali = fs::read_to_string(&smali_file).unwrap();
        assert!(patched_smali.contains("const/4 v0, 0x1"));
        assert!(patched_smali.contains("const/4 p3, 0x0"));
    }

    /// Convert a synthetic unmapped DEX (from `DexBuilder`) into a strict `map_list`-equipped
    /// DEX matching `dx`/`d8` layout so we can verify `relocate` and `dex_file_verifier` invariants.
    fn attach_map_list(raw_dex: Vec<u8>) -> Vec<u8> {
        let mut dex = DexFile::parse(raw_dex).unwrap();
        let mut map_items = Vec::new();
        map_items.push(relocate::MapItem {
            type_code: relocate::TYPE_HEADER_ITEM,
            unused: 0,
            size: 1,
            offset: 0,
        });
        if dex.header.string_ids_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_STRING_ID_ITEM,
                unused: 0,
                size: dex.header.string_ids_size,
                offset: dex.header.string_ids_off,
            });
        }
        if dex.header.type_ids_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_TYPE_ID_ITEM,
                unused: 0,
                size: dex.header.type_ids_size,
                offset: dex.header.type_ids_off,
            });
        }
        if dex.header.proto_ids_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_PROTO_ID_ITEM,
                unused: 0,
                size: dex.header.proto_ids_size,
                offset: dex.header.proto_ids_off,
            });
        }
        if dex.header.field_ids_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_FIELD_ID_ITEM,
                unused: 0,
                size: dex.header.field_ids_size,
                offset: dex.header.field_ids_off,
            });
        }
        if dex.header.method_ids_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_METHOD_ID_ITEM,
                unused: 0,
                size: dex.header.method_ids_size,
                offset: dex.header.method_ids_off,
            });
        }
        if dex.header.class_defs_size > 0 {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_CLASS_DEF_ITEM,
                unused: 0,
                size: dex.header.class_defs_size,
                offset: dex.header.class_defs_off,
            });
        }

        // Data sections emitted in exact order by `DexBuilder`:
        // 1. TYPE_LIST (unique proto parameters_off > 0)
        let mut type_lists: Vec<u32> = dex
            .protos
            .iter()
            .filter_map(|p| if p.parameters_off != 0 { Some(p.parameters_off) } else { None })
            .collect();
        type_lists.sort_unstable();
        type_lists.dedup();
        if !type_lists.is_empty() {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_TYPE_LIST,
                unused: 0,
                size: type_lists.len() as u32,
                offset: type_lists[0],
            });
        }

        // 2. STRING_DATA_ITEM
        if !dex.string_offsets.is_empty() {
            let first_str = *dex.string_offsets.iter().min().unwrap();
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_STRING_DATA_ITEM,
                unused: 0,
                size: dex.string_offsets.len() as u32,
                offset: first_str,
            });
        }

        // 3. CODE_ITEM & 4. CLASS_DATA_ITEM
        let mut code_offs = Vec::new();
        let mut cd_offs = Vec::new();
        for cd in &dex.class_defs {
            if cd.class_data_off != 0 {
                cd_offs.push(cd.class_data_off);
                let parsed_cd = dex.read_class_data(cd.class_data_off).unwrap();
                for m in parsed_cd
                    .direct_methods
                    .iter()
                    .chain(parsed_cd.virtual_methods.iter())
                {
                    if m.code_off != 0 {
                        code_offs.push(m.code_off);
                    }
                }
            }
        }
        code_offs.sort_unstable();
        code_offs.dedup();
        cd_offs.sort_unstable();
        cd_offs.dedup();
        if !code_offs.is_empty() {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_CODE_ITEM,
                unused: 0,
                size: code_offs.len() as u32,
                offset: code_offs[0],
            });
        }
        if !cd_offs.is_empty() {
            map_items.push(relocate::MapItem {
                type_code: relocate::TYPE_CLASS_DATA_ITEM,
                unused: 0,
                size: cd_offs.len() as u32,
                offset: cd_offs[0],
            });
        }

        while dex.data.len() % 4 != 0 {
            dex.data.push(0);
        }
        let map_off = dex.data.len() as u32;
        map_items.push(relocate::MapItem {
            type_code: relocate::TYPE_MAP_LIST,
            unused: 0,
            size: 1,
            offset: map_off,
        });
        map_items.sort_by_key(|m| m.offset);

        dex.data.extend_from_slice(&(map_items.len() as u32).to_le_bytes());
        for m in &map_items {
            dex.data.extend_from_slice(&m.type_code.to_le_bytes());
            dex.data.extend_from_slice(&m.unused.to_le_bytes());
            dex.data.extend_from_slice(&m.size.to_le_bytes());
            dex.data.extend_from_slice(&m.offset.to_le_bytes());
        }
        crate::dex::write_u32(&mut dex.data, 0x34, map_off);
        dex.header.map_off = map_off;
        dex.update_hashes();
        dex.data
    }

    /// Strict ART-style `DexFileVerifier` check for test assertions.
    fn assert_strict_mapped_dex_valid(raw: &[u8]) {
        let dex = DexFile::parse(raw.to_vec()).expect("DEX parse failed");
        assert!(dex.verify_hashes(), "DEX SHA-1/Adler32 invalid");
        assert_eq!(dex.header.file_size as usize, raw.len(), "file_size mismatch");
        assert_eq!(
            dex.header.data_off + dex.header.data_size,
            dex.header.file_size,
            "data_off + data_size != file_size"
        );
        assert_ne!(dex.header.map_off, 0, "expected map_off != 0");

        // 1. Check strict MUTF-8 ordering of `string_ids`.
        for i in 1..dex.strings.len() {
            let prev = relocate::raw_mutf8_bytes_at(&dex.data, dex.string_offsets[i - 1] as usize)
                .unwrap();
            let cur = relocate::raw_mutf8_bytes_at(&dex.data, dex.string_offsets[i] as usize).unwrap();
            assert!(
                prev < cur,
                "string_ids not strictly sorted at {}: {:?} >= {:?}",
                i,
                dex.strings[i - 1],
                dex.strings[i]
            );
        }

        // 2. Check map_list ordering, alignment, contiguous CODE_ITEM / CLASS_DATA_ITEM / STRING_DATA_ITEM offsets.
        let map_items = relocate::read_map_list(&dex.data, dex.header.map_off as usize).unwrap();
        let mut valid_code_offs = std::collections::HashSet::new();
        let mut valid_cd_offs = std::collections::HashSet::new();
        let mut valid_str_offs = std::collections::HashSet::new();
        for w in map_items.windows(2) {
            assert!(w[0].offset < w[1].offset, "map_list not strictly increasing");
        }
        for mi in &map_items {
            assert_eq!(
                mi.offset as usize % relocate::section_alignment(mi.type_code),
                0,
                "map section 0x{:04x} unaligned at 0x{:x}",
                mi.type_code,
                mi.offset
            );
            match mi.type_code {
                relocate::TYPE_CODE_ITEM => {
                    let mut p = mi.offset as usize;
                    for _ in 0..mi.size {
                        p = relocate::align_up(p, 4);
                        valid_code_offs.insert(p as u32);
                        let len = relocate::code_item_raw_len(&dex.data, p).unwrap();
                        p += len;
                    }
                }
                relocate::TYPE_CLASS_DATA_ITEM => {
                    let mut p = mi.offset as usize;
                    for _ in 0..mi.size {
                        valid_cd_offs.insert(p as u32);
                        let cd = dex.read_class_data(p as u32).unwrap();
                        p += DexFile::encode_class_data(&cd).len();
                    }
                }
                relocate::TYPE_STRING_DATA_ITEM => {
                    let mut p = mi.offset as usize;
                    for _ in 0..mi.size {
                        valid_str_offs.insert(p as u32);
                        p += crate::dex::encoded_string_item_len(&dex.data, p).unwrap();
                    }
                }
                _ => {}
            }
        }
        for &s_off in &dex.string_offsets {
            assert!(
                valid_str_offs.contains(&s_off),
                "string_data_off 0x{:x} not registered in TYPE_STRING_DATA_ITEM section",
                s_off
            );
        }
        for cd in &dex.class_defs {
            if cd.class_data_off != 0 {
                assert!(
                    valid_cd_offs.contains(&cd.class_data_off),
                    "class_data_off 0x{:x} missing from TYPE_CLASS_DATA_ITEM",
                    cd.class_data_off
                );
                let parsed_cd = dex.read_class_data(cd.class_data_off).unwrap();
                for m in parsed_cd
                    .direct_methods
                    .iter()
                    .chain(parsed_cd.virtual_methods.iter())
                {
                    if m.code_off != 0 {
                        assert!(
                            valid_code_offs.contains(&m.code_off),
                            "method {} code_off 0x{:x} missing from TYPE_CODE_ITEM",
                            m.method_idx,
                            m.code_off
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_replace_sget_inserts_sorted_string_without_corrupting_model() {
        let mut b = DexBuilder::new();
        b.add_class("Lcom/heytap/SpeechHelper;", "Ljava/lang/Object;");
        b.add_field_ref("Landroid/os/Build;", "MODEL", "Ljava/lang/String;");
        b.add_method_ref(
            "Landroid/os/Build;",
            "getModelName",
            &[],
            "Ljava/lang/String;",
        );
        let tmp = DexFile::parse(b.build()).unwrap();
        let model_f_idx = (0..tmp.fields.len())
            .find(|&i| {
                tmp.get_field_signature(i as u32)
                    .map(|(_, n, _)| n == "MODEL")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        b.add_method(MethodSpec {
            class_desc: "Lcom/heytap/SpeechHelper;".to_string(),
            name: "readModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0062, model_f_idx, 0x0011], // sget-object v0, Build->MODEL; return-object v0
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mapped_raw = attach_map_list(b.build());
        let mut dex = DexFile::parse(mapped_raw).unwrap();
        assert_strict_mapped_dex_valid(&dex.data);

        let count = replace_sget_with_const_string(
            &mut dex,
            "Landroid/os/Build;",
            "MODEL",
            "PLG110",
            None,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_strict_mapped_dex_valid(&dex.data);

        // Verify "MODEL" is STILL in strings AND Build->MODEL field still resolves to "MODEL"
        assert!(dex.strings.iter().any(|s| s == "MODEL"), "MODEL string must remain intact");
        assert!(dex.strings.iter().any(|s| s == "PLG110"), "PLG110 must be inserted");
        let (_, f_name, _) = dex.get_field_signature(model_f_idx as u32).unwrap();
        assert_eq!(f_name, "MODEL");

        // Verify readModel bytecode now loads "PLG110"
        let plg_idx = dex.strings.iter().position(|s| s == "PLG110").unwrap() as u16;
        let cd = dex.read_class_data(dex.class_defs[0].class_data_off).unwrap();
        let code = dex.read_code_item(cd.direct_methods[0].code_off).unwrap();
        assert_eq!(code.insns, vec![0x001a, plg_idx, 0x0011]);
    }

    #[test]
    fn test_hook_after_string_oppo_gallery_and_idempotency() {
        let mut b = DexBuilder::new();
        let cls = "Lcom/coloros/gallery/ApiLevelHelper;";
        b.add_class(cls, "Ljava/lang/Object;");
        b.add_string("ro.product.first_api_level");
        b.add_method_ref("Landroid/os/SystemProperties;", "getInt", &["Ljava/lang/String;", "I"], "I");
        let mut tmp_b = b.clone();
        tmp_b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "getFirstApiLevel".to_string(),
            params: vec![],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 2,
            ins_size: 0,
            outs_size: 2,
            insns: vec![0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let tmp = DexFile::parse(tmp_b.build()).unwrap();
        let key_idx = tmp
            .strings
            .iter()
            .position(|s| s == "ro.product.first_api_level")
            .unwrap() as u16;
        let get_int_idx = (0..tmp.methods.len())
            .find(|&i| {
                tmp.get_method_signature(i as u32)
                    .map(|(_, n, _)| n == "getInt")
                    .unwrap_or(false)
            })
            .unwrap() as u16;

        // PC 0: const-string v0, "ro.product.first_api_level" (2)
        // PC 2: const/4 v1, 0x0 (1)
        // PC 3: invoke-static {v0, v1}, getInt (3)
        // PC 6: move-result v0 (1)
        // PC 7: if-eqz v0, +3 (2) -> target PC 10 (return v0)
        // PC 9: const/4 v0, 0x1 (1)
        // PC 10: return v0 (1)
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "getFirstApiLevel".to_string(),
            params: vec![],
            return_type: "I".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 2,
            ins_size: 0,
            outs_size: 2,
            insns: vec![
                0x001a, key_idx,
                0x0112,
                0x2071, get_int_idx, 0x0010,
                0x000a,
                0x0038, 0x0003,
                0x1012,
                0x000f,
            ],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mut dex = DexFile::parse(attach_map_list(b.build())).unwrap();
        let n = hook_move_result_after_string(
            &mut dex,
            r#"const-string.*"ro.product.first_api_level""#,
            0x22,
            None,
            None,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_strict_mapped_dex_valid(&dex.data);

        let cd = dex.read_class_data(dex.class_defs[0].class_data_off).unwrap();
        let code = dex.read_code_item(cd.direct_methods[0].code_off).unwrap();
        // move-result v0 (1 unit) became const/16 v0, 0x22 (2 units); if-eqz moved from PC 7 -> PC 8
        // and its relative offset stayed +3 (pointing to PC 11 return v0)!
        assert_eq!(code.insns[6], 0x0013);
        assert_eq!(code.insns[7], 0x0022);
        assert_eq!(code.insns[8], 0x0038);
        assert_eq!(code.insns[9], 3);

        // Second run must be an idempotent no-op
        let n2 = hook_move_result_after_string(&mut dex, "ro.product.first_api_level", 0x22, None, None)
            .unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_stub_require_and_aod_gate_optional() {
        let tmp = TempDir::new().unwrap();
        let dex_path = tmp.path().join("classes.dex");
        fs::write(&dex_path, attach_map_list(build_sample_dex())).unwrap();

        // --require fails when method does not exist
        let missing_cli = Cli::parse_from([
            "dex-patcher",
            "stub-method",
            "--file",
            dex_path.to_str().unwrap(),
            "--class",
            "OplusEngineerFwService",
            "--method",
            "onBootPhase(I)V",
            "--return-void",
            "--require",
        ]);
        assert!(run_cli(missing_cli).is_err());

        // Without --require it succeeds with 0 patched
        let optional_stub = Cli::parse_from([
            "dex-patcher",
            "stub-method",
            "--file",
            dex_path.to_str().unwrap(),
            "--class",
            "OplusBgSceneManager",
            "--method",
            "isGmsRestricted",
            "--return",
            "false",
        ]);
        run_cli(optional_stub).unwrap();

        // patch-inspiration-aod-gate fails without --optional, succeeds with --optional
        let gate_req = Cli::parse_from([
            "dex-patcher",
            "patch-inspiration-aod-gate",
            "--file",
            dex_path.to_str().unwrap(),
        ]);
        assert!(run_cli(gate_req).is_err());

        let gate_opt = Cli::parse_from([
            "dex-patcher",
            "patch-inspiration-aod-gate",
            "--file",
            dex_path.to_str().unwrap(),
            "--optional",
        ]);
        run_cli(gate_opt).unwrap();
    }

    #[test]
    fn test_deduplicated_code_off_and_switch_payload_alignment() {
        // 1. Test deduplicated code_off: two methods sharing one code_item in a mapped DEX
        let mut b = DexBuilder::new();
        let cls = "Lcom/android/systemui/Option;";
        b.add_class(cls, "Ljava/lang/Object;");
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "flagA".to_string(),
            params: vec![],
            return_type: "Z".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x1012, 0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        b.add_method(MethodSpec {
            class_desc: cls.to_string(),
            name: "flagB".to_string(),
            params: vec![],
            return_type: "Z".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x1012, 0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let raw_mapped = attach_map_list(b.build());
        // Force both methods in ClassData to point to flagA's code_off, mimicking r8 deduplication
        let mut dex = DexFile::parse(raw_mapped).unwrap();
        let cd_off = dex.class_defs[0].class_data_off;
        let mut cd = dex.read_class_data(cd_off).unwrap();
        let shared_code_off = cd.direct_methods[0].code_off;
        cd.direct_methods[1].code_off = shared_code_off;
        // Write patched ClassData inside new attach_map_list style
        let encoded_cd = DexFile::encode_class_data(&cd);
        dex.data[cd_off as usize..cd_off as usize + encoded_cd.len()].copy_from_slice(&encoded_cd);
        // Update map_list CODE_ITEM size to 1 so strict verifier sees 1 shared item
        let mut mi = relocate::read_map_list(&dex.data, dex.header.map_off as usize).unwrap();
        for m in &mut mi {
            if m.type_code == relocate::TYPE_CODE_ITEM {
                m.size = 1;
            }
        }
        let mp = dex.header.map_off as usize;
        for (i, m) in mi.iter().enumerate() {
            crate::dex::write_u32(&mut dex.data, mp + 4 + i * 12 + 4, m.size);
        }
        dex.update_hashes();

        // Stub ONLY flagA -> False; flagB must stay True (`0x1012, 0x000f`)!
        let patched = stub_method(&mut dex, Some(cls), "flagA", None, ReturnSpec::False).unwrap();
        assert_eq!(patched, 1);
        assert_strict_mapped_dex_valid(&dex.data);

        let cd_after = dex.read_class_data(dex.class_defs[0].class_data_off).unwrap();
        let m0_code = dex.read_code_item(cd_after.direct_methods[0].code_off).unwrap();
        let m1_code = dex.read_code_item(cd_after.direct_methods[1].code_off).unwrap();
        assert_eq!(m0_code.insns, vec![0x0012, 0x000f], "flagA must return false");
        assert_eq!(m1_code.insns, vec![0x1012, 0x000f], "flagB must remain true");

        // 2. Test packed-switch payload stays even-aligned after odd instruction insertion
        // PC 0: const/4 v0, 0x0 (1)
        // PC 1: packed-switch v0, +5 (3) -> payload at PC 6 (EVEN!)
        // PC 4: return-void (1)
        // PC 5: return-void (1)
        // PC 6: packed-switch-payload size=1, first_key=0, target=+3 (PC 1 + 3 = PC 4)
        let mut ci = CodeItem {
            offset: 0,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            tries_size: 0,
            debug_info_off: 0,
            insns: vec![
                0x0012,
                0x002b, 0x0005, 0x0000,
                0x000e,
                0x000e,
                0x0100, 0x0001, 0x0000, 0x0000, 0x0003, 0x0000,
            ],
            tries_and_handlers: Vec::new(),
        };
        insert_insns_at(&mut ci, 1, &[0x1012]).unwrap(); // insert 1 unit before packed-switch
        // Find packed-switch at PC 2, read its payload offset
        assert_eq!(ci.insns[2] & 0xff, 0x2b);
        let rel = ((ci.insns[3] as u32) | ((ci.insns[4] as u32) << 16)) as i32;
        let payload_pc = (2isize + rel as isize) as usize;
        assert_eq!(payload_pc % 2, 0, "switch payload PC {} must remain 4-byte aligned (even)", payload_pc);
        assert_eq!(ci.insns[payload_pc], 0x0100);
    }

    #[test]
    fn test_batch_cli_apk_container() {
        let mut b = DexBuilder::new();
        b.add_class("Lcom/heytap/AiCallCommonBean;", "Ljava/lang/Object;");
        b.add_field_ref("Landroid/os/Build;", "MODEL", "Ljava/lang/String;");
        b.add_method(MethodSpec {
            class_desc: "Lcom/heytap/AiCallCommonBean;".to_string(),
            name: "getSupportAiCall".to_string(),
            params: vec![],
            return_type: "Z".to_string(),
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            insns: vec![0x0012, 0x000f],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });
        let tmp_dex = DexFile::parse(b.build()).unwrap();
        let f_idx = (0..tmp_dex.fields.len())
            .find(|&i| {
                tmp_dex
                    .get_field_signature(i as u32)
                    .map(|(_, n, _)| n == "MODEL")
                    .unwrap_or(false)
            })
            .unwrap() as u16;
        b.add_method(MethodSpec {
            class_desc: "Lcom/heytap/AiCallCommonBean;".to_string(),
            name: "getDeviceModel".to_string(),
            params: vec![],
            return_type: "Ljava/lang/String;".to_string(),
            access_flags: 0x0001 | ACC_STATIC,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x0062, f_idx, 0x0011],
            tries_size: 0,
            tries_and_handlers: Vec::new(),
        });

        let mapped_dex = attach_map_list(b.build());
        let tmp = TempDir::new().unwrap();
        let apk_path = tmp.path().join("HeyTapSpeechAssist.apk");
        let mut zip_buf = Vec::new();
        {
            let mut zw = ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("classes.dex", stored).unwrap();
            zw.write_all(&mapped_dex).unwrap();
            zw.start_file("AndroidManifest.xml", stored).unwrap();
            zw.write_all(b"manifest").unwrap();
            zw.finish().unwrap();
        }
        fs::write(&apk_path, &zip_buf).unwrap();

        let cli = Cli::parse_from([
            "dex-patcher",
            "batch",
            "--file",
            apk_path.to_str().unwrap(),
            "--require-stub",
            "AiCallCommonBean::getSupportAiCall=true",
            "--replace-sget",
            "Landroid/os/Build;->MODEL=PLG110",
        ]);
        run_cli(cli).unwrap();

        let updated_zip = fs::read(&apk_path).unwrap();
        verify_zip_alignment_4(&updated_zip).unwrap();

        let mut za = zip::ZipArchive::new(std::io::Cursor::new(updated_zip)).unwrap();
        let mut dex_entry = Vec::new();
        std::io::Read::read_to_end(&mut za.by_name("classes.dex").unwrap(), &mut dex_entry).unwrap();
        assert_strict_mapped_dex_valid(&dex_entry);
    }

    #[test]
    fn test_fix_arsc_cli_apk_container_and_alignment() {
        // Construct a synthetic ARSC with 1 bad 0x0196 attribute
        let header_size_type = 28usize;
        let entry_count = 1usize;
        let entries_start = header_size_type + entry_count * 4;
        let entry0_data = [
            0x00, 0x00, // flags = simple (0)
            0x00, 0x00, // key index
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, // size = 8
            0x00,       // res0
            0x02,       // dataType = TYPE_ATTRIBUTE (0x02)
            0x18, 0x00, 0x96, 0x01, // data = 0x01960018
        ];
        let type_chunk_size = (entries_start + entry0_data.len()) as u32;
        let mut type_chunk = Vec::new();
        type_chunk.extend_from_slice(&0x0201u16.to_le_bytes());
        type_chunk.extend_from_slice(&(header_size_type as u16).to_le_bytes());
        type_chunk.extend_from_slice(&type_chunk_size.to_le_bytes());
        type_chunk.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
        type_chunk.extend_from_slice(&(entry_count as u32).to_le_bytes());
        type_chunk.extend_from_slice(&(entries_start as u32).to_le_bytes());
        type_chunk.extend_from_slice(&[0u8; 8]);
        type_chunk.extend_from_slice(&0u32.to_le_bytes());
        type_chunk.extend_from_slice(&entry0_data);

        let pkg_header_size = 16usize;
        let pkg_chunk_size = (pkg_header_size + type_chunk.len()) as u32;
        let mut pkg_chunk = Vec::new();
        pkg_chunk.extend_from_slice(&0x0200u16.to_le_bytes());
        pkg_chunk.extend_from_slice(&(pkg_header_size as u16).to_le_bytes());
        pkg_chunk.extend_from_slice(&pkg_chunk_size.to_le_bytes());
        pkg_chunk.extend_from_slice(&[0u8; 8]);
        pkg_chunk.extend_from_slice(&type_chunk);

        let table_header_size = 12usize;
        let table_chunk_size = (table_header_size + pkg_chunk.len()) as u32;
        let mut table = Vec::new();
        table.extend_from_slice(&0x0002u16.to_le_bytes());
        table.extend_from_slice(&(table_header_size as u16).to_le_bytes());
        table.extend_from_slice(&table_chunk_size.to_le_bytes());
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(&pkg_chunk);

        let tmp = TempDir::new().unwrap();
        let apk_path = tmp.path().join("SystemUI_test.apk");
        let mut zip_buf = Vec::new();
        {
            let mut zw = ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zw.start_file("resources.arsc", stored).unwrap();
            zw.write_all(&table).unwrap();
            zw.finish().unwrap();
        }
        fs::write(&apk_path, &zip_buf).unwrap();

        // Run fix-arsc CLI
        let cli = Cli::parse_from([
            "dex-patcher",
            "fix-arsc",
            "--file",
            apk_path.to_str().unwrap(),
            "--require",
        ]);
        run_cli(cli).unwrap();

        let updated_zip = fs::read(&apk_path).unwrap();
        verify_zip_alignment_4(&updated_zip).unwrap();

        let mut za = zip::ZipArchive::new(std::io::Cursor::new(updated_zip)).unwrap();
        let mut arsc_entry = Vec::new();
        std::io::Read::read_to_end(&mut za.by_name("resources.arsc").unwrap(), &mut arsc_entry).unwrap();

        // Check that dataType is now TYPE_REFERENCE (0x01)
        let ep0 = table_header_size + pkg_header_size + entries_start;
        assert_eq!(arsc_entry[ep0 + 11], 0x01);
    }
}
