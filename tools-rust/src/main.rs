//! Unified binary dispatcher (`coloros-tools`) for all 4 stages.
//!
//! Supports both explicit subcommands (`coloros-tools <stage> ...`) and BusyBox-style
//! multicall `argv[0]` invocation (e.g. symlinked as `rom-fs-patcher`, `dex-patcher`,
//! `smali-patcher`, `prop-tool`, `smalikit`, `patchmethod_v2`, `patchmethod`,
//! `contextpatch`, or `fspatch`).

use std::ffi::OsString;
use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "coloros-tools",
    version,
    about = "Unified high-performance Rust toolset for ColorOS/OxygenOS ROM porting"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Stage 1: SELinux file_contexts and fs_config patcher
    #[command(visible_aliases = ["rom-fs-patcher", "fspatcher"])]
    FsPatcher(rom_fs_patcher::Cli),
    /// Stage 2: Direct DEX bytecode & APK/JAR patcher
    #[command(visible_aliases = ["dexpatcher"])]
    DexPatcher(dex_patcher::Cli),
    /// Stage 3: Parallel Regex Engine for Smali
    #[command(visible_aliases = ["smalipatcher", "smalikit"])]
    SmaliPatcher(smali_patcher::Cli),
    /// Stage 4: Batch build.prop and fstab processor
    #[command(visible_aliases = ["proptool"])]
    PropTool(prop_tool::Cli),
    /// Stage 5: Batch XML feature and config processor
    #[command(visible_aliases = ["xmltool"])]
    XmlTool(xml_tool::Cli),
    /// Stage 6: Native ROM ops (tree-size, debloat, patch-vbmeta, strip-non-ascii)
    #[command(visible_aliases = ["romops"])]
    RomOps(rom_ops::Cli),
}

/// Dispatch CLI invocation from an arbitrary argument iterator (`argv[0..n]`).
pub fn run_from_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args_vec: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if let Some(argv0) = args_vec.first() {
        let stem = Path::new(argv0)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        match stem {
            "rom-fs-patcher" | "fs-patcher" | "fspatcher" => {
                let sub = rom_fs_patcher::Cli::try_parse_from(&args_vec)?;
                return rom_fs_patcher::run_cli(sub);
            }
            "contextpatch" => {
                let mut forwarded = Vec::with_capacity(args_vec.len() + 1);
                forwarded.push(OsString::from("rom-fs-patcher"));
                forwarded.push(OsString::from("context-patch"));
                forwarded.extend_from_slice(&args_vec[1..]);
                let sub = rom_fs_patcher::Cli::try_parse_from(forwarded)?;
                return rom_fs_patcher::run_cli(sub);
            }
            "fspatch" => {
                let mut forwarded = Vec::with_capacity(args_vec.len() + 1);
                forwarded.push(OsString::from("rom-fs-patcher"));
                forwarded.push(OsString::from("fs-patch"));
                forwarded.extend_from_slice(&args_vec[1..]);
                let sub = rom_fs_patcher::Cli::try_parse_from(forwarded)?;
                return rom_fs_patcher::run_cli(sub);
            }
            "dex-patcher" | "dexpatcher" => {
                let sub = dex_patcher::Cli::try_parse_from(&args_vec)?;
                return dex_patcher::run_cli(sub);
            }
            "smali-patcher" | "smalipatcher" => {
                let sub = smali_patcher::Cli::try_parse_from(&args_vec)?;
                return smali_patcher::run_cli(sub);
            }
            "smalikit" => {
                let mut forwarded = Vec::with_capacity(args_vec.len() + 1);
                forwarded.push(OsString::from("smali-patcher"));
                forwarded.push(OsString::from("smalikit"));
                forwarded.extend_from_slice(&args_vec[1..]);
                let sub = smali_patcher::Cli::try_parse_from(forwarded)?;
                return smali_patcher::run_cli(sub);
            }
            "patchmethod_v2" => {
                let mut forwarded = Vec::with_capacity(args_vec.len() + 1);
                forwarded.push(OsString::from("smali-patcher"));
                forwarded.push(OsString::from("patchmethod_v2"));
                forwarded.extend_from_slice(&args_vec[1..]);
                let sub = smali_patcher::Cli::try_parse_from(forwarded)?;
                return smali_patcher::run_cli(sub);
            }
            "patchmethod" => {
                let mut forwarded = Vec::with_capacity(args_vec.len() + 1);
                forwarded.push(OsString::from("smali-patcher"));
                forwarded.push(OsString::from("patchmethod"));
                forwarded.extend_from_slice(&args_vec[1..]);
                let sub = smali_patcher::Cli::try_parse_from(forwarded)?;
                return smali_patcher::run_cli(sub);
            }
            "prop-tool" | "proptool" => {
                let sub = prop_tool::Cli::try_parse_from(&args_vec)?;
                return prop_tool::run_cli(sub);
            }
            "xml-tool" | "xmltool" => {
                let sub = xml_tool::Cli::try_parse_from(&args_vec)?;
                return xml_tool::run_cli(sub);
            }
            "rom-ops" | "romops" => {
                let sub = rom_ops::Cli::try_parse_from(&args_vec)?;
                return rom_ops::run_cli(sub);
            }
            _ => {}
        }
    }

    let cli = Cli::try_parse_from(args_vec)?;
    match cli.command {
        Commands::FsPatcher(sub) => rom_fs_patcher::run_cli(sub),
        Commands::DexPatcher(sub) => dex_patcher::run_cli(sub),
        Commands::SmaliPatcher(sub) => smali_patcher::run_cli(sub),
        Commands::PropTool(sub) => prop_tool::run_cli(sub),
        Commands::XmlTool(sub) => xml_tool::run_cli(sub),
        Commands::RomOps(sub) => rom_ops::run_cli(sub),
    }
}

fn main() -> Result<()> {
    if let Err(err) = run_from_args(std::env::args_os()) {
        if let Some(clap_err) = err.downcast_ref::<clap::Error>() {
            clap_err.exit();
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_dispatcher_fs_patcher_and_multicall() {
        let dir = tempdir().unwrap();
        let part_dir = dir.path().join("system");
        fs::create_dir_all(part_dir.join("bin")).unwrap();
        fs::write(part_dir.join("bin/init"), b"#!/bin/sh\n").unwrap();

        let fs_config = dir.path().join("system_fs_config");
        let file_contexts = dir.path().join("system_file_contexts");
        fs::write(&fs_config, "/ 0 0 0755\nsystem/bin 0 2000 0755\n").unwrap();
        fs::write(
            &file_contexts,
            "/ u:object_r:rootfs:s0\n/system/bin/sh u:object_r:shell_exec:s0\n",
        )
        .unwrap();

        run_from_args([
            "coloros-tools",
            "fs-patcher",
            "patch-all",
            part_dir.to_str().unwrap(),
            fs_config.to_str().unwrap(),
            file_contexts.to_str().unwrap(),
        ])
        .unwrap();

        let fc_out = fs::read_to_string(&file_contexts).unwrap();
        assert!(fc_out.contains("/system/bin/init u:object_r:shell_exec:s0"));
    }

    #[test]
    fn test_dispatcher_smali_patcher_and_multicall() {
        let dir = tempdir().unwrap();
        let smali_file = dir.path().join("Test.smali");
        fs::write(
            &smali_file,
            concat!(
                ".class public Lcom/example/Test;\n",
                ".super Ljava/lang/Object;\n",
                ".method public isRestricted()Z\n",
                "    .locals 1\n",
                "    const/4 v0, 0x1\n",
                "    return v0\n",
                ".end method\n"
            ),
        )
        .unwrap();

        run_from_args([
            "coloros-tools",
            "smali-patcher",
            "patchmethod",
            smali_file.to_str().unwrap(),
            "-isRestricted",
        ])
        .unwrap();

        let patched = fs::read_to_string(&smali_file).unwrap();
        assert!(patched.contains("const/4 v0, 0x0"));

        // Also test multicall argv[0] = smalikit
        run_from_args([
            "smalikit",
            "-p",
            smali_file.to_str().unwrap(),
            "-m",
            "isRestricted()Z",
            "-remake",
            ".locals 1\nconst/4 v0, 0x1\nreturn v0",
        ])
        .unwrap();

        let patched2 = fs::read_to_string(&smali_file).unwrap();
        assert!(patched2.contains("const/4 v0, 0x1"));
    }

    #[test]
    fn test_dispatcher_prop_tool() {
        let dir = tempdir().unwrap();
        let prop_file = dir.path().join("build.prop");
        fs::write(
            &prop_file,
            "ro.build.type=user\nro.debuggable=0\npersist.old.key=1\n",
        )
        .unwrap();

        run_from_args([
            "coloros-tools",
            "prop-tool",
            "batch",
            "--file",
            prop_file.to_str().unwrap(),
            "--set",
            "ro.debuggable=1",
            "--remove",
            "persist.old.key",
        ])
        .unwrap();

        let content = fs::read_to_string(&prop_file).unwrap();
        assert!(content.contains("ro.debuggable=1"));
        assert!(!content.contains("persist.old.key"));
    }

    #[test]
    fn test_help_error_is_clap_display_help() {
        let err = run_from_args(["coloros-tools", "dex-patcher", "--help"]).unwrap_err();
        let clap_err = err.downcast_ref::<clap::Error>().unwrap();
        assert_eq!(clap_err.kind(), clap::error::ErrorKind::DisplayHelp);

        let err2 = run_from_args(["dex-patcher", "--help"]).unwrap_err();
        let clap_err2 = err2.downcast_ref::<clap::Error>().unwrap();
        assert_eq!(clap_err2.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_dispatcher_xml_tool_and_rom_ops_multicall() {
        let dir = tempdir().unwrap();
        let port_etc = dir.path().join("my_product/etc");
        fs::create_dir_all(&port_etc).unwrap();

        run_from_args([
            "coloros-tools",
            "xml-tool",
            "add-features",
            "--port-dir",
            port_etc.to_str().unwrap(),
            "--type",
            "oplus_feature",
            "oplus.software.test^test_comment",
        ])
        .unwrap();

        let ext_xml = fs::read_to_string(
            port_etc.join("extension/com.oplus.oplus-feature-ext-bruce.xml"),
        )
        .unwrap();
        assert!(ext_xml.contains("oplus.software.test"));

        // Multicall xml-tool
        run_from_args([
            "xml-tool",
            "remove-features",
            "--port-dir",
            port_etc.to_str().unwrap(),
            "--force",
            "oplus.software.test",
        ])
        .unwrap();
        let ext_xml_after = fs::read_to_string(
            port_etc.join("extension/com.oplus.oplus-feature-ext-bruce.xml"),
        )
        .unwrap();
        assert!(!ext_xml_after.contains("oplus.software.test"));

        // Subcommand & multicall rom-ops
        let fc = dir.path().join("test_file_contexts");
        fs::write(&fc, "/a u:object_r:a:s0\n/中文 u:object_r:b:s0\n").unwrap();
        run_from_args([
            "rom-ops",
            "strip-non-ascii",
            fc.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(fs::read_to_string(&fc).unwrap(), "/a u:object_r:a:s0\n");

        run_from_args(["coloros-tools", "rom-ops", "tree-size", dir.path().to_str().unwrap()])
            .unwrap();
    }
}
