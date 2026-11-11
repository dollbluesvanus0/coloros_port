use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

mod apk;
mod dex;

use dex::ReturnType;

fn print_usage() {
    eprintln!("DEX / APK / JAR In-place Method Patcher (ColorOS Port Tools in Rust)");
    eprintln!("Usage: dex_patcher <input_file> <class_pattern> <method_name> <void|true|false> [output_file]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  dex_patcher SystemUI.apk DefaultSettingsPopupMenuSection addViews void");
    eprintln!("  dex_patcher services.jar ScanPackageUtils assertMinSignatureSchemeIsValid void");
    eprintln!("  dex_patcher classes2.dex SmoothTransitionController isSupportMyDevice true");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        print_usage();
        std::process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);
    let class_pattern = &args[2];
    let method_name = &args[3];
    let ret_str = &args[4];

    let ret = match ReturnType::from_str(ret_str) {
        Some(r) => r,
        None => {
            eprintln!("Invalid return type '{}'. Valid values: void, true, false", ret_str);
            std::process::exit(1);
        }
    };

    let (out_path, in_place) = if args.len() >= 6 {
        (PathBuf::from(&args[5]), false)
    } else {
        let temp_out = input_path.with_extension(format!("{}.patched", input_path.extension().unwrap_or_default().to_str().unwrap_or("tmp")));
        (temp_out, true)
    };

    println!("[*] Input: {}", input_path.display());
    println!("[*] Target: {}::{} -> {:?}", class_pattern, method_name, ret);
    println!("[*] Output: {}", out_path.display());

    let start = Instant::now();

    let ext = input_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let patched_count = if ext == "apk" || ext == "jar" || ext == "zip" {
        let results = apk::patch_archive(&input_path, &out_path, class_pattern, method_name, ret)?;
        results.len()
    } else {
        // Direct DEX file
        let mut data = fs::read(&input_path)?;
        let results = dex::patch_dex_bytes(&mut data, class_pattern, method_name, ret);
        if !results.is_empty() {
            fs::write(&out_path, &data)?;
        }
        results.len()
    };

    let elapsed = start.elapsed();

    if patched_count == 0 {
        eprintln!("[!] Warning: Method {}::{} not found in {}", class_pattern, method_name, input_path.display());
        if in_place && out_path.exists() {
            let _ = fs::remove_file(&out_path);
        }
        std::process::exit(2);
    }

    if in_place {
        fs::rename(&out_path, &input_path)?;
        println!("[+] Successfully patched {} in-place! Time: {:?}", input_path.display(), elapsed);
    } else {
        println!("[+] Successfully created {}! Time: {:?}", out_path.display(), elapsed);
    }

    Ok(())
}
