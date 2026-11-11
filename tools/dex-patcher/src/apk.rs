use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::dex::{patch_dex_bytes, PatchResult, ReturnType};

pub fn patch_archive(
    in_path: &Path,
    out_path: &Path,
    class_pattern: &str,
    target_method: &str,
    ret: ReturnType,
) -> Result<Vec<PatchResult>, Box<dyn std::error::Error>> {
    let in_file = File::open(in_path)?;
    let mut zip_in = ZipArchive::new(in_file)?;

    let out_file = File::create(out_path)?;
    let mut zip_out = ZipWriter::new(out_file);

    let mut all_results = Vec::new();

    for i in 0..zip_in.len() {
        let mut entry = zip_in.by_index(i)?;
        let name = entry.name()?.to_string();
        let compression = entry.compression();

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;

        if name.ends_with(".dex") {
            let res = patch_dex_bytes(&mut data, class_pattern, target_method, ret);
            if !res.is_empty() {
                println!("[+] Patched in {}:", name);
                for r in &res {
                    println!("    {}::{} -> {:?}", r.class_name, r.method_name, r.return_type);
                }
                all_results.extend(res);
            }
        }

        let options = SimpleFileOptions::default()
            .compression_method(compression)
            .unix_permissions(entry.unix_mode().unwrap_or(0o644));

        zip_out.start_file(name, options)?;
        zip_out.write_all(&data)?;
    }

    zip_out.finish()?;
    Ok(all_results)
}
