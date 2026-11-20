//! Parallel Android A/B OTA `CrAU` v2 `payload.bin` generator, RSA signer, verifier, and OTA ZIP packager.
//!
//! Uses `memmap2` zero-copy reads and `rayon` chunk-level parallelism across 2 MiB chunks
//! while streaming operation blobs to keep memory usage bounded even on multi-GB ROM images.

pub mod crypto;
pub mod proto;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use bzip2::read::{BzDecoder, BzEncoder};
use bzip2::Compression as BzCompression;
use clap::{Parser, Subcommand, ValueEnum};
use coloros_common::read_text_lossy;
use lzma_rust2::{CheckType, XzOptions, XzReader, XzWriter};
use memmap2::Mmap;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::crypto::{base64_encode, sha256_bytes, RsaPrivateKey, RsaPublicKey};
use crate::proto::{
    extract_raw_apex_infos, DeltaArchiveManifest, DynamicPartitionGroup, DynamicPartitionMetadata,
    Extent, InstallOperation, OperationType, PartitionInfo, PartitionUpdate, Signature, Signatures,
};

pub const CRAU_MAGIC: &[u8; 4] = b"CrAU";
pub const DEFAULT_MAJOR_VERSION: u64 = 2;
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

#[derive(Debug, Parser)]
#[command(
    name = "payload-gen",
    about = "Fast parallel Android A/B OTA CrAU v2 payload.bin generator, signer, and OTA packager"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompressionMode {
    /// XZ/LZMA2 preset 1 with CRC32 (3-6x faster than standard preset 6)
    #[value(name = "fast-xz")]
    FastXz,
    /// Standard XZ/LZMA2 preset 6 with CRC32
    #[value(name = "xz")]
    Xz,
    /// Bzip2 (`REPLACE_BZ`)
    #[value(name = "bz2")]
    Bz2,
    /// Uncompressed (`REPLACE` + `ZERO`)
    #[value(name = "none")]
    None,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Generate an Android A/B OTA `CrAU` v2 `payload.bin` (and optional properties + OTA ZIP)
    Generate {
        /// Directory containing `<partition>.img` files
        #[arg(long)]
        images_dir: PathBuf,

        /// Comma- or space-separated partition names (e.g. `system,vendor,boot`)
        #[arg(long)]
        partitions: Option<String>,

        /// Partition name (repeatable; alternative to `--partitions`)
        #[arg(long = "partition")]
        partition_list: Vec<String>,

        /// Path to `META/ab_partitions.txt` listing partition names (one per line)
        #[arg(long)]
        ab_partitions_file: Option<PathBuf>,

        /// Output `payload.bin` path
        #[arg(long, visible_alias = "output")]
        out_file: PathBuf,

        /// Optional output `payload_properties.txt` path
        #[arg(long, visible_alias = "properties-file")]
        properties_out: Option<PathBuf>,

        /// Optional `META/dynamic_partitions_info.txt` path
        #[arg(long)]
        dynamic_partitions_info: Option<PathBuf>,

        /// Optional `apex_info.pb` path
        #[arg(long)]
        apex_info: Option<PathBuf>,

        /// Optional RSA private key (PKCS#1 PEM `.key` or PKCS#8 DER/PEM `.pk8`) for payload signing
        #[arg(long)]
        private_key: Option<PathBuf>,

        /// Signature byte size when signing (default: key modulus size, e.g. 256 for RSA-2048)
        #[arg(long)]
        signature_size: Option<usize>,

        /// Chunk compression mode
        #[arg(long, value_enum, default_value_t = CompressionMode::FastXz)]
        compression: CompressionMode,

        /// Payload format major version
        #[arg(long, default_value_t = DEFAULT_MAJOR_VERSION)]
        major_version: u64,

        /// Optional payload minor version (e.g. `0` for full OTA)
        #[arg(long)]
        minor_version: Option<u32>,

        /// Uncompressed chunk size in bytes (must be a non-zero multiple of `--block-size`)
        #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
        chunk_size: usize,

        /// Filesystem block size in bytes
        #[arg(long, default_value_t = DEFAULT_BLOCK_SIZE)]
        block_size: u32,

        /// Optional max timestamp (`int64` Unix epoch)
        #[arg(long)]
        max_timestamp: Option<i64>,

        /// Optional security patch level (e.g. `2026-04-05`)
        #[arg(long)]
        security_patch_level: Option<String>,

        /// Optional Rayon thread pool size override (otherwise uses `RAYON_NUM_THREADS` / all CPUs)
        #[arg(long)]
        threads: Option<usize>,

        /// Optional path to directly package an uncompressed (`ZIP_STORED`) OTA ZIP
        #[arg(long)]
        ota_zip: Option<PathBuf>,

        /// Optional `META-INF/com/android/metadata` file to include in `--ota-zip`
        #[arg(long)]
        metadata_file: Option<PathBuf>,

        /// Optional `care_map.pb` file to include in `--ota-zip`
        #[arg(long)]
        care_map: Option<PathBuf>,

        /// Extra ZIP entries `<ZIP_PATH=LOCAL_PATH>` to include in `--ota-zip`
        #[arg(long = "extra-entry")]
        extra_entries: Vec<String>,
    },

    /// Package `payload.bin`, `payload_properties.txt`, and metadata into an uncompressed (`ZIP_STORED`) OTA ZIP
    PackageOta {
        /// Path to `payload.bin`
        #[arg(long)]
        payload: PathBuf,

        /// Path to `payload_properties.txt`
        #[arg(long)]
        properties: PathBuf,

        /// Optional `META-INF/com/android/metadata` file
        #[arg(long)]
        metadata: Option<PathBuf>,

        /// Optional `care_map.pb` file
        #[arg(long)]
        care_map: Option<PathBuf>,

        /// Optional `apex_info.pb` file
        #[arg(long)]
        apex_info: Option<PathBuf>,

        /// Extra ZIP entries `<ZIP_PATH=LOCAL_PATH>`, repeatable
        #[arg(long = "extra-entry")]
        extra_entries: Vec<String>,

        /// Output unsigned OTA ZIP path
        #[arg(long, short)]
        output: PathBuf,
    },

    /// Verify `CrAU` header, manifest, operation hashes, partition hashes, and optional RSA signatures
    Verify {
        /// Path to `payload.bin`
        #[arg(long, short)]
        file: PathBuf,

        /// Optional X.509 certificate PEM (e.g. `otatools/key/testkey.x509.pem`) to verify RSA signatures
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

/// Parsed `dynamic_partitions_info.txt` representation.
pub fn parse_dynamic_partitions_info(text: &str) -> Result<DynamicPartitionMetadata> {
    let mut kv: HashMap<String, String> = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let mut groups = Vec::new();
    if let Some(group_list) = kv.get("super_partition_groups") {
        for group_name in group_list.split_whitespace() {
            let size_key = format!("super_{group_name}_group_size");
            let part_key = format!("super_{group_name}_partition_list");
            let size = match kv.get(&size_key) {
                Some(s) if !s.is_empty() => Some(
                    s.parse::<u64>()
                        .with_context(|| format!("Invalid {size_key}: {s}"))?,
                ),
                _ => None,
            };
            let partition_names = kv
                .get(&part_key)
                .map(|v| v.split_whitespace().map(|s| s.to_string()).collect())
                .unwrap_or_default();
            groups.push(DynamicPartitionGroup {
                name: group_name.to_string(),
                size,
                partition_names,
            });
        }
    }

    let snapshot_enabled = kv.get("virtual_ab").map(|v| v.eq_ignore_ascii_case("true"));
    // Without COW merge ops (`CowMergeOperation`), `vabc_enabled` must stay false so
    // `update_engine` uses standard snapshot partition writes for `REPLACE*`/`ZERO` ops.
    let vabc_enabled = if snapshot_enabled == Some(true) {
        Some(false)
    } else {
        None
    };

    Ok(DynamicPartitionMetadata {
        groups,
        snapshot_enabled,
        vabc_enabled,
    })
}

/// Compress a single non-zero chunk according to `mode`, falling back to `REPLACE` if compression expands it.
fn compress_chunk(chunk: &[u8], mode: CompressionMode) -> Result<(OperationType, Vec<u8>)> {
    if chunk.iter().all(|&b| b == 0) {
        return Ok((OperationType::Zero, Vec::new()));
    }

    match mode {
        CompressionMode::None => Ok((OperationType::Replace, chunk.to_vec())),
        CompressionMode::FastXz | CompressionMode::Xz => {
            let preset = if mode == CompressionMode::FastXz { 1 } else { 6 };
            let mut opts = XzOptions::with_preset(preset);
            // AOSP update_engine xz-embedded uses CRC32 checks.
            opts.check_type = CheckType::Crc32;
            let mut compressed = Vec::with_capacity(chunk.len() / 2);
            {
                let mut writer = XzWriter::new(&mut compressed, opts)?;
                writer.write_all(chunk)?;
                writer.finish()?;
            }
            if compressed.len() < chunk.len() {
                Ok((OperationType::ReplaceXz, compressed))
            } else {
                Ok((OperationType::Replace, chunk.to_vec()))
            }
        }
        CompressionMode::Bz2 => {
            let mut encoder = BzEncoder::new(chunk, BzCompression::default());
            let mut compressed = Vec::with_capacity(chunk.len() / 2);
            encoder.read_to_end(&mut compressed)?;
            if compressed.len() < chunk.len() {
                Ok((OperationType::ReplaceBz, compressed))
            } else {
                Ok((OperationType::Replace, chunk.to_vec()))
            }
        }
    }
}

struct ChunkOutput {
    op_type: OperationType,
    start_block: u64,
    num_blocks: u64,
    data: Vec<u8>,
    data_hash: Option<[u8; 32]>,
}

/// Configuration for generating a `CrAU` v2 payload.
#[derive(Debug, Clone)]
pub struct GenerateConfig {
    pub images_dir: PathBuf,
    pub partitions: Vec<String>,
    pub out_file: PathBuf,
    pub properties_out: Option<PathBuf>,
    pub dynamic_partitions_info: Option<PathBuf>,
    pub apex_info: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub signature_size: Option<usize>,
    pub compression: CompressionMode,
    pub major_version: u64,
    pub minor_version: Option<u32>,
    pub chunk_size: usize,
    pub block_size: u32,
    pub max_timestamp: Option<i64>,
    pub security_patch_level: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PayloadProperties {
    pub file_hash: String,
    pub file_size: u64,
    pub metadata_hash: String,
    pub metadata_size: u64,
}

impl PayloadProperties {
    pub fn format_text(&self) -> String {
        format!(
            "FILE_HASH={}\nFILE_SIZE={}\nMETADATA_HASH={}\nMETADATA_SIZE={}\n",
            self.file_hash, self.file_size, self.metadata_hash, self.metadata_size
        )
    }
}

fn encode_signature_proto(raw_sig: &[u8], padded_size: usize) -> Result<Vec<u8>> {
    ensure!(
        raw_sig.len() <= padded_size,
        "RSA signature ({} bytes) exceeds configured --signature-size ({padded_size})",
        raw_sig.len()
    );
    let mut padded = raw_sig.to_vec();
    padded.resize(padded_size, 0);
    let sigs = Signatures {
        signatures: vec![Signature {
            version: Some(1),
            data: padded,
            unpadded_signature_size: Some(raw_sig.len() as u32),
        }],
    };
    Ok(sigs.encode())
}

/// Generate a `CrAU` v2 `payload.bin` (and optional `payload_properties.txt`).
pub fn generate_payload(cfg: &GenerateConfig) -> Result<PayloadProperties> {
    ensure!(cfg.block_size > 0 && cfg.block_size.is_multiple_of(512), "Invalid block_size {}", cfg.block_size);
    ensure!(
        cfg.chunk_size > 0 && cfg.chunk_size.is_multiple_of(cfg.block_size as usize),
        "chunk_size ({}) must be a positive multiple of block_size ({})",
        cfg.chunk_size,
        cfg.block_size
    );
    ensure!(!cfg.partitions.is_empty(), "No partitions specified");
    ensure!(cfg.major_version == 2, "Only major_version=2 is supported");

    let signing_key = match cfg.private_key.as_deref() {
        Some(path) => Some(RsaPrivateKey::from_file(path)?),
        None => None,
    };
    let sig_size = match (&signing_key, cfg.signature_size) {
        (Some(k), Some(sz)) => {
            ensure!(sz >= k.modulus_bytes, "--signature-size {sz} < RSA modulus bytes {}", k.modulus_bytes);
            sz
        }
        (Some(k), None) => k.modulus_bytes,
        (None, _) => 0,
    };

    let dynamic_partition_metadata = match cfg.dynamic_partitions_info.as_deref() {
        Some(path) => {
            let text = read_text_lossy(path)
                .with_context(|| format!("Failed to read dynamic_partitions_info: {}", path.display()))?;
            Some(parse_dynamic_partitions_info(&text)?)
        }
        None => None,
    };

    let raw_apex_infos = match cfg.apex_info.as_deref() {
        Some(path) => {
            let bytes = fs::read(path)
                .with_context(|| format!("Failed to read apex_info: {}", path.display()))?;
            extract_raw_apex_infos(&bytes)?
        }
        None => Vec::new(),
    };

    if let Some(parent) = cfg.out_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let out_parent = cfg
        .out_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut blob_tmp = NamedTempFile::new_in(out_parent)
        .context("Failed to create temporary blob staging file")?;

    let mut data_offset: u64 = 0;
    let mut data_hasher = Sha256::new();
    let mut partition_updates = Vec::with_capacity(cfg.partitions.len());
    let block_sz = cfg.block_size as usize;

    // Process each partition in deterministic order, parallelizing 2 MiB chunks in bounded windows
    // so peak memory stays small (~batch_chunks * 2 MiB) even for multi-GB images.
    let batch_chunks = (rayon::current_num_threads() * 4).clamp(16, 64);

    for part_name in &cfg.partitions {
        let img_path = cfg.images_dir.join(format!("{part_name}.img"));
        let img_file = File::open(&img_path)
            .with_context(|| format!("Missing partition image: {}", img_path.display()))?;
        let raw_len = img_file.metadata()?.len() as usize;
        let padded_len = if raw_len == 0 {
            0
        } else {
            raw_len.div_ceil(block_sz) * block_sz
        };

        let mmap = if raw_len > 0 {
            // Safety: file is opened read-only and remains unmodified during payload generation.
            Some(unsafe { Mmap::map(&img_file)? })
        } else {
            None
        };
        let raw_slice: &[u8] = mmap.as_deref().unwrap_or(&[]);

        let mut part_hasher = Sha256::new();
        part_hasher.update(raw_slice);
        if padded_len > raw_len {
            let pad = vec![0u8; padded_len - raw_len];
            part_hasher.update(&pad);
        }
        let mut part_hash = [0u8; 32];
        part_hash.copy_from_slice(&part_hasher.finalize());

        let total_chunks = if padded_len == 0 {
            0
        } else {
            padded_len.div_ceil(cfg.chunk_size)
        };

        let mut operations = Vec::with_capacity(total_chunks);
        let mut chunk_idx = 0usize;

        while chunk_idx < total_chunks {
            let batch_end = (chunk_idx + batch_chunks).min(total_chunks);
            let results: Vec<ChunkOutput> = (chunk_idx..batch_end)
                .into_par_iter()
                .map(|idx| -> Result<ChunkOutput> {
                    let byte_start = idx * cfg.chunk_size;
                    let byte_end = ((idx + 1) * cfg.chunk_size).min(padded_len);
                    let start_block = (byte_start / block_sz) as u64;
                    let num_blocks = ((byte_end - byte_start) / block_sz) as u64;

                    let (op_type, data) = if byte_end <= raw_len {
                        compress_chunk(&raw_slice[byte_start..byte_end], cfg.compression)?
                    } else {
                        let mut owned = Vec::with_capacity(byte_end - byte_start);
                        if byte_start < raw_len {
                            owned.extend_from_slice(&raw_slice[byte_start..raw_len]);
                        }
                        owned.resize(byte_end - byte_start, 0);
                        compress_chunk(&owned, cfg.compression)?
                    };

                    let data_hash = if op_type == OperationType::Zero {
                        None
                    } else {
                        Some(sha256_bytes(&data))
                    };

                    Ok(ChunkOutput {
                        op_type,
                        start_block,
                        num_blocks,
                        data,
                        data_hash,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            for ch in results {
                let extent = Extent {
                    start_block: ch.start_block,
                    num_blocks: ch.num_blocks,
                };
                if ch.op_type == OperationType::Zero {
                    operations.push(InstallOperation {
                        op_type: OperationType::Zero,
                        data_offset: None,
                        data_length: None,
                        dst_extents: vec![extent],
                        data_sha256_hash: None,
                    });
                } else {
                    let len = ch.data.len() as u64;
                    blob_tmp.write_all(&ch.data)?;
                    data_hasher.update(&ch.data);
                    operations.push(InstallOperation {
                        op_type: ch.op_type,
                        data_offset: Some(data_offset),
                        data_length: Some(len),
                        dst_extents: vec![extent],
                        data_sha256_hash: ch.data_hash,
                    });
                    data_offset += len;
                }
            }

            chunk_idx = batch_end;
        }

        partition_updates.push(PartitionUpdate {
            partition_name: part_name.clone(),
            filesystem_type: None,
            new_partition_info: PartitionInfo {
                size: padded_len as u64,
                hash: part_hash,
            },
            operations,
        });
    }

    blob_tmp.flush()?;

    let sig_proto_len = if signing_key.is_some() {
        Some(Signatures::serialized_len_for_size(sig_size))
    } else {
        None
    };

    let manifest = DeltaArchiveManifest {
        block_size: cfg.block_size,
        signatures_offset: sig_proto_len.map(|_| data_offset),
        signatures_size: sig_proto_len.map(|l| l as u64),
        minor_version: cfg.minor_version,
        partitions: partition_updates,
        max_timestamp: cfg.max_timestamp,
        dynamic_partition_metadata,
        partial_update: None,
        raw_apex_infos,
        security_patch_level: cfg.security_patch_level.clone(),
    };

    let manifest_bytes = manifest.encode();
    let meta_sig_size_u32 = sig_proto_len.unwrap_or(0) as u32;

    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(CRAU_MAGIC);
    header.extend_from_slice(&cfg.major_version.to_be_bytes());
    header.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    header.extend_from_slice(&meta_sig_size_u32.to_be_bytes());

    let metadata_size = (header.len() + manifest_bytes.len()) as u64;
    let mut meta_hasher = Sha256::new();
    meta_hasher.update(&header);
    meta_hasher.update(&manifest_bytes);
    let mut metadata_hash = [0u8; 32];
    metadata_hash.copy_from_slice(&meta_hasher.finalize());

    let (metadata_sig_proto, eof_sig_proto) = if let Some(ref key) = signing_key {
        let meta_sig_raw = key.sign_sha256_digest(&metadata_hash)?;
        let meta_sig_proto = encode_signature_proto(&meta_sig_raw, sig_size)?;
        ensure!(
            meta_sig_proto.len() == meta_sig_size_u32 as usize,
            "Internal error: metadata signature protobuf length mismatch"
        );

        // Payload hash covers [header || manifest] + [operation data blobs], skipping metadata_sig_proto.
        let mut payload_hasher = Sha256::new();
        payload_hasher.update(&header);
        payload_hasher.update(&manifest_bytes);
        blob_tmp.seek(SeekFrom::Start(0))?;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = blob_tmp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            payload_hasher.update(&buf[..n]);
        }
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&payload_hasher.finalize());

        let eof_sig_raw = key.sign_sha256_digest(&payload_hash)?;
        let eof_sig_proto = encode_signature_proto(&eof_sig_raw, sig_size)?;
        ensure!(
            eof_sig_proto.len() == meta_sig_size_u32 as usize,
            "Internal error: EOF signature protobuf length mismatch"
        );
        (Some(meta_sig_proto), Some(eof_sig_proto))
    } else {
        (None, None)
    };

    // Assemble final `payload.bin` while hashing the entire file for `FILE_HASH`.
    let out_file = File::create(&cfg.out_file)
        .with_context(|| format!("Failed to create {}", cfg.out_file.display()))?;
    let mut writer = HashingWriter::new(BufWriter::with_capacity(1024 * 1024, out_file));
    writer.write_all(&header)?;
    writer.write_all(&manifest_bytes)?;
    if let Some(ref ms) = metadata_sig_proto {
        writer.write_all(ms)?;
    }

    blob_tmp.seek(SeekFrom::Start(0))?;
    io::copy(&mut blob_tmp, &mut writer)?;

    if let Some(ref es) = eof_sig_proto {
        writer.write_all(es)?;
    }
    let (file_hash_bytes, file_size) = writer.finish()?;

    let props = PayloadProperties {
        file_hash: base64_encode(&file_hash_bytes),
        file_size,
        metadata_hash: base64_encode(&metadata_hash),
        metadata_size,
    };

    if let Some(ref prop_path) = cfg.properties_out {
        if let Some(parent) = prop_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(prop_path, props.format_text())
            .with_context(|| format!("Failed to write {}", prop_path.display()))?;
    }

    Ok(props)
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(mut self) -> io::Result<([u8; 32], u64)> {
        self.inner.flush()?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&self.hasher.finalize());
        Ok((digest, self.written))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Package `payload.bin`, `payload_properties.txt`, and optional metadata files into an
/// uncompressed (`ZIP_STORED` + ZIP64) OTA ZIP archive.
pub fn package_ota_zip(
    output_zip: &Path,
    payload: &Path,
    properties: &Path,
    metadata: Option<&Path>,
    care_map: Option<&Path>,
    apex_info: Option<&Path>,
    extra_entries: &[(String, PathBuf)],
) -> Result<()> {
    if let Some(parent) = output_zip.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(output_zip)
        .with_context(|| format!("Failed to create OTA ZIP: {}", output_zip.display()))?;
    let mut zw = ZipWriter::new(BufWriter::with_capacity(1024 * 1024, file));
    let stored_opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true);

    let mut add_stored = |zip_name: &str, src_path: &Path| -> Result<()> {
        let mut src = BufReader::with_capacity(1024 * 1024, File::open(src_path).with_context(|| {
            format!("Failed to open {} for OTA ZIP entry {zip_name}", src_path.display())
        })?);
        zw.start_file(zip_name, stored_opts)?;
        io::copy(&mut src, &mut zw)?;
        Ok(())
    };

    add_stored("payload.bin", payload)?;
    add_stored("payload_properties.txt", properties)?;
    if let Some(m) = metadata {
        add_stored("META-INF/com/android/metadata", m)?;
    }
    if let Some(cm) = care_map {
        add_stored("care_map.pb", cm)?;
    }
    if let Some(ai) = apex_info {
        add_stored("apex_info.pb", ai)?;
    }
    for (zip_path, local_path) in extra_entries {
        add_stored(zip_path, local_path)?;
    }

    zw.finish()?.flush()?;
    Ok(())
}

/// Verify a `CrAU` v2 `payload.bin`: magic, header, manifest decoding, operation & partition hashes,
/// decompression round-trips (`REPLACE`, `REPLACE_BZ`, `REPLACE_XZ`, `ZERO`), and optional RSA signatures.
pub fn verify_payload_file(
    payload_path: &Path,
    public_key_path: Option<&Path>,
) -> Result<DeltaArchiveManifest> {
    let mut f = File::open(payload_path)
        .with_context(|| format!("Failed to open {}", payload_path.display()))?;
    let total_len = f.metadata()?.len();
    ensure!(total_len >= 24, "Payload file too small ({total_len} bytes)");

    let mut hdr = [0u8; 24];
    f.read_exact(&mut hdr)?;
    ensure!(&hdr[0..4] == CRAU_MAGIC, "Invalid CrAU magic");
    let major_version = u64::from_be_bytes(hdr[4..12].try_into().unwrap());
    ensure!(major_version == 2, "Expected major_version=2, got {major_version}");
    let manifest_size = u64::from_be_bytes(hdr[12..20].try_into().unwrap()) as usize;
    let metadata_sig_size = u32::from_be_bytes(hdr[20..24].try_into().unwrap()) as usize;

    let metadata_size = 24u64 + manifest_size as u64;
    ensure!(
        metadata_size + metadata_sig_size as u64 <= total_len,
        "Manifest/signature sizes exceed file length"
    );

    let mut manifest_bytes = vec![0u8; manifest_size];
    f.read_exact(&mut manifest_bytes)?;
    let manifest = DeltaArchiveManifest::decode(&manifest_bytes)?;

    let mut metadata_sig_bytes = vec![0u8; metadata_sig_size];
    if metadata_sig_size > 0 {
        f.read_exact(&mut metadata_sig_bytes)?;
    }

    let data_base_off = metadata_size + metadata_sig_size as u64;

    // Verify metadata signature if public key is given.
    let pub_key = match public_key_path {
        Some(p) => Some(RsaPublicKey::from_x509_pem_file(p)?),
        None => None,
    };

    let mut meta_hasher = Sha256::new();
    meta_hasher.update(hdr);
    meta_hasher.update(&manifest_bytes);
    let mut meta_digest = [0u8; 32];
    meta_digest.copy_from_slice(&meta_hasher.finalize());

    if let Some(ref pk) = pub_key {
        ensure!(metadata_sig_size > 0, "Payload has no metadata signature");
        let meta_sigs = Signatures::decode(&metadata_sig_bytes)?;
        ensure!(!meta_sigs.signatures.is_empty(), "Empty metadata Signatures");
        let sig = &meta_sigs.signatures[0];
        let unpadded = sig.unpadded_signature_size.unwrap_or(sig.data.len() as u32) as usize;
        pk.verify_sha256_digest(&meta_digest, &sig.data[..unpadded])
            .context("Metadata signature verification failed")?;
    }

    // Verify every operation's data hash and reconstructed partition SHA-256.
    let block_sz = manifest.block_size as usize;
    for part in &manifest.partitions {
        let mut part_hasher = Sha256::new();
        let mut reconstructed_len = 0u64;
        let mut scratch = Vec::new();

        for op in &part.operations {
            let expected_blocks: u64 = op.dst_extents.iter().map(|e| e.num_blocks).sum();
            let expected_bytes = (expected_blocks as usize) * block_sz;
            reconstructed_len += expected_bytes as u64;

            if op.op_type == OperationType::Zero {
                scratch.clear();
                scratch.resize(expected_bytes, 0);
                part_hasher.update(&scratch);
                continue;
            }

            let rel_off = op.data_offset.context("Missing op.data_offset")?;
            let data_len = op.data_length.context("Missing op.data_length")? as usize;
            f.seek(SeekFrom::Start(data_base_off + rel_off))?;
            let mut blob = vec![0u8; data_len];
            f.read_exact(&mut blob)?;

            if let Some(expected_hash) = op.data_sha256_hash {
                ensure!(
                    sha256_bytes(&blob) == expected_hash,
                    "Operation data SHA-256 mismatch in partition {}",
                    part.partition_name
                );
            }

            scratch.clear();
            match op.op_type {
                OperationType::Replace => scratch.extend_from_slice(&blob),
                OperationType::ReplaceXz => {
                    let mut reader = XzReader::new(io::Cursor::new(&blob), false);
                    reader.read_to_end(&mut scratch)?;
                }
                OperationType::ReplaceBz => {
                    let mut dec = BzDecoder::new(io::Cursor::new(&blob));
                    dec.read_to_end(&mut scratch)?;
                }
                other => bail!("Unsupported op type {:?} in verify", other),
            }
            ensure!(
                scratch.len() == expected_bytes,
                "Decompressed op size {} != expected {} in {}",
                scratch.len(),
                expected_bytes,
                part.partition_name
            );
            part_hasher.update(&scratch);
        }

        let mut actual_part_hash = [0u8; 32];
        actual_part_hash.copy_from_slice(&part_hasher.finalize());
        ensure!(
            reconstructed_len == part.new_partition_info.size,
            "Partition {} size mismatch: {} != {}",
            part.partition_name,
            reconstructed_len,
            part.new_partition_info.size
        );
        ensure!(
            actual_part_hash == part.new_partition_info.hash,
            "Partition {} hash mismatch",
            part.partition_name
        );
    }

    // Verify EOF payload signature if public key is given.
    if let Some(ref pk) = pub_key {
        let sig_off = manifest
            .signatures_offset
            .context("Manifest missing signatures_offset")?;
        let sig_sz = manifest
            .signatures_size
            .context("Manifest missing signatures_size")? as usize;

        let mut payload_hasher = Sha256::new();
        payload_hasher.update(hdr);
        payload_hasher.update(&manifest_bytes);
        f.seek(SeekFrom::Start(data_base_off))?;
        let mut remaining = sig_off;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            f.read_exact(&mut buf[..to_read])?;
            payload_hasher.update(&buf[..to_read]);
            remaining -= to_read as u64;
        }
        let mut payload_digest = [0u8; 32];
        payload_digest.copy_from_slice(&payload_hasher.finalize());

        let mut eof_sig_bytes = vec![0u8; sig_sz];
        f.read_exact(&mut eof_sig_bytes)?;
        let eof_sigs = Signatures::decode(&eof_sig_bytes)?;
        ensure!(!eof_sigs.signatures.is_empty(), "Empty EOF Signatures");
        let sig = &eof_sigs.signatures[0];
        let unpadded = sig.unpadded_signature_size.unwrap_or(sig.data.len() as u32) as usize;
        pk.verify_sha256_digest(&payload_digest, &sig.data[..unpadded])
            .context("Payload EOF signature verification failed")?;
    }

    Ok(manifest)
}

fn parse_partitions(
    partitions_arg: Option<&str>,
    partition_list: Vec<String>,
    ab_partitions_file: Option<&Path>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if let Some(p_str) = partitions_arg {
        for item in p_str.split([',', ' ', '\t', '\r', '\n']) {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }
    for p in partition_list {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    if let Some(ab_file) = ab_partitions_file {
        let text = read_text_lossy(ab_file)
            .with_context(|| format!("Failed to read ab_partitions file: {}", ab_file.display()))?;
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                out.push(trimmed.to_string());
            }
        }
    }
    // Preserve order while deduplicating.
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    ensure!(!out.is_empty(), "Specify --partitions, --partition, or --ab-partitions-file");
    Ok(out)
}

fn parse_extra_entries(raw: &[String]) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let (zip_path, local_path) = item
            .split_once('=')
            .with_context(|| format!("Invalid --extra-entry '{item}' (expected ZIP_PATH=LOCAL_PATH)"))?;
        out.push((zip_path.trim().to_string(), PathBuf::from(local_path.trim())));
    }
    Ok(out)
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Generate {
            images_dir,
            partitions,
            partition_list,
            ab_partitions_file,
            out_file,
            properties_out,
            dynamic_partitions_info,
            apex_info,
            private_key,
            signature_size,
            compression,
            major_version,
            minor_version,
            chunk_size,
            block_size,
            max_timestamp,
            security_patch_level,
            threads,
            ota_zip,
            metadata_file,
            care_map,
            extra_entries,
        } => {
            if let Some(n) = threads {
                let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
            }

            let part_names = parse_partitions(
                partitions.as_deref(),
                partition_list,
                ab_partitions_file.as_deref(),
            )?;

            let effective_props_out = if ota_zip.is_some() && properties_out.is_none() {
                Some(out_file.with_extension("properties.txt"))
            } else {
                properties_out
            };

            let cfg = GenerateConfig {
                images_dir,
                partitions: part_names,
                out_file: out_file.clone(),
                properties_out: effective_props_out.clone(),
                dynamic_partitions_info,
                apex_info: apex_info.clone(),
                private_key,
                signature_size,
                compression,
                major_version,
                minor_version,
                chunk_size,
                block_size,
                max_timestamp,
                security_patch_level,
            };

            let props = generate_payload(&cfg)?;
            println!(
                "[+] payload-gen: generated {} (size={} bytes, metadata_size={})",
                out_file.display(),
                props.file_size,
                props.metadata_size
            );

            if let Some(ref zip_out) = ota_zip {
                let props_file = effective_props_out.as_deref().context("Missing properties file")?;
                let parsed_extra = parse_extra_entries(&extra_entries)?;
                package_ota_zip(
                    zip_out,
                    &out_file,
                    props_file,
                    metadata_file.as_deref(),
                    care_map.as_deref(),
                    apex_info.as_deref(),
                    &parsed_extra,
                )?;
                println!("[+] payload-gen: packaged uncompressed OTA ZIP {}", zip_out.display());
            }
            Ok(())
        }

        Commands::PackageOta {
            payload,
            properties,
            metadata,
            care_map,
            apex_info,
            extra_entries,
            output,
        } => {
            let parsed_extra = parse_extra_entries(&extra_entries)?;
            package_ota_zip(
                &output,
                &payload,
                &properties,
                metadata.as_deref(),
                care_map.as_deref(),
                apex_info.as_deref(),
                &parsed_extra,
            )?;
            println!("[+] payload-gen package-ota: created {}", output.display());
            Ok(())
        }

        Commands::Verify { file, public_key } => {
            let manifest = verify_payload_file(&file, public_key.as_deref())?;
            println!(
                "[+] payload-gen verify: OK ({} partitions, block_size={})",
                manifest.partitions.len(),
                manifest.block_size
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_image(size: usize, seed: u8) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        // First 4096 bytes non-zero patterned, second 4096 bytes all-zero (tests ZERO op!),
        // remainder non-zero compressible/incompressible mix.
        for (i, b) in buf.iter_mut().enumerate().take(4096.min(size)) {
            *b = seed.wrapping_add((i % 29) as u8);
        }
        if size > 8192 {
            for (i, b) in buf.iter_mut().enumerate().skip(8192) {
                *b = ((i * 31) ^ (seed as usize)) as u8;
            }
        }
        buf
    }

    #[test]
    fn test_dynamic_partitions_info_parser() {
        let txt = "\
super_partition_size=10200547328
super_partition_groups=qti_dynamic_partitions
super_qti_dynamic_partitions_group_size=10199006208
super_qti_dynamic_partitions_partition_list=system system_ext product vendor odm
virtual_ab=true
virtual_ab_compression=true
";
        let dpm = parse_dynamic_partitions_info(txt).unwrap();
        assert_eq!(dpm.groups.len(), 1);
        assert_eq!(dpm.groups[0].name, "qti_dynamic_partitions");
        assert_eq!(dpm.groups[0].size, Some(10199006208));
        assert_eq!(
            dpm.groups[0].partition_names,
            vec!["system", "system_ext", "product", "vendor", "odm"]
        );
        assert_eq!(dpm.snapshot_enabled, Some(true));
        // Must stay false without VABC COW ops
        assert_eq!(dpm.vabc_enabled, Some(false));
    }

    #[test]
    fn test_payload_generation_all_compressions_signed_and_verified() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..");
        let priv_key = repo_root.join("otatools/key/testkey.pk8");
        let pub_cert = repo_root.join("otatools/key/testkey.x509.pem");

        let td = TempDir::new().unwrap();
        let img_dir = td.path().join("IMAGES");
        fs::create_dir_all(&img_dir).unwrap();

        // 3 chunks in system.img when chunk_size=4096: chunk0 non-zero, chunk1 all-zero -> ZERO, chunk2 non-zero
        let sys_bytes = make_test_image(12288, 7);
        // Unaligned boot.img (5000 bytes -> auto-padded to 8192 bytes)
        let boot_bytes = make_test_image(5000, 42);
        fs::write(img_dir.join("system.img"), &sys_bytes).unwrap();
        fs::write(img_dir.join("boot.img"), &boot_bytes).unwrap();

        let dpm_path = td.path().join("dynamic_partitions_info.txt");
        fs::write(
            &dpm_path,
            "super_partition_groups=qti_dynamic_partitions\nsuper_qti_dynamic_partitions_group_size=1048576\nsuper_qti_dynamic_partitions_partition_list=system\nvirtual_ab=true\n",
        )
        .unwrap();

        for mode in [
            CompressionMode::FastXz,
            CompressionMode::Xz,
            CompressionMode::Bz2,
            CompressionMode::None,
        ] {
            let out_payload = td.path().join(format!("payload_{mode:?}.bin"));
            let out_props = td.path().join(format!("props_{mode:?}.txt"));
            let out_zip = td.path().join(format!("ota_{mode:?}.zip"));
            let meta_file = td.path().join("metadata");
            fs::write(&meta_file, "ota-type=AB\n").unwrap();

            run_cli(Cli::parse_from([
                "payload-gen",
                "generate",
                "--images-dir",
                img_dir.to_str().unwrap(),
                "--partitions",
                "system,boot",
                "--out-file",
                out_payload.to_str().unwrap(),
                "--properties-out",
                out_props.to_str().unwrap(),
                "--dynamic-partitions-info",
                dpm_path.to_str().unwrap(),
                "--private-key",
                priv_key.to_str().unwrap(),
                "--compression",
                match mode {
                    CompressionMode::FastXz => "fast-xz",
                    CompressionMode::Xz => "xz",
                    CompressionMode::Bz2 => "bz2",
                    CompressionMode::None => "none",
                },
                "--chunk-size",
                "4096",
                "--minor-version",
                "0",
                "--security-patch-level",
                "2026-04-05",
                "--ota-zip",
                out_zip.to_str().unwrap(),
                "--metadata-file",
                meta_file.to_str().unwrap(),
            ]))
            .unwrap();

            // Verify CrAU v2 payload + RSA signatures + hashes + decompression
            let manifest = verify_payload_file(&out_payload, Some(&pub_cert)).unwrap();
            assert_eq!(manifest.partitions.len(), 2);
            assert_eq!(manifest.partitions[0].partition_name, "system");
            // Chunk 1 of system.img is all zeros -> MUST be OperationType::Zero!
            assert_eq!(manifest.partitions[0].operations[1].op_type, OperationType::Zero);
            assert_eq!(manifest.partitions[1].new_partition_info.size, 8192);
            assert_eq!(manifest.security_patch_level.as_deref(), Some("2026-04-05"));
            assert_eq!(
                manifest
                    .dynamic_partition_metadata
                    .as_ref()
                    .and_then(|d| d.vabc_enabled),
                Some(false)
            );

            // Verify payload_properties.txt format & exact FILE_SIZE / FILE_HASH
            let props_text = fs::read_to_string(&out_props).unwrap();
            let payload_bytes = fs::read(&out_payload).unwrap();
            let expected_file_hash = base64_encode(&sha256_bytes(&payload_bytes));
            assert!(props_text.contains(&format!("FILE_HASH={expected_file_hash}\n")));
            assert!(props_text.contains(&format!("FILE_SIZE={}\n", payload_bytes.len())));
            assert!(props_text.contains("METADATA_HASH="));
            assert!(props_text.contains("METADATA_SIZE="));

            // Verify OTA ZIP has Stored entries
            let za = zip::ZipArchive::new(File::open(&out_zip).unwrap()).unwrap();
            assert_eq!(za.len(), 3);
        }
    }
}
