//! Minimal, zero-dependency protobuf encoder and decoder for AOSP `update_metadata.proto`.
//!
//! Covers:
//! - `Extent`, `InstallOperation`, `PartitionInfo`, `PartitionUpdate`
//! - `DynamicPartitionGroup`, `DynamicPartitionMetadata`, `ApexInfo`, `ApexMetadata`
//! - `DeltaArchiveManifest`
//! - `Signatures`, `Signature`

use anyhow::{bail, ensure, Result};

/// AOSP `InstallOperation::Type` enum values from `update_metadata.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OperationType {
    Replace = 0,
    ReplaceBz = 1,
    Zero = 6,
    Discard = 7,
    ReplaceXz = 8,
}

impl OperationType {
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::Replace),
            1 => Ok(Self::ReplaceBz),
            6 => Ok(Self::Zero),
            7 => Ok(Self::Discard),
            8 => Ok(Self::ReplaceXz),
            other => bail!("Unsupported InstallOperation::Type value: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extent {
    pub start_block: u64,
    pub num_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOperation {
    pub op_type: OperationType,
    pub data_offset: Option<u64>,
    pub data_length: Option<u64>,
    pub dst_extents: Vec<Extent>,
    pub data_sha256_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    pub size: u64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionUpdate {
    pub partition_name: String,
    pub filesystem_type: Option<String>,
    pub new_partition_info: PartitionInfo,
    pub operations: Vec<InstallOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicPartitionGroup {
    pub name: String,
    pub size: Option<u64>,
    pub partition_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DynamicPartitionMetadata {
    pub groups: Vec<DynamicPartitionGroup>,
    pub snapshot_enabled: Option<bool>,
    pub vabc_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexInfo {
    pub package_name: Option<String>,
    pub version: Option<i64>,
    pub is_compressed: Option<bool>,
    pub decompressed_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaArchiveManifest {
    pub block_size: u32,
    pub signatures_offset: Option<u64>,
    pub signatures_size: Option<u64>,
    pub minor_version: Option<u32>,
    pub partitions: Vec<PartitionUpdate>,
    pub max_timestamp: Option<i64>,
    pub dynamic_partition_metadata: Option<DynamicPartitionMetadata>,
    pub partial_update: Option<bool>,
    /// Raw serialized `ApexInfo` sub-messages (wire field 17 in `DeltaArchiveManifest`).
    pub raw_apex_infos: Vec<Vec<u8>>,
    pub security_patch_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub version: Option<u32>,
    pub data: Vec<u8>,
    pub unpadded_signature_size: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signatures {
    pub signatures: Vec<Signature>,
}

// --- Low-level protobuf wire helpers ---

const WIRE_VARINT: u32 = 0;
const WIRE_LEN: u32 = 2;
const WIRE_FIXED32: u32 = 5;

fn push_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn push_tag(buf: &mut Vec<u8>, field: u32, wire_type: u32) {
    push_varint(buf, ((field << 3) | wire_type) as u64);
}

fn push_varint_field(buf: &mut Vec<u8>, field: u32, val: u64) {
    push_tag(buf, field, WIRE_VARINT);
    push_varint(buf, val);
}

fn push_bool_field(buf: &mut Vec<u8>, field: u32, val: bool) {
    push_varint_field(buf, field, if val { 1 } else { 0 });
}

fn push_bytes_field(buf: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    push_tag(buf, field, WIRE_LEN);
    push_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn push_fixed32_field(buf: &mut Vec<u8>, field: u32, val: u32) {
    push_tag(buf, field, WIRE_FIXED32);
    buf.extend_from_slice(&val.to_le_bytes());
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        ensure!(*pos < data.len(), "Truncated protobuf varint");
        let b = data[*pos];
        *pos += 1;
        ensure!(shift < 64, "Protobuf varint overflow");
        val |= ((b & 0x7F) as u64) << shift;
        if b < 0x80 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_varint(data, pos)? as usize;
    ensure!(*pos + len <= data.len(), "Truncated protobuf length-delimited field");
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u32) -> Result<()> {
    match wire_type {
        WIRE_VARINT => {
            let _ = read_varint(data, pos)?;
        }
        1 => {
            ensure!(*pos + 8 <= data.len(), "Truncated fixed64");
            *pos += 8;
        }
        WIRE_LEN => {
            let _ = read_bytes(data, pos)?;
        }
        WIRE_FIXED32 => {
            ensure!(*pos + 4 <= data.len(), "Truncated fixed32");
            *pos += 4;
        }
        other => bail!("Unsupported protobuf wire type {other}"),
    }
    Ok(())
}

// --- Encoders ---

impl Extent {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        push_varint_field(&mut out, 1, self.start_block);
        push_varint_field(&mut out, 2, self.num_blocks);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut start_block = 0;
        let mut num_blocks = 0;
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_VARINT) => start_block = read_varint(data, &mut pos)?,
                (2, WIRE_VARINT) => num_blocks = read_varint(data, &mut pos)?,
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self {
            start_block,
            num_blocks,
        })
    }
}

impl InstallOperation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        push_varint_field(&mut out, 1, self.op_type as u64);
        if let Some(off) = self.data_offset {
            push_varint_field(&mut out, 2, off);
        }
        if let Some(len) = self.data_length {
            push_varint_field(&mut out, 3, len);
        }
        for ext in &self.dst_extents {
            push_bytes_field(&mut out, 6, &ext.encode());
        }
        if let Some(hash) = &self.data_sha256_hash {
            push_bytes_field(&mut out, 8, hash);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut op_type = None;
        let mut data_offset = None;
        let mut data_length = None;
        let mut dst_extents = Vec::new();
        let mut data_sha256_hash = None;

        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_VARINT) => {
                    op_type = Some(OperationType::from_u32(read_varint(data, &mut pos)? as u32)?);
                }
                (2, WIRE_VARINT) => data_offset = Some(read_varint(data, &mut pos)?),
                (3, WIRE_VARINT) => data_length = Some(read_varint(data, &mut pos)?),
                (6, WIRE_LEN) => dst_extents.push(Extent::decode(read_bytes(data, &mut pos)?)?),
                (8, WIRE_LEN) => {
                    let h = read_bytes(data, &mut pos)?;
                    ensure!(h.len() == 32, "Expected 32-byte SHA-256 hash");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(h);
                    data_sha256_hash = Some(arr);
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }

        Ok(Self {
            op_type: op_type.ok_or_else(|| anyhow::anyhow!("Missing InstallOperation.type"))?,
            data_offset,
            data_length,
            dst_extents,
            data_sha256_hash,
        })
    }
}

impl PartitionInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        push_varint_field(&mut out, 1, self.size);
        push_bytes_field(&mut out, 2, &self.hash);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut size = 0;
        let mut hash = [0u8; 32];
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_VARINT) => size = read_varint(data, &mut pos)?,
                (2, WIRE_LEN) => {
                    let b = read_bytes(data, &mut pos)?;
                    ensure!(b.len() == 32, "Expected 32-byte PartitionInfo.hash");
                    hash.copy_from_slice(b);
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self { size, hash })
    }
}

impl PartitionUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.operations.len() * 64 + 64);
        push_bytes_field(&mut out, 1, self.partition_name.as_bytes());
        if let Some(ref fs_type) = self.filesystem_type {
            push_bytes_field(&mut out, 4, fs_type.as_bytes());
        }
        push_bytes_field(&mut out, 7, &self.new_partition_info.encode());
        for op in &self.operations {
            push_bytes_field(&mut out, 8, &op.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut partition_name = String::new();
        let mut filesystem_type = None;
        let mut new_partition_info = None;
        let mut operations = Vec::new();
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_LEN) => {
                    partition_name = String::from_utf8(read_bytes(data, &mut pos)?.to_vec())?;
                }
                (4, WIRE_LEN) => {
                    filesystem_type = Some(String::from_utf8(read_bytes(data, &mut pos)?.to_vec())?);
                }
                (7, WIRE_LEN) => {
                    new_partition_info = Some(PartitionInfo::decode(read_bytes(data, &mut pos)?)?);
                }
                (8, WIRE_LEN) => {
                    operations.push(InstallOperation::decode(read_bytes(data, &mut pos)?)?);
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self {
            partition_name,
            filesystem_type,
            new_partition_info: new_partition_info
                .ok_or_else(|| anyhow::anyhow!("Missing new_partition_info"))?,
            operations,
        })
    }
}

impl DynamicPartitionGroup {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        push_bytes_field(&mut out, 1, self.name.as_bytes());
        if let Some(size) = self.size {
            push_varint_field(&mut out, 2, size);
        }
        for p in &self.partition_names {
            push_bytes_field(&mut out, 3, p.as_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut name = String::new();
        let mut size = None;
        let mut partition_names = Vec::new();
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_LEN) => name = String::from_utf8(read_bytes(data, &mut pos)?.to_vec())?,
                (2, WIRE_VARINT) => size = Some(read_varint(data, &mut pos)?),
                (3, WIRE_LEN) => {
                    partition_names.push(String::from_utf8(read_bytes(data, &mut pos)?.to_vec())?);
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self {
            name,
            size,
            partition_names,
        })
    }
}

impl DynamicPartitionMetadata {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        for g in &self.groups {
            push_bytes_field(&mut out, 1, &g.encode());
        }
        if let Some(snap) = self.snapshot_enabled {
            push_bool_field(&mut out, 2, snap);
        }
        if let Some(vabc) = self.vabc_enabled {
            push_bool_field(&mut out, 3, vabc);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut groups = Vec::new();
        let mut snapshot_enabled = None;
        let mut vabc_enabled = None;
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_LEN) => {
                    groups.push(DynamicPartitionGroup::decode(read_bytes(data, &mut pos)?)?);
                }
                (2, WIRE_VARINT) => snapshot_enabled = Some(read_varint(data, &mut pos)? != 0),
                (3, WIRE_VARINT) => vabc_enabled = Some(read_varint(data, &mut pos)? != 0),
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self {
            groups,
            snapshot_enabled,
            vabc_enabled,
        })
    }
}

impl DeltaArchiveManifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4096);
        push_varint_field(&mut out, 3, self.block_size as u64);
        if let Some(off) = self.signatures_offset {
            push_varint_field(&mut out, 4, off);
        }
        if let Some(sz) = self.signatures_size {
            push_varint_field(&mut out, 5, sz);
        }
        if let Some(mv) = self.minor_version {
            push_varint_field(&mut out, 12, mv as u64);
        }
        for p in &self.partitions {
            push_bytes_field(&mut out, 13, &p.encode());
        }
        if let Some(ts) = self.max_timestamp {
            push_varint_field(&mut out, 14, ts as u64);
        }
        if let Some(ref dpm) = self.dynamic_partition_metadata {
            push_bytes_field(&mut out, 15, &dpm.encode());
        }
        if let Some(partial) = self.partial_update {
            push_bool_field(&mut out, 16, partial);
        }
        for raw_apex in &self.raw_apex_infos {
            push_bytes_field(&mut out, 17, raw_apex);
        }
        if let Some(ref spl) = self.security_patch_level {
            push_bytes_field(&mut out, 18, spl.as_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut block_size = 4096u32;
        let mut signatures_offset = None;
        let mut signatures_size = None;
        let mut minor_version = None;
        let mut partitions = Vec::new();
        let mut max_timestamp = None;
        let mut dynamic_partition_metadata = None;
        let mut partial_update = None;
        let mut raw_apex_infos = Vec::new();
        let mut security_patch_level = None;

        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (3, WIRE_VARINT) => block_size = read_varint(data, &mut pos)? as u32,
                (4, WIRE_VARINT) => signatures_offset = Some(read_varint(data, &mut pos)?),
                (5, WIRE_VARINT) => signatures_size = Some(read_varint(data, &mut pos)?),
                (12, WIRE_VARINT) => minor_version = Some(read_varint(data, &mut pos)? as u32),
                (13, WIRE_LEN) => {
                    partitions.push(PartitionUpdate::decode(read_bytes(data, &mut pos)?)?);
                }
                (14, WIRE_VARINT) => max_timestamp = Some(read_varint(data, &mut pos)? as i64),
                (15, WIRE_LEN) => {
                    dynamic_partition_metadata =
                        Some(DynamicPartitionMetadata::decode(read_bytes(data, &mut pos)?)?);
                }
                (16, WIRE_VARINT) => partial_update = Some(read_varint(data, &mut pos)? != 0),
                (17, WIRE_LEN) => raw_apex_infos.push(read_bytes(data, &mut pos)?.to_vec()),
                (18, WIRE_LEN) => {
                    security_patch_level =
                        Some(String::from_utf8(read_bytes(data, &mut pos)?.to_vec())?);
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }

        Ok(Self {
            block_size,
            signatures_offset,
            signatures_size,
            minor_version,
            partitions,
            max_timestamp,
            dynamic_partition_metadata,
            partial_update,
            raw_apex_infos,
            security_patch_level,
        })
    }
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 16);
        if let Some(ver) = self.version {
            push_varint_field(&mut out, 1, ver as u64);
        }
        push_bytes_field(&mut out, 2, &self.data);
        if let Some(unpadded) = self.unpadded_signature_size {
            push_fixed32_field(&mut out, 3, unpadded);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut version = None;
        let mut sig_data = Vec::new();
        let mut unpadded_signature_size = None;
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_VARINT) => version = Some(read_varint(data, &mut pos)? as u32),
                (2, WIRE_LEN) => sig_data = read_bytes(data, &mut pos)?.to_vec(),
                (3, WIRE_FIXED32) => {
                    ensure!(pos + 4 <= data.len(), "Truncated fixed32 unpadded_signature_size");
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&data[pos..pos + 4]);
                    pos += 4;
                    unpadded_signature_size = Some(u32::from_le_bytes(b));
                }
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self {
            version,
            data: sig_data,
            unpadded_signature_size,
        })
    }
}

impl Signatures {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in &self.signatures {
            push_bytes_field(&mut out, 1, &s.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let mut signatures = Vec::new();
        while pos < data.len() {
            let tag = read_varint(data, &mut pos)? as u32;
            let field = tag >> 3;
            let wire = tag & 0x07;
            match (field, wire) {
                (1, WIRE_LEN) => signatures.push(Signature::decode(read_bytes(data, &mut pos)?)?),
                _ => skip_field(data, &mut pos, wire)?,
            }
        }
        Ok(Self { signatures })
    }

    /// Compute the exact serialized byte length of a 1-signature `Signatures` protobuf
    /// for a given padded `signature_size`.
    pub fn serialized_len_for_size(signature_size: usize) -> usize {
        Self {
            signatures: vec![Signature {
                version: Some(1),
                data: vec![0u8; signature_size],
                unpadded_signature_size: Some(signature_size as u32),
            }],
        }
        .encode()
        .len()
    }
}

/// Extract raw `ApexInfo` entries (field 1 of `ApexMetadata` in `apex_info.pb`)
/// so they can be embedded directly as field 17 of `DeltaArchiveManifest`.
pub fn extract_raw_apex_infos(apex_metadata_pb: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut pos = 0;
    let mut infos = Vec::new();
    while pos < apex_metadata_pb.len() {
        let tag = read_varint(apex_metadata_pb, &mut pos)? as u32;
        let field = tag >> 3;
        let wire = tag & 0x07;
        if field == 1 && wire == WIRE_LEN {
            infos.push(read_bytes(apex_metadata_pb, &mut pos)?.to_vec());
        } else {
            skip_field(apex_metadata_pb, &mut pos, wire)?;
        }
    }
    Ok(infos)
}
