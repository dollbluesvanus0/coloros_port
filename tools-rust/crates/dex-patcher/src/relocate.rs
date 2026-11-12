//! DEX layout relocation and sorted `string_ids` insertion preserving `map_list`
//! and Android ART `DexFileVerifier` invariants.

use crate::dex::{
    decode_string_at, insn_len, insert_insns_at, read_sleb128, read_u16, read_u32, read_uleb128,
    write_u16, write_u32, write_uleb128, ClassData, CodeItem, DexFile, NO_INDEX,
};
use anyhow::{bail, ensure, Context, Result};
use std::collections::{BTreeMap, HashMap};

pub const TYPE_HEADER_ITEM: u16 = 0x0000;
pub const TYPE_STRING_ID_ITEM: u16 = 0x0001;
pub const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
pub const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
pub const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
pub const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
pub const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
pub const TYPE_CALL_SITE_ID_ITEM: u16 = 0x0007;
pub const TYPE_METHOD_HANDLE_ITEM: u16 = 0x0008;
pub const TYPE_MAP_LIST: u16 = 0x1000;
pub const TYPE_TYPE_LIST: u16 = 0x1001;
pub const TYPE_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
pub const TYPE_ANNOTATION_SET_ITEM: u16 = 0x1003;
pub const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
pub const TYPE_CODE_ITEM: u16 = 0x2001;
pub const TYPE_STRING_DATA_ITEM: u16 = 0x2002;
pub const TYPE_DEBUG_INFO_ITEM: u16 = 0x2003;
pub const TYPE_ANNOTATION_ITEM: u16 = 0x2004;
pub const TYPE_ENCODED_ARRAY_ITEM: u16 = 0x2005;
pub const TYPE_ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const TYPE_HIDDENAPI_CLASS_DATA_ITEM: u16 = 0xF000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    pub type_code: u16,
    pub unused: u16,
    pub size: u32,
    pub offset: u32,
}

#[inline]
pub fn align_up(val: usize, align: usize) -> usize {
    if align <= 1 {
        return val;
    }
    let rem = val % align;
    if rem == 0 {
        val
    } else {
        val + (align - rem)
    }
}

/// Required DEX alignment for each `map_list` section type.
pub fn section_alignment(type_code: u16) -> usize {
    match type_code {
        TYPE_CLASS_DATA_ITEM
        | TYPE_STRING_DATA_ITEM
        | TYPE_DEBUG_INFO_ITEM
        | TYPE_ANNOTATION_ITEM
        | TYPE_ENCODED_ARRAY_ITEM => 1,
        _ => 4,
    }
}

/// Read `map_list` at `map_off`.
pub fn read_map_list(data: &[u8], map_off: usize) -> Result<Vec<MapItem>> {
    ensure!(map_off + 4 <= data.len(), "map_off 0x{:x} out of bounds", map_off);
    let count = read_u32(data, map_off) as usize;
    ensure!(
        map_off + 4 + count * 12 <= data.len(),
        "map_list truncated (count={})",
        count
    );
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let pos = map_off + 4 + i * 12;
        items.push(MapItem {
            type_code: read_u16(data, pos),
            unused: read_u16(data, pos + 2),
            size: read_u32(data, pos + 4),
            offset: read_u32(data, pos + 8),
        });
    }
    Ok(items)
}

/// Encode `s` into raw MUTF-8 bytes (without ULEB128 header or trailing NUL).
pub fn encode_mutf8_raw(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for code_unit in s.encode_utf16() {
        if code_unit == 0 {
            out.push(0xC0);
            out.push(0x80);
        } else if code_unit < 0x80 {
            out.push(code_unit as u8);
        } else if code_unit < 0x800 {
            out.push(0xC0 | ((code_unit >> 6) as u8));
            out.push(0x80 | ((code_unit & 0x3F) as u8));
        } else {
            out.push(0xE0 | ((code_unit >> 12) as u8));
            out.push(0x80 | (((code_unit >> 6) & 0x3F) as u8));
            out.push(0x80 | ((code_unit & 0x3F) as u8));
        }
    }
    out
}

/// Read the raw MUTF-8 bytes (excluding ULEB128 utf16_size header and NUL) of a `string_data_item`.
pub fn raw_mutf8_bytes_at(data: &[u8], offset: usize) -> Result<&[u8]> {
    let (_, n) = read_uleb128(data, offset)?;
    let start = offset + n;
    let nul_pos = data[start..]
        .iter()
        .position(|&b| b == 0)
        .context("Missing NUL in string_data_item")?;
    Ok(&data[start..start + nul_pos])
}

/// Compute the byte length of a single `code_item` starting at `off`.
pub fn code_item_raw_len(data: &[u8], off: usize) -> Result<usize> {
    ensure!(off + 16 <= data.len(), "code_item header out of bounds at 0x{:x}", off);
    let tries_size = read_u16(data, off + 6) as usize;
    let insns_size = read_u32(data, off + 12) as usize;
    let mut pos = off + 16 + insns_size * 2;
    if tries_size > 0 {
        if insns_size % 2 == 1 {
            pos += 2;
        }
        pos += tries_size * 8;
        let (handlers_size, n) = read_uleb128(data, pos)?;
        pos += n;
        for _ in 0..handlers_size {
            let (size, n) = read_sleb128(data, pos)?;
            pos += n;
            let pairs = size.unsigned_abs() as usize;
            for _ in 0..pairs {
                let (_, n1) = read_uleb128(data, pos)?;
                pos += n1;
                let (_, n2) = read_uleb128(data, pos)?;
                pos += n2;
            }
            if size <= 0 {
                let (_, n_ca) = read_uleb128(data, pos)?;
                pos += n_ca;
            }
        }
    }
    ensure!(pos <= data.len(), "code_item truncated at 0x{:x}", off);
    Ok(pos - off)
}

/// Count how many `EncodedMethod`s across all `class_defs` point to `code_off`.
pub fn count_code_off_refs(dex: &DexFile, code_off: u32) -> Result<usize> {
    let mut count = 0usize;
    for cd in &dex.class_defs {
        if cd.class_data_off == 0 {
            continue;
        }
        let class_data = dex.read_class_data(cd.class_data_off)?;
        for m in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            if m.code_off == code_off {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Skip/transform a `debug_info_item` starting at `off`, optionally incrementing string indices >= `shift_from`.
/// Returns `(consumed_bytes, encoded_bytes)`.
fn scan_or_shift_debug_info(data: &[u8], off: usize, shift_from: Option<u32>) -> Result<(usize, Vec<u8>)> {
    let mut pos = off;
    let mut out = Vec::new();
    let shift_uleb128p1 = |val_p1: u32| -> u32 {
        if let Some(k) = shift_from {
            if val_p1 > 0 {
                let idx = val_p1 - 1;
                if idx >= k {
                    return val_p1 + 1;
                }
            }
        }
        val_p1
    };

    let (line_start, n) = read_uleb128(data, pos)?;
    pos += n;
    write_uleb128(&mut out, line_start);

    let (params_size, n) = read_uleb128(data, pos)?;
    pos += n;
    write_uleb128(&mut out, params_size);

    for _ in 0..params_size {
        let (p_name_p1, n) = read_uleb128(data, pos)?;
        pos += n;
        write_uleb128(&mut out, shift_uleb128p1(p_name_p1));
    }

    loop {
        ensure!(pos < data.len(), "Truncated debug_info_item at 0x{:x}", off);
        let op = data[pos];
        pos += 1;
        out.push(op);
        match op {
            0x00 => break, // DBG_END_SEQUENCE
            0x01 => {
                // DBG_ADVANCE_PC(addr_diff: uleb128)
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, v);
            }
            0x02 => {
                // DBG_ADVANCE_LINE(line_diff: sleb128)
                let (v, n) = read_sleb128(data, pos)?;
                pos += n;
                crate::dex::write_sleb128(&mut out, v);
            }
            0x03 => {
                // DBG_START_LOCAL(reg, name_idx: uleb128p1, type_idx: uleb128p1)
                let (reg, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, reg);
                let (name_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, shift_uleb128p1(name_p1));
                let (ty_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, ty_p1);
            }
            0x04 => {
                // DBG_START_LOCAL_EXTENDED(reg, name_idx, type_idx, sig_idx)
                let (reg, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, reg);
                let (name_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, shift_uleb128p1(name_p1));
                let (ty_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, ty_p1);
                let (sig_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, shift_uleb128p1(sig_p1));
            }
            0x05 | 0x06 => {
                // DBG_END_LOCAL / DBG_RESTART_LOCAL(reg: uleb128)
                let (reg, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, reg);
            }
            0x07 | 0x08 => {}
            0x09 => {
                // DBG_SET_FILE(name_idx: uleb128p1)
                let (name_p1, n) = read_uleb128(data, pos)?;
                pos += n;
                write_uleb128(&mut out, shift_uleb128p1(name_p1));
            }
            _ => {}
        }
    }

    Ok((pos - off, out))
}

/// Scan/shift an `encoded_value` at `data[*pos]`, advancing `*pos` and appending encoded bytes to `out`.
fn scan_or_shift_encoded_value(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    shift_from: Option<u32>,
) -> Result<()> {
    ensure!(*pos < data.len(), "Truncated encoded_value at 0x{:x}", *pos);
    let header = data[*pos];
    *pos += 1;
    let value_type = header & 0x1F;
    let value_arg = (header >> 5) & 0x07;

    match value_type {
        0x1E | 0x1F => {
            // VALUE_NULL / VALUE_BOOLEAN (no value bytes)
            out.push(header);
        }
        0x1C => {
            // VALUE_ARRAY
            out.push(header);
            scan_or_shift_encoded_array(data, pos, out, shift_from)?;
        }
        0x1D => {
            // VALUE_ANNOTATION
            out.push(header);
            scan_or_shift_encoded_annotation(data, pos, out, shift_from)?;
        }
        0x17 => {
            // VALUE_STRING: unsigned LE integer of length (value_arg + 1)
            let byte_count = (value_arg as usize) + 1;
            ensure!(
                byte_count <= 4 && *pos + byte_count <= data.len(),
                "Invalid VALUE_STRING length"
            );
            let mut idx = 0u32;
            for b_i in 0..byte_count {
                idx |= (data[*pos + b_i] as u32) << (8 * b_i);
            }
            *pos += byte_count;
            if let Some(k) = shift_from {
                if idx >= k {
                    idx += 1;
                }
            }
            let min_bytes = if idx <= 0xFF {
                1
            } else if idx <= 0xFFFF {
                2
            } else if idx <= 0xFF_FFFF {
                3
            } else {
                4
            };
            let new_arg = (min_bytes - 1) as u8;
            out.push((new_arg << 5) | value_type);
            for b_i in 0..min_bytes {
                out.push(((idx >> (8 * b_i)) & 0xFF) as u8);
            }
        }
        0x00 | 0x02 | 0x03 | 0x04 | 0x06 | 0x10 | 0x11 | 0x15 | 0x16 | 0x18 | 0x19 | 0x1A
        | 0x1B => {
            let byte_count = (value_arg as usize) + 1;
            ensure!(*pos + byte_count <= data.len(), "Truncated encoded_value payload");
            out.push(header);
            out.extend_from_slice(&data[*pos..*pos + byte_count]);
            *pos += byte_count;
        }
        other => bail!("Unknown DEX encoded_value type 0x{:02x}", other),
    }
    Ok(())
}

fn scan_or_shift_encoded_array(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    shift_from: Option<u32>,
) -> Result<()> {
    let (size, n) = read_uleb128(data, *pos)?;
    *pos += n;
    write_uleb128(out, size);
    for _ in 0..size {
        scan_or_shift_encoded_value(data, pos, out, shift_from)?;
    }
    Ok(())
}

fn scan_or_shift_encoded_annotation(
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    shift_from: Option<u32>,
) -> Result<()> {
    let (type_idx, n) = read_uleb128(data, *pos)?;
    *pos += n;
    write_uleb128(out, type_idx);
    let (size, n) = read_uleb128(data, *pos)?;
    *pos += n;
    write_uleb128(out, size);
    for _ in 0..size {
        let (mut name_idx, n) = read_uleb128(data, *pos)?;
        *pos += n;
        if let Some(k) = shift_from {
            if name_idx >= k {
                name_idx += 1;
            }
        }
        write_uleb128(out, name_idx);
        scan_or_shift_encoded_value(data, pos, out, shift_from)?;
    }
    Ok(())
}

/// Shift `string_idx >= k` inside a single `CodeItem`. Returns `Ok(true)` if modified.
fn shift_string_idx_in_code_item(code: &mut CodeItem, shift_from: u32) -> Result<bool> {
    let mut changed = false;
    let mut upgrade_pcs = Vec::new();
    let mut pc = 0;
    while pc < code.insns.len() {
        let len = insn_len(&code.insns, pc);
        let word = code.insns[pc];
        if word != 0x0100 && word != 0x0200 && word != 0x0300 {
            let op = (word & 0xFF) as u8;
            if op == 0x1A && pc + 1 < code.insns.len() {
                let s_idx = code.insns[pc + 1] as u32;
                if s_idx >= shift_from {
                    let new_idx = s_idx + 1;
                    if new_idx <= u16::MAX as u32 {
                        code.insns[pc + 1] = new_idx as u16;
                    } else {
                        upgrade_pcs.push((pc, new_idx));
                    }
                    changed = true;
                }
            } else if op == 0x1B && pc + 2 < code.insns.len() {
                let s_idx = (code.insns[pc + 1] as u32) | ((code.insns[pc + 2] as u32) << 16);
                if s_idx >= shift_from {
                    let new_idx = s_idx + 1;
                    code.insns[pc + 1] = (new_idx & 0xFFFF) as u16;
                    code.insns[pc + 2] = (new_idx >> 16) as u16;
                    changed = true;
                }
            }
        }
        pc += len;
    }

    // Upgrade any 0x1A const-string whose index crossed 0xFFFF -> 0x10000 into 0x1B const-string/jumbo
    for (orig_pc, new_idx) in upgrade_pcs.into_iter().rev() {
        let reg_aa = code.insns[orig_pc] & 0xFF00;
        let lo = (new_idx & 0xFFFF) as u16;
        let hi = (new_idx >> 16) as u16;
        insert_insns_at(code, orig_pc + 2, &[hi])?;
        code.insns[orig_pc] = reg_aa | 0x001B;
        code.insns[orig_pc + 1] = lo;
    }

    Ok(changed)
}

/// Representation of a parsed data section for clean layout & offset remapping.
enum DataSectionKind {
    CodeItems {
        items: Vec<(u32, CodeItem, Vec<u8>)>,
    },
    ClassDataItems {
        items: Vec<(u32, ClassData, Vec<u8>)>,
    },
    StringDataItems {
        items: Vec<(Option<u32>, Vec<u8>)>,
    },
    VariableItems {
        /// `(old_off, transformed_bytes)` for `DEBUG_INFO_ITEM`, `ANNOTATION_ITEM`, `ENCODED_ARRAY_ITEM`
        items: Vec<(u32, Vec<u8>)>,
    },
    MapList,
    Opaque {
        bytes: Vec<u8>,
    },
}

struct DataSection {
    type_code: u16,
    unused: u16,
    size: u32,
    old_offset: u32,
    new_offset: u32,
    kind: DataSectionKind,
}

/// Piecewise + item-level mapping from original file offsets to new file offsets.
struct OffsetMapper {
    item_map: HashMap<u32, u32>,
    /// `(old_start, new_start)` sorted by `old_start` for opaque sections shifted rigidly.
    opaque_blocks: Vec<(u32, u32, u32)>, // (old_start, old_end, new_start)
    pre_data_shift_from: u32,
    pre_data_shift_delta: u32,
}

impl OffsetMapper {
    fn remap(&self, old_off: u32) -> u32 {
        if old_off == 0 {
            return 0;
        }
        if let Some(&new_off) = self.item_map.get(&old_off) {
            return new_off;
        }
        for &(s, e, ns) in &self.opaque_blocks {
            if old_off >= s && old_off < e {
                return ns + (old_off - s);
            }
        }
        if self.pre_data_shift_delta > 0 && old_off >= self.pre_data_shift_from {
            return old_off + self.pre_data_shift_delta;
        }
        old_off
    }
}

/// Compute exact raw byte length of an opaque data section in `dex.data`.
fn opaque_section_byte_len(data: &[u8], type_code: u16, size: u32, off: usize) -> Result<usize> {
    let count = size as usize;
    match type_code {
        TYPE_TYPE_LIST => {
            let mut p = off;
            let mut last_end = off;
            for _ in 0..count {
                p = align_up(p, 4);
                let len = read_u32(data, p) as usize;
                p += 4 + len * 2;
                last_end = p;
            }
            Ok(last_end - off)
        }
        TYPE_ANNOTATION_SET_REF_LIST => {
            let mut p = off;
            for _ in 0..count {
                let sz = read_u32(data, p) as usize;
                p += 4 + sz * 4;
            }
            Ok(p - off)
        }
        TYPE_ANNOTATION_SET_ITEM => {
            let mut p = off;
            for _ in 0..count {
                let sz = read_u32(data, p) as usize;
                p += 4 + sz * 4;
            }
            Ok(p - off)
        }
        TYPE_ANNOTATIONS_DIRECTORY_ITEM => {
            let mut p = off;
            for _ in 0..count {
                let fields_sz = read_u32(data, p + 4) as usize;
                let methods_sz = read_u32(data, p + 8) as usize;
                let params_sz = read_u32(data, p + 12) as usize;
                p += 16 + (fields_sz + methods_sz + params_sz) * 8;
            }
            Ok(p - off)
        }
        TYPE_HIDDENAPI_CLASS_DATA_ITEM => {
            ensure!(off + 4 <= data.len(), "hiddenapi section out of bounds");
            let total_sz = read_u32(data, off) as usize;
            Ok(total_sz)
        }
        TYPE_CALL_SITE_ID_ITEM => Ok(count * 4),
        TYPE_METHOD_HANDLE_ITEM => Ok(count * 8),
        _ => bail!(
            "Unsupported DEX map section type 0x{:04x} during relocation",
            type_code
        ),
    }
}

/// Core relocation engine for a DEX file WITH a `map_list` (`header.map_off != 0`).
/// Supports replacing a `code_item` (or inserting a new `code_item` when deduplicated)
/// AND/OR inserting a new string at sorted index `k`.
fn rebuild_mapped_dex(
    dex: &mut DexFile,
    code_replacement: Option<(usize, u32, u32, CodeItem, bool)>, // (class_def_idx, method_idx, old_code_off, new_code, must_fork_shared)
    insert_str: Option<(usize, String)>, // (sorted_idx k, value)
) -> Result<Option<u32>> {
    let map_off = dex.header.map_off as usize;
    ensure!(map_off != 0, "rebuild_mapped_dex called with map_off == 0");
    let mut map_items = read_map_list(&dex.data, map_off)?;
    map_items.sort_by_key(|m| m.offset);

    let data_off = dex.header.data_off as usize;
    let old_string_ids_end =
        (dex.header.string_ids_off as usize) + (dex.header.string_ids_size as usize) * 4;
    let pre_shift_delta = if insert_str.is_some() { 4u32 } else { 0u32 };
    let shift_str_from = insert_str.as_ref().map(|(k, _)| *k as u32);

    // Prepare prefix `[0 .. data_off]` (plus +4 bytes if inserting a string_id).
    let mut prefix = Vec::with_capacity(data_off + pre_shift_delta as usize);
    if let Some((ins_k, _)) = &insert_str {
        let ins_pos = (dex.header.string_ids_off as usize) + ins_k * 4;
        prefix.extend_from_slice(&dex.data[..ins_pos]);
        prefix.extend_from_slice(&0u32.to_le_bytes()); // placeholder for new string_data_off
        prefix.extend_from_slice(&dex.data[ins_pos..data_off]);
    } else {
        prefix.extend_from_slice(&dex.data[..data_off]);
    }

    // Shift string_idx >= k in pre-data fixed tables (`type_ids`, `proto_ids`, `field_ids`, `method_ids`, `class_defs`).
    if let Some(k) = shift_str_from {
        let new_type_off = (dex.header.type_ids_off + pre_shift_delta) as usize;
        for i in 0..dex.header.type_ids_size as usize {
            let p = new_type_off + i * 4;
            let idx = read_u32(&prefix, p);
            if idx >= k {
                write_u32(&mut prefix, p, idx + 1);
            }
        }
        let new_proto_off = (dex.header.proto_ids_off + pre_shift_delta) as usize;
        for i in 0..dex.header.proto_ids_size as usize {
            let p = new_proto_off + i * 12;
            let idx = read_u32(&prefix, p);
            if idx >= k {
                write_u32(&mut prefix, p, idx + 1);
            }
        }
        let new_field_off = (dex.header.field_ids_off + pre_shift_delta) as usize;
        for i in 0..dex.header.field_ids_size as usize {
            let p = new_field_off + i * 8 + 4;
            let idx = read_u32(&prefix, p);
            if idx >= k {
                write_u32(&mut prefix, p, idx + 1);
            }
        }
        let new_method_off = (dex.header.method_ids_off + pre_shift_delta) as usize;
        for i in 0..dex.header.method_ids_size as usize {
            let p = new_method_off + i * 8 + 4;
            let idx = read_u32(&prefix, p);
            if idx >= k {
                write_u32(&mut prefix, p, idx + 1);
            }
        }
        let new_class_off = (dex.header.class_defs_off + pre_shift_delta) as usize;
        for i in 0..dex.header.class_defs_size as usize {
            let p = new_class_off + i * 32 + 16;
            let idx = read_u32(&prefix, p);
            if idx != NO_INDEX && idx >= k {
                write_u32(&mut prefix, p, idx + 1);
            }
        }
    }

    // Parse all data sections (`offset >= data_off`).
    let mut pre_map_items = Vec::new();
    let mut data_sections = Vec::new();

    for mi in &map_items {
        if (mi.offset as usize) < data_off {
            let mut m = *mi;
            if m.type_code == TYPE_STRING_ID_ITEM && insert_str.is_some() {
                m.size += 1;
            } else if pre_shift_delta > 0 && (m.offset as usize) >= old_string_ids_end {
                m.offset += pre_shift_delta;
            }
            pre_map_items.push(m);
            continue;
        }

        let sec_off = mi.offset as usize;
        match mi.type_code {
            TYPE_CODE_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize);
                let mut replaced_existing = false;
                for _ in 0..mi.size {
                    pos = align_up(pos, 4);
                    let item_off = pos as u32;
                    let mut ci = dex.read_code_item(item_off)?;
                    let raw_len = code_item_raw_len(&dex.data, pos)?;
                    pos += raw_len;

                    if let Some((_, _, old_code_off, ref new_ci, must_fork)) = code_replacement {
                        if item_off == old_code_off && !must_fork {
                            ci = new_ci.clone();
                            replaced_existing = true;
                        }
                    }
                    if let Some(k) = shift_str_from {
                        let _ = shift_string_idx_in_code_item(&mut ci, k)?;
                    }
                    let encoded = DexFile::encode_code_item(&ci);
                    items.push((item_off, ci, encoded));
                }

                // If the modified code_item was shared across multiple methods, fork it into a new slot.
                let mut sec_size = mi.size;
                if let Some((_, _, _, ref new_ci, must_fork)) = code_replacement {
                    if must_fork || !replaced_existing {
                        let mut ci = new_ci.clone();
                        if let Some(k) = shift_str_from {
                            let _ = shift_string_idx_in_code_item(&mut ci, k)?;
                        }
                        let encoded = DexFile::encode_code_item(&ci);
                        // Sentinel old_off = u32::MAX identifies the newly added code_item.
                        items.push((u32::MAX, ci, encoded));
                        sec_size += 1;
                    }
                }

                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: sec_size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::CodeItems { items },
                });
            }
            TYPE_CLASS_DATA_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize);
                for _ in 0..mi.size {
                    let item_off = pos as u32;
                    let cd = dex.read_class_data(item_off)?;
                    let encoded = DexFile::encode_class_data(&cd);
                    pos += encoded.len();
                    items.push((item_off, cd, encoded));
                }
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::ClassDataItems { items },
                });
            }
            TYPE_STRING_DATA_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize + 1);
                for _ in 0..mi.size {
                    let item_off = pos as u32;
                    let len = crate::dex::encoded_string_item_len(&dex.data, pos)?;
                    items.push((Some(item_off), dex.data[pos..pos + len].to_vec()));
                    pos += len;
                }
                let mut sec_size = mi.size;
                if let Some((_, ref s_val)) = insert_str {
                    let encoded = encode_string_data_mutf8(s_val);
                    items.push((None, encoded));
                    sec_size += 1;
                }
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: sec_size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::StringDataItems { items },
                });
            }
            TYPE_DEBUG_INFO_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize);
                for _ in 0..mi.size {
                    let item_off = pos as u32;
                    let (consumed, bytes) =
                        scan_or_shift_debug_info(&dex.data, pos, shift_str_from)?;
                    pos += consumed;
                    items.push((item_off, bytes));
                }
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::VariableItems { items },
                });
            }
            TYPE_ANNOTATION_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize);
                for _ in 0..mi.size {
                    let item_off = pos as u32;
                    let mut out = Vec::new();
                    ensure!(pos < dex.data.len(), "Truncated annotation_item");
                    out.push(dex.data[pos]); // visibility
                    pos += 1;
                    scan_or_shift_encoded_annotation(&dex.data, &mut pos, &mut out, shift_str_from)?;
                    items.push((item_off, out));
                }
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::VariableItems { items },
                });
            }
            TYPE_ENCODED_ARRAY_ITEM => {
                let mut pos = sec_off;
                let mut items = Vec::with_capacity(mi.size as usize);
                for _ in 0..mi.size {
                    let item_off = pos as u32;
                    let mut out = Vec::new();
                    scan_or_shift_encoded_array(&dex.data, &mut pos, &mut out, shift_str_from)?;
                    items.push((item_off, out));
                }
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::VariableItems { items },
                });
            }
            TYPE_MAP_LIST => {
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::MapList,
                });
            }
            other => {
                let len = opaque_section_byte_len(&dex.data, other, mi.size, sec_off)?;
                data_sections.push(DataSection {
                    type_code: mi.type_code,
                    unused: mi.unused,
                    size: mi.size,
                    old_offset: mi.offset,
                    new_offset: 0,
                    kind: DataSectionKind::Opaque {
                        bytes: dex.data[sec_off..sec_off + len].to_vec(),
                    },
                });
            }
        }
    }

    // Target class_data_off and method_idx if code_replacement is active.
    let target_cd_off = code_replacement.as_ref().map(|(c_idx, _, _, _, _)| {
        dex.class_defs[*c_idx].class_data_off
    });

    // Fixed-point layout pass (converges in 1-2 iterations even when ULEB128 code_off changes byte width).
    let mut item_map: HashMap<u32, u32> = HashMap::new();
    let mut new_code_off_result: Option<u32> = None;
    let mut new_str_data_off: Option<u32> = None;
    let mut opaque_blocks = Vec::new();

    for _pass in 0..6 {
        let mut cursor = prefix.len();
        let mut next_item_map = HashMap::new();
        let mut next_opaque_blocks = Vec::new();
        let mut changed = false;

        let mapper = OffsetMapper {
            item_map: item_map.clone(),
            opaque_blocks: opaque_blocks.clone(),
            pre_data_shift_from: old_string_ids_end as u32,
            pre_data_shift_delta: pre_shift_delta,
        };

        for sec in &mut data_sections {
            cursor = align_up(cursor, section_alignment(sec.type_code));
            if sec.new_offset != cursor as u32 {
                sec.new_offset = cursor as u32;
                changed = true;
            }
            match &mut sec.kind {
                DataSectionKind::CodeItems { items } => {
                    for (old_off, _, encoded) in items.iter() {
                        cursor = align_up(cursor, 4);
                        if *old_off == u32::MAX {
                            new_code_off_result = Some(cursor as u32);
                        } else {
                            if let Some((_, _, target_old, _, false)) = code_replacement {
                                if *old_off == target_old {
                                    new_code_off_result = Some(cursor as u32);
                                }
                            }
                            next_item_map.insert(*old_off, cursor as u32);
                        }
                        cursor += encoded.len();
                    }
                }
                DataSectionKind::ClassDataItems { items } => {
                    for (old_cd_off, cd, encoded) in items.iter_mut() {
                        next_item_map.insert(*old_cd_off, cursor as u32);
                        let mut updated_cd = cd.clone();
                        for em in updated_cd
                            .direct_methods
                            .iter_mut()
                            .chain(updated_cd.virtual_methods.iter_mut())
                        {
                            if let Some((_, t_method_idx, t_old_code_off, _, true)) =
                                code_replacement
                            {
                                if target_cd_off == Some(*old_cd_off)
                                    && em.method_idx == t_method_idx
                                    && em.code_off == t_old_code_off
                                {
                                    if let Some(forked) = new_code_off_result {
                                        em.code_off = forked;
                                        continue;
                                    }
                                }
                            }
                            if em.code_off != 0 {
                                em.code_off = mapper.remap(em.code_off);
                            }
                        }
                        let new_enc = DexFile::encode_class_data(&updated_cd);
                        if new_enc.len() != encoded.len() {
                            changed = true;
                        }
                        *encoded = new_enc;
                        cursor += encoded.len();
                    }
                }
                DataSectionKind::StringDataItems { items } => {
                    for (old_off_opt, bytes) in items.iter() {
                        if let Some(old_off) = old_off_opt {
                            next_item_map.insert(*old_off, cursor as u32);
                        } else {
                            new_str_data_off = Some(cursor as u32);
                        }
                        cursor += bytes.len();
                    }
                }
                DataSectionKind::VariableItems { items } => {
                    for (old_off, bytes) in items.iter() {
                        next_item_map.insert(*old_off, cursor as u32);
                        cursor += bytes.len();
                    }
                }
                DataSectionKind::MapList => {
                    cursor += 4 + map_items.len() * 12;
                }
                DataSectionKind::Opaque { bytes } => {
                    next_opaque_blocks.push((
                        sec.old_offset,
                        sec.old_offset + bytes.len() as u32,
                        cursor as u32,
                    ));
                    cursor += bytes.len();
                }
            }
        }

        if next_item_map != item_map {
            changed = true;
        }
        item_map = next_item_map;
        opaque_blocks = next_opaque_blocks;
        if !changed && _pass > 0 {
            break;
        }
    }

    let final_mapper = OffsetMapper {
        item_map,
        opaque_blocks,
        pre_data_shift_from: old_string_ids_end as u32,
        pre_data_shift_delta: pre_shift_delta,
    };

    // Build output buffer.
    let mut out = prefix;
    for sec in &mut data_sections {
        let align = section_alignment(sec.type_code);
        while out.len() % align != 0 {
            out.push(0);
        }
        debug_assert_eq!(out.len(), sec.new_offset as usize);
        match &mut sec.kind {
            DataSectionKind::CodeItems { items } => {
                for (_, ci, encoded) in items.iter() {
                    while out.len() % 4 != 0 {
                        out.push(0);
                    }
                    let ci_start = out.len();
                    out.extend_from_slice(encoded);
                    if ci.debug_info_off != 0 {
                        write_u32(&mut out, ci_start + 8, final_mapper.remap(ci.debug_info_off));
                    }
                }
            }
            DataSectionKind::ClassDataItems { items } => {
                for (_, _, encoded) in items.iter() {
                    out.extend_from_slice(encoded);
                }
            }
            DataSectionKind::StringDataItems { items } => {
                for (_, bytes) in items.iter() {
                    out.extend_from_slice(bytes);
                }
            }
            DataSectionKind::VariableItems { items } => {
                for (_, bytes) in items.iter() {
                    out.extend_from_slice(bytes);
                }
            }
            DataSectionKind::MapList => {
                let map_pos = out.len();
                out.resize(map_pos + 4 + map_items.len() * 12, 0);
            }
            DataSectionKind::Opaque { bytes } => {
                let sec_start = out.len();
                let mut patched_bytes = bytes.clone();
                match sec.type_code {
                    TYPE_ANNOTATION_SET_REF_LIST => {
                        let mut p = 0;
                        for _ in 0..sec.size {
                            let cnt = read_u32(&patched_bytes, p) as usize;
                            p += 4;
                            for _ in 0..cnt {
                                let old_v = read_u32(&patched_bytes, p);
                                write_u32(&mut patched_bytes, p, final_mapper.remap(old_v));
                                p += 4;
                            }
                        }
                    }
                    TYPE_ANNOTATION_SET_ITEM => {
                        let mut p = 0;
                        for _ in 0..sec.size {
                            let cnt = read_u32(&patched_bytes, p) as usize;
                            p += 4;
                            for _ in 0..cnt {
                                let old_v = read_u32(&patched_bytes, p);
                                write_u32(&mut patched_bytes, p, final_mapper.remap(old_v));
                                p += 4;
                            }
                        }
                    }
                    TYPE_ANNOTATIONS_DIRECTORY_ITEM => {
                        let mut p = 0;
                        for _ in 0..sec.size {
                            let cls_ann = read_u32(&patched_bytes, p);
                            if cls_ann != 0 {
                                write_u32(&mut patched_bytes, p, final_mapper.remap(cls_ann));
                            }
                            let f_sz = read_u32(&patched_bytes, p + 4) as usize;
                            let m_sz = read_u32(&patched_bytes, p + 8) as usize;
                            let p_sz = read_u32(&patched_bytes, p + 12) as usize;
                            p += 16;
                            for _ in 0..(f_sz + m_sz + p_sz) {
                                let old_v = read_u32(&patched_bytes, p + 4);
                                write_u32(&mut patched_bytes, p + 4, final_mapper.remap(old_v));
                                p += 8;
                            }
                        }
                    }
                    TYPE_CALL_SITE_ID_ITEM => {
                        for i in 0..sec.size as usize {
                            let old_v = read_u32(&patched_bytes, i * 4);
                            write_u32(&mut patched_bytes, i * 4, final_mapper.remap(old_v));
                        }
                    }
                    _ => {}
                }
                let _ = sec_start;
                out.extend_from_slice(&patched_bytes);
            }
        }
    }

    // Write map_list bytes into its reserved section slot.
    let new_map_off = data_sections
        .iter()
        .find(|s| s.type_code == TYPE_MAP_LIST)
        .map(|s| s.new_offset)
        .unwrap_or(0);
    if new_map_off != 0 {
        let mut final_map = Vec::with_capacity(pre_map_items.len() + data_sections.len());
        final_map.extend_from_slice(&pre_map_items);
        for s in &data_sections {
            final_map.push(MapItem {
                type_code: s.type_code,
                unused: s.unused,
                size: s.size,
                offset: s.new_offset,
            });
        }
        final_map.sort_by_key(|m| m.offset);
        let mp = new_map_off as usize;
        write_u32(&mut out, mp, final_map.len() as u32);
        for (i, m) in final_map.iter().enumerate() {
            let p = mp + 4 + i * 12;
            write_u16(&mut out, p, m.type_code);
            write_u16(&mut out, p + 2, m.unused);
            write_u32(&mut out, p + 4, m.size);
            write_u32(&mut out, p + 8, m.offset);
        }
    }

    // Copy optional `link_data` if present at old `link_off`.
    let new_link_off = if dex.header.link_size > 0 && dex.header.link_off != 0 {
        let lo = dex.header.link_off as usize;
        let ls = dex.header.link_size as usize;
        let new_lo = out.len() as u32;
        if lo + ls <= dex.data.len() {
            out.extend_from_slice(&dex.data[lo..lo + ls]);
        }
        new_lo
    } else {
        0
    };

    // Update header offsets and sizes.
    let new_str_count = dex.header.string_ids_size + if insert_str.is_some() { 1 } else { 0 };
    write_u32(&mut out, 0x30, new_link_off);
    write_u32(&mut out, 0x34, new_map_off);
    write_u32(&mut out, 0x38, new_str_count);
    if pre_shift_delta > 0 {
        for hdr_off in [0x44usize, 0x4C, 0x54, 0x5C, 0x64, 0x6C] {
            let v = read_u32(&out, hdr_off);
            if v != 0 {
                write_u32(&mut out, hdr_off, v + pre_shift_delta);
            }
        }
    }

    // Update `string_ids` offsets (plus newly inserted string_id_item if any).
    let str_ids_off = read_u32(&out, 0x3C) as usize;
    let ins_idx = insert_str.as_ref().map(|(k, _)| *k);
    for i in 0..new_str_count as usize {
        let p = str_ids_off + i * 4;
        if Some(i) == ins_idx {
            let s_off = new_str_data_off.context("Missing offset for inserted string_data_item")?;
            write_u32(&mut out, p, s_off);
        } else {
            let old_s_off = read_u32(&out, p);
            write_u32(&mut out, p, final_mapper.remap(old_s_off));
        }
    }

    // Update `proto_ids[i].parameters_off`.
    let proto_off = read_u32(&out, 0x4C) as usize;
    let proto_cnt = read_u32(&out, 0x48) as usize;
    for i in 0..proto_cnt {
        let p = proto_off + i * 12 + 8;
        let old_p = read_u32(&out, p);
        if old_p != 0 {
            write_u32(&mut out, p, final_mapper.remap(old_p));
        }
    }

    // Update `class_defs[i]` offsets (`interfaces_off`, `annotations_off`, `class_data_off`, `static_values_off`).
    let class_defs_off = read_u32(&out, 0x64) as usize;
    let class_cnt = read_u32(&out, 0x60) as usize;
    for i in 0..class_cnt {
        let base = class_defs_off + i * 32;
        for field_off in [12usize, 20, 24, 28] {
            let old_v = read_u32(&out, base + field_off);
            if old_v != 0 {
                write_u32(&mut out, base + field_off, final_mapper.remap(old_v));
            }
        }
    }

    // Update `call_site_ids` if placed BEFORE `data_off` (in prefix).
    for m in &pre_map_items {
        if m.type_code == TYPE_CALL_SITE_ID_ITEM {
            let base = m.offset as usize;
            for i in 0..m.size as usize {
                let old_v = read_u32(&out, base + i * 4);
                write_u32(&mut out, base + i * 4, final_mapper.remap(old_v));
            }
        }
    }

    let new_data_off = read_u32(&out, 0x6C);
    let file_size = out.len() as u32;
    let data_size = file_size - new_data_off;
    write_u32(&mut out, 0x20, file_size);
    write_u32(&mut out, 0x68, data_size);

    // Reload DexFile fields cleanly.
    let updated = DexFile::parse(out)?;
    *dex = updated;
    dex.update_hashes();

    if let Some((k, _)) = insert_str {
        Ok(Some(k as u32))
    } else {
        Ok(new_code_off_result)
    }
}

/// Encode MUTF-8 `string_data_item` with exact UTF-16 code unit length prefix + MUTF-8 + NUL.
pub fn encode_string_data_mutf8(s: &str) -> Vec<u8> {
    let utf16_len = s.encode_utf16().count() as u32;
    let mut out = Vec::with_capacity(5 + s.len() + 1);
    write_uleb128(&mut out, utf16_len);
    out.extend_from_slice(&encode_mutf8_raw(s));
    out.push(0);
    out
}

/// Rewrite a `code_item` on a mapped DEX (`header.map_off != 0`) while keeping `map_list` consistent.
pub fn rewrite_code_item_with_map(
    dex: &mut DexFile,
    class_def_idx: usize,
    method_idx: u32,
    old_code: &CodeItem,
    new_code: &CodeItem,
) -> Result<u32> {
    let ref_count = count_code_off_refs(dex, old_code.offset as u32)?;
    let must_fork = ref_count > 1;
    let res = rebuild_mapped_dex(
        dex,
        Some((class_def_idx, method_idx, old_code.offset as u32, new_code.clone(), must_fork)),
        None,
    )?;
    res.context("Failed to locate rewritten code_item offset")
}

/// Find `s` in `dex.strings` or insert it in strict MUTF-8 sorted order into `string_ids`.
pub fn add_or_get_string(dex: &mut DexFile, s: &str) -> Result<u32> {
    if let Some(idx) = dex.strings.iter().position(|existing| existing == s) {
        return Ok(idx as u32);
    }

    let target_mutf8 = encode_mutf8_raw(s);
    let mut insert_k = dex.strings.len();
    for (i, &s_off) in dex.string_offsets.iter().enumerate() {
        let existing_bytes = raw_mutf8_bytes_at(&dex.data, s_off as usize)?;
        match existing_bytes.cmp(target_mutf8.as_slice()) {
            std::cmp::Ordering::Equal => return Ok(i as u32),
            std::cmp::Ordering::Greater => {
                insert_k = i;
                break;
            }
            std::cmp::Ordering::Less => {}
        }
    }

    if dex.header.map_off != 0 {
        let idx = rebuild_mapped_dex(dex, None, Some((insert_k, s.to_string())))?
            .context("insert_string returned None")?;
        return Ok(idx);
    }

    // Synthetic DEX (`map_off == 0`): insert into `string_ids`, shift pre-data tables + data offsets,
    // update all string_idx >= insert_k references, and append string_data_item at end.
    insert_string_unmapped(dex, insert_k, s)
}

fn insert_string_unmapped(dex: &mut DexFile, insert_k: usize, s: &str) -> Result<u32> {
    let data_off = dex.header.data_off as usize;
    let ins_pos = (dex.header.string_ids_off as usize) + insert_k * 4;
    let k = insert_k as u32;
    let delta = 4u32;

    // Collect every existing CodeItem and ClassData before mutating offsets.
    let mut class_infos = Vec::with_capacity(dex.class_defs.len());
    for cd in &dex.class_defs {
        if cd.class_data_off == 0 {
            class_infos.push(None);
            continue;
        }
        let mut class_data = dex.read_class_data(cd.class_data_off)?;
        let mut method_codes = Vec::new();
        for m in class_data
            .direct_methods
            .iter_mut()
            .chain(class_data.virtual_methods.iter_mut())
        {
            if m.code_off != 0 {
                let mut ci = dex.read_code_item(m.code_off)?;
                let changed = shift_string_idx_in_code_item(&mut ci, k)?;
                method_codes.push((m.method_idx, m.code_off, ci, changed));
            }
        }
        class_infos.push(Some((cd.class_data_off, class_data, method_codes)));
    }

    let mut out = Vec::with_capacity(dex.data.len() + 64);
    out.extend_from_slice(&dex.data[..ins_pos]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&dex.data[ins_pos..]);

    // Update header sizes/offsets
    write_u32(&mut out, 0x38, dex.header.string_ids_size + 1);
    for hdr_off in [0x44usize, 0x4C, 0x54, 0x5C, 0x64, 0x6C] {
        let v = read_u32(&out, hdr_off);
        if v != 0 {
            write_u32(&mut out, hdr_off, v + delta);
        }
    }

    // Update type_ids, proto_ids, field_ids, method_ids, class_defs string_idx & data offsets
    let new_type_off = (dex.header.type_ids_off + delta) as usize;
    for i in 0..dex.header.type_ids_size as usize {
        let p = new_type_off + i * 4;
        let idx = read_u32(&out, p);
        if idx >= k {
            write_u32(&mut out, p, idx + 1);
        }
    }
    let new_proto_off = (dex.header.proto_ids_off + delta) as usize;
    for i in 0..dex.header.proto_ids_size as usize {
        let p = new_proto_off + i * 12;
        let idx = read_u32(&out, p);
        if idx >= k {
            write_u32(&mut out, p, idx + 1);
        }
        let p_off = read_u32(&out, p + 8);
        if p_off >= data_off as u32 {
            write_u32(&mut out, p + 8, p_off + delta);
        }
    }
    let new_field_off = (dex.header.field_ids_off + delta) as usize;
    for i in 0..dex.header.field_ids_size as usize {
        let p = new_field_off + i * 8 + 4;
        let idx = read_u32(&out, p);
        if idx >= k {
            write_u32(&mut out, p, idx + 1);
        }
    }
    let new_method_off = (dex.header.method_ids_off + delta) as usize;
    for i in 0..dex.header.method_ids_size as usize {
        let p = new_method_off + i * 8 + 4;
        let idx = read_u32(&out, p);
        if idx >= k {
            write_u32(&mut out, p, idx + 1);
        }
    }
    let new_class_off = (dex.header.class_defs_off + delta) as usize;
    for i in 0..dex.header.class_defs_size as usize {
        let base = new_class_off + i * 32;
        let sf = read_u32(&out, base + 16);
        if sf != NO_INDEX && sf >= k {
            write_u32(&mut out, base + 16, sf + 1);
        }
        for f_off in [12usize, 20, 24, 28] {
            let v = read_u32(&out, base + f_off);
            if v >= data_off as u32 {
                write_u32(&mut out, base + f_off, v + delta);
            }
        }
    }

    // Shift string_offsets >= data_off and append new string_data_item
    let new_str_data_off = out.len() as u32;
    out.extend_from_slice(&encode_string_data_mutf8(s));
    let str_ids_off = dex.header.string_ids_off as usize;
    for i in 0..(dex.header.string_ids_size as usize + 1) {
        let p = str_ids_off + i * 4;
        if i == insert_k {
            write_u32(&mut out, p, new_str_data_off);
        } else {
            let v = read_u32(&out, p);
            if v >= data_off as u32 {
                write_u32(&mut out, p, v + delta);
            }
        }
    }

    // Re-encode ClassData items (at shifted or newly appended offsets because ULEB128 code_off increased by +4)
    let mut updated_dex = DexFile::parse(out)?;
    for (c_idx, info_opt) in class_infos.into_iter().enumerate() {
        let Some((_, mut cd, method_codes)) = info_opt else {
            continue;
        };
        let mut new_codes: BTreeMap<u32, u32> = BTreeMap::new();
        for (m_idx, old_c_off, mut ci, changed) in method_codes {
            let shifted_c_off = old_c_off + delta;
            if ci.debug_info_off != 0 {
                ci.debug_info_off += delta;
            }
            if !changed {
                if ci.debug_info_off != 0 {
                    write_u32(&mut updated_dex.data, shifted_c_off as usize + 8, ci.debug_info_off);
                }
                new_codes.insert(m_idx, shifted_c_off);
            } else {
                let encoded = DexFile::encode_code_item(&ci);
                let old_encoded_len = code_item_raw_len(&updated_dex.data, shifted_c_off as usize)?;
                if encoded.len() <= old_encoded_len {
                    updated_dex.data[shifted_c_off as usize..shifted_c_off as usize + encoded.len()]
                        .copy_from_slice(&encoded);
                    new_codes.insert(m_idx, shifted_c_off);
                } else {
                    while updated_dex.data.len() % 4 != 0 {
                        updated_dex.data.push(0);
                    }
                    let appended_off = updated_dex.data.len() as u32;
                    updated_dex.data.extend_from_slice(&encoded);
                    new_codes.insert(m_idx, appended_off);
                }
            }
        }
        for em in cd
            .direct_methods
            .iter_mut()
            .chain(cd.virtual_methods.iter_mut())
        {
            if let Some(&nc) = new_codes.get(&em.method_idx) {
                em.code_off = nc;
            }
        }
        let encoded_cd = DexFile::encode_class_data(&cd);
        let new_cd_off = updated_dex.data.len() as u32;
        updated_dex.data.extend_from_slice(&encoded_cd);
        let def_off = updated_dex.class_defs[c_idx].def_offset;
        write_u32(&mut updated_dex.data, def_off + 24, new_cd_off);
        updated_dex.class_defs[c_idx].class_data_off = new_cd_off;
    }

    updated_dex.reload_tables()?;
    updated_dex.update_hashes();
    *dex = updated_dex;
    let _ = decode_string_at; // silence unused warning if any
    Ok(k)
}
