//! In-memory ARSC (`resources.arsc`) parser and patcher.
//!
//! Fixes invalid `val_type == 0x02` (`TYPE_ATTRIBUTE`) references that point to framework
//! color tokens in the `0x0196xxxx` range. In modern Android (Android 14+ / U/V/16/17),
//! Google allocated Monet dynamic colors under package `0x01` and type `0x96`.
//! Decompilation tools such as `APKEditor` often misclassify these color IDs as theme
//! attributes, writing `val_type = 0x02` into `resources.arsc`, which crashes `TypedArray`
//! with `UnsupportedOperationException: Failed to resolve attribute at index...` at runtime
//! (particularly prominent in dark mode / night themes).
//!
//! This module traverses the binary ARSC chunk hierarchy (`RES_TABLE_TYPE` 0x0002,
//! `RES_TABLE_PACKAGE_TYPE` 0x0200, `RES_TABLE_TYPE_TYPE` 0x0201) and patches any
//! `TYPE_ATTRIBUTE` (0x02) targeting `0x0196xxxx` to `TYPE_REFERENCE` (0x01).

/// Patch all invalid `TYPE_ATTRIBUTE` (0x02) references pointing to `0x0196xxxx`
/// in an in-memory `resources.arsc` buffer.
///
/// Handles simple, map/style and compact entries with dense, sparse or 16-bit
/// offset tables. Malformed chunks and entries are skipped without writing
/// outside the declaring chunk.
///
/// Returns the number of entries patched.
pub fn patch_arsc_buffer(data: &mut [u8]) -> usize {
    patch_arsc_chunk(data)
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn patch_arsc_chunk(data: &mut [u8]) -> usize {
    if data.len() < 8 {
        return 0;
    }
    let chunk_type = read_u16(data, 0);
    let header_size = read_u16(data, 2) as usize;
    let chunk_size = read_u32(data, 4) as usize;

    if header_size < 8 || header_size > chunk_size || chunk_size > data.len() {
        return 0;
    }
    // Keep all offsets bounded by this chunk, including nested chunks.
    let chunk = &mut data[..chunk_size];

    match chunk_type {
        // RES_TABLE_TYPE (0x0002) or RES_TABLE_PACKAGE_TYPE (0x0200)
        0x0002 | 0x0200 => {
            let mut patched_count = 0;
            let mut sub = header_size;
            // Tables contain packages; packages contain types. Restricting the
            // hierarchy also prevents unbounded recursion on malformed input.
            let child_type = if chunk_type == 0x0002 { 0x0200 } else { 0x0201 };
            while chunk.len() - sub >= 8 {
                let sub_size = read_u32(chunk, sub + 4) as usize;
                if sub_size < 8 || sub_size > chunk.len() - sub {
                    break;
                }
                if read_u16(chunk, sub) == child_type {
                    patched_count += patch_arsc_chunk(&mut chunk[sub..sub + sub_size]);
                }
                sub += sub_size;
            }
            patched_count
        }
        // RES_TABLE_TYPE_TYPE (0x0201)
        0x0201 => patch_type_chunk(chunk, header_size),
        _ => 0,
    }
}

fn patch_type_chunk(chunk: &mut [u8], header_size: usize) -> usize {
    if header_size < 20 {
        return 0;
    }
    let flags = chunk[9];
    // FLAG_SPARSE and FLAG_OFFSET16 are mutually exclusive index encodings.
    if flags & !0x03 != 0 || flags == 0x03 {
        return 0;
    }
    let entry_count = read_u32(chunk, 12) as usize;
    let entries_start = read_u32(chunk, 16) as usize;
    let index_width = if flags == 0x02 { 2 } else { 4 };
    let Some(index_end) = entry_count
        .checked_mul(index_width)
        .and_then(|size| header_size.checked_add(size))
    else {
        return 0;
    };
    if entries_start < index_end || entries_start > chunk.len() {
        return 0;
    }

    let mut patched_count = 0;
    for entry_idx in 0..entry_count {
        let off_pos = header_size + entry_idx * index_width;
        let entry_offset = match flags {
            0x01 => read_u16(chunk, off_pos + 2) as usize * 4, // sparse ID/offset pair
            0x02 => {
                let offset = read_u16(chunk, off_pos);
                if offset == u16::MAX {
                    continue;
                }
                offset as usize * 4
            }
            _ => {
                let offset = read_u32(chunk, off_pos);
                if offset == u32::MAX {
                    continue;
                }
                offset as usize
            }
        };
        let Some(entry_start) = entries_start.checked_add(entry_offset) else {
            continue;
        };
        if let Some(entry) = chunk.get_mut(entry_start..) {
            patched_count += patch_entry(entry);
        }
    }
    patched_count
}

fn patch_entry(entry: &mut [u8]) -> usize {
    if entry.len() < 8 {
        return 0;
    }
    // ResTable_entry starts with size/key (u16), then flags (u16).
    // See AOSP ResourceTypes.h: ResTable_entry and ResTable_map_entry.
    let flags = read_u16(entry, 2);
    let is_complex = flags & 0x0001 != 0;
    if flags & 0x0008 != 0 {
        // FLAG_COMPACT stores dataType in the high byte of flags and the
        // value in the entry itself. A compact entry cannot contain a map.
        return if is_complex {
            0
        } else {
            patch_attribute(&mut entry[..8])
        };
    }

    let header_size = read_u16(entry, 0) as usize;
    if header_size < 8 || header_size > entry.len() {
        return 0;
    }
    if !is_complex {
        return patch_value(&mut entry[header_size..]);
    }
    if header_size < 16 {
        return 0;
    }
    let map_count = read_u32(entry, 12) as usize;
    if map_count > (entry.len() - header_size) / 12 {
        return 0;
    }
    entry[header_size..header_size + map_count * 12]
        .chunks_exact_mut(12)
        .map(|map| patch_value(&mut map[4..]))
        .sum()
}

fn patch_value(value: &mut [u8]) -> usize {
    if value.len() < 8 {
        return 0;
    }
    let size = read_u16(value, 0) as usize;
    if size < 8 || size > value.len() {
        return 0;
    }
    patch_attribute(value)
}

fn patch_attribute(value: &mut [u8]) -> usize {
    // Both Res_value and a compact ResTable_entry place dataType at byte 3
    // and data at byte 4. Preserve every other byte, including entry flags.
    if value[3] == 0x02 && (read_u32(value, 4) >> 16) == 0x0196 {
        value[3] = 0x01; // TYPE_ATTRIBUTE -> TYPE_REFERENCE
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(data_type: u8, data: u32) -> Vec<u8> {
        let mut value = vec![8, 0, 0, data_type];
        value.extend_from_slice(&data.to_le_bytes());
        value
    }

    fn simple_entry(header_size: u16, value: &[u8]) -> Vec<u8> {
        let mut entry = vec![0xa5; header_size as usize];
        entry[..2].copy_from_slice(&header_size.to_le_bytes());
        entry[2..4].copy_from_slice(&2u16.to_le_bytes()); // FLAG_PUBLIC
        entry[4..8].copy_from_slice(&3u32.to_le_bytes()); // key index
        entry.extend_from_slice(value);
        entry
    }

    fn style_entry(header_size: u16, values: &[Vec<u8>]) -> Vec<u8> {
        let mut entry = vec![0xa5; header_size as usize];
        entry[..2].copy_from_slice(&header_size.to_le_bytes());
        entry[2..4].copy_from_slice(&3u16.to_le_bytes()); // FLAG_COMPLEX | FLAG_PUBLIC
        entry[4..8].copy_from_slice(&5u32.to_le_bytes()); // key index
        entry[8..12].copy_from_slice(&0x0103_0001u32.to_le_bytes()); // parent
        entry[12..16].copy_from_slice(&(values.len() as u32).to_le_bytes());
        for (index, value) in values.iter().enumerate() {
            entry.extend_from_slice(&(0x0101_0000 + index as u32).to_le_bytes());
            entry.extend_from_slice(value);
        }
        entry
    }

    fn table_with_index(flags: u8, index: &[u8], entries: &[u8]) -> (Vec<u8>, usize) {
        const TYPE_HEADER: usize = 28;
        const PACKAGE_HEADER: usize = 288;
        const TABLE_HEADER: usize = 12;
        let index_width = if flags == 2 { 2 } else { 4 };
        let entries_start = (TYPE_HEADER + index.len() + 3) & !3;
        let type_size = entries_start + entries.len();
        let mut type_chunk = vec![0; entries_start];
        type_chunk[..2].copy_from_slice(&0x0201u16.to_le_bytes());
        type_chunk[2..4].copy_from_slice(&(TYPE_HEADER as u16).to_le_bytes());
        type_chunk[4..8].copy_from_slice(&(type_size as u32).to_le_bytes());
        type_chunk[8] = 6; // type ID
        type_chunk[9] = flags;
        type_chunk[12..16].copy_from_slice(&((index.len() / index_width) as u32).to_le_bytes());
        type_chunk[16..20].copy_from_slice(&(entries_start as u32).to_le_bytes());
        type_chunk[20..24].copy_from_slice(&8u32.to_le_bytes()); // config size
        type_chunk[TYPE_HEADER..TYPE_HEADER + index.len()].copy_from_slice(index);
        type_chunk.extend_from_slice(entries);

        let mut package = vec![0; PACKAGE_HEADER];
        package[..2].copy_from_slice(&0x0200u16.to_le_bytes());
        package[2..4].copy_from_slice(&(PACKAGE_HEADER as u16).to_le_bytes());
        package[4..8].copy_from_slice(&((PACKAGE_HEADER + type_size) as u32).to_le_bytes());
        package[8..12].copy_from_slice(&0x7fu32.to_le_bytes()); // package ID
        package.extend_from_slice(&type_chunk);

        let mut table = vec![0; TABLE_HEADER];
        table[..2].copy_from_slice(&2u16.to_le_bytes());
        table[2..4].copy_from_slice(&(TABLE_HEADER as u16).to_le_bytes());
        table[4..8].copy_from_slice(&((TABLE_HEADER + package.len()) as u32).to_le_bytes());
        table[8..12].copy_from_slice(&1u32.to_le_bytes()); // package count
        table.extend_from_slice(&package);
        (table, TABLE_HEADER + PACKAGE_HEADER + entries_start)
    }

    fn table(entries: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>) {
        let mut index = Vec::new();
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for entry in entries {
            offsets.push(body.len());
            index.extend_from_slice(&(body.len() as u32).to_le_bytes());
            body.extend_from_slice(entry);
        }
        let (data, entries_start) = table_with_index(0, &index, &body);
        (
            data,
            offsets.into_iter().map(|off| entries_start + off).collect(),
        )
    }

    fn assert_patched(mut data: Vec<u8>, value_offsets: &[usize]) {
        let mut expected = data.clone();
        for offset in value_offsets {
            expected[offset + 3] = 1;
        }
        assert_eq!(patch_arsc_buffer(&mut data), value_offsets.len());
        assert_eq!(data, expected, "Only the invalid dataType bytes may change");
        assert_eq!(patch_arsc_buffer(&mut data), 0, "Patch must be idempotent");
    }

    #[test]
    fn test_patch_style_values() {
        let entries = [
            simple_entry(8, &value(2, 0x0196_0018)),
            style_entry(
                16,
                &[
                    value(2, 0x0196_0019),
                    value(2, 0x0101_0001), // legitimate theme attribute
                    value(1, 0x0196_001a), // already a reference
                    value(2, 0x0195_0018), // outside the target range
                ],
            ),
        ];
        let (data, offsets) = table(&entries);
        assert_patched(data, &[offsets[0] + 8, offsets[1] + 16 + 4]);
    }

    #[test]
    fn test_entry_header_sizes() {
        let (data, offsets) = table(&[
            simple_entry(12, &value(2, 0x0196_0018)),
            style_entry(20, &[value(2, 0x0196_0019)]),
        ]);
        assert_patched(data, &[offsets[0] + 12, offsets[1] + 20 + 4]);
    }

    #[test]
    fn test_sparse_and_offset16_indices() {
        let simple = simple_entry(8, &value(2, 0x0196_0018));
        let style = style_entry(16, &[value(2, 0x0196_0019)]);
        let mut entries = simple.clone();
        entries.extend_from_slice(&style);
        for flags in [0, 1, 2] {
            let mut index = Vec::new();
            match flags {
                0 => {
                    index.extend_from_slice(&0u32.to_le_bytes());
                    index.extend_from_slice(&u32::MAX.to_le_bytes()); // NO_ENTRY
                    index.extend_from_slice(&(simple.len() as u32).to_le_bytes());
                }
                1 => {
                    index.extend_from_slice(&3u16.to_le_bytes()); // sparse entry ID
                    index.extend_from_slice(&0u16.to_le_bytes());
                    index.extend_from_slice(&500u16.to_le_bytes()); // non-consecutive ID
                    index.extend_from_slice(&((simple.len() / 4) as u16).to_le_bytes());
                }
                2 => {
                    index.extend_from_slice(&0u16.to_le_bytes());
                    index.extend_from_slice(&u16::MAX.to_le_bytes()); // NO_ENTRY
                    index.extend_from_slice(&((simple.len() / 4) as u16).to_le_bytes());
                }
                _ => unreachable!(),
            }
            let (data, base) = table_with_index(flags, &index, &entries);
            assert_patched(data, &[base + 8, base + simple.len() + 16 + 4]);
        }
    }

    #[test]
    fn test_compact_entry_preserves_key_and_flags() {
        let mut entries = Vec::new();
        for (key, data_type, data) in [(7u16, 2u16, 0x0196_0018u32), (9, 2, 0x0101_0001)] {
            let mut entry = Vec::new();
            entry.extend_from_slice(&key.to_le_bytes());
            entry.extend_from_slice(&((data_type << 8) | 0x0a).to_le_bytes());
            entry.extend_from_slice(&data.to_le_bytes());
            entries.push(entry);
        }
        let (data, offsets) = table(&entries);
        assert_patched(data, &[offsets[0]]);
    }

    #[test]
    fn test_malformed_data_is_unchanged() {
        let (valid, offsets) = table(&[simple_entry(8, &value(2, 0x0196_0018))]);
        const TYPE_START: usize = 12 + 288;
        let mut cases = Vec::new();
        for (offset, bytes) in [
            (2, 0u16.to_le_bytes().to_vec()), // invalid container header
            (4, 7u32.to_le_bytes().to_vec()), // chunk smaller than its header
            (12 + 4, (valid.len() as u32).to_le_bytes().to_vec()), // child exceeds parent
            (TYPE_START + 12, u32::MAX.to_le_bytes().to_vec()), // oversized index table
            (TYPE_START + 16, 0u32.to_le_bytes().to_vec()), // entries overlap header
            (TYPE_START + 28, (u32::MAX - 1).to_le_bytes().to_vec()), // invalid entry offset
            (offsets[0], u16::MAX.to_le_bytes().to_vec()), // oversized entry header
            (offsets[0] + 8, 7u16.to_le_bytes().to_vec()), // undersized Res_value
        ] {
            let mut data = valid.clone();
            data[offset..offset + bytes.len()].copy_from_slice(&bytes);
            cases.push(data);
        }
        let (mut bad_style, style_offsets) = table(&[style_entry(16, &[value(2, 0x0196_0018)])]);
        bad_style[style_offsets[0] + 12..style_offsets[0] + 16]
            .copy_from_slice(&2u32.to_le_bytes());
        cases.push(bad_style); // map count exceeds the available maps
        for flags in [3, 0x80] {
            let mut data = valid.clone();
            data[TYPE_START + 9] = flags;
            cases.push(data);
        }
        for mut data in cases {
            let expected = data.clone();
            assert_eq!(patch_arsc_buffer(&mut data), 0);
            assert_eq!(data, expected);
        }
        for len in 0..valid.len() {
            let mut truncated = valid[..len].to_vec();
            let expected = truncated.clone();
            assert_eq!(patch_arsc_buffer(&mut truncated), 0);
            assert_eq!(truncated, expected);
        }
    }

    #[test]
    fn test_patch_arsc_buffer() {
        let (data, offsets) = table(&[
            simple_entry(8, &value(2, 0x0196_0018)),
            simple_entry(8, &value(2, 0x0101_0001)), // legitimate theme attribute
            simple_entry(8, &value(1, 0x0196_0018)), // already a reference
        ]);
        assert_patched(data, &[offsets[0] + 8]);
    }
}
