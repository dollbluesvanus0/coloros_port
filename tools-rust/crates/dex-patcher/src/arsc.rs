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
/// Returns the number of entries patched.
pub fn patch_arsc_buffer(data: &mut [u8]) -> usize {
    let mut patched_count = 0;
    patch_arsc_chunk(data, 0, &mut patched_count);
    patched_count
}

fn patch_arsc_chunk(data: &mut [u8], pos: usize, patched_count: &mut usize) {
    if pos + 8 > data.len() {
        return;
    }
    let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
    let header_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
    let chunk_size = u32::from_le_bytes([
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]) as usize;

    if chunk_size == 0 || pos.checked_add(chunk_size).map_or(true, |end| end > data.len()) {
        return;
    }

    match chunk_type {
        // RES_TABLE_TYPE (0x0002) or RES_TABLE_PACKAGE_TYPE (0x0200)
        0x0002 | 0x0200 => {
            let mut sub = pos + header_size;
            let end = pos + chunk_size;
            while sub + 8 <= end {
                let sub_size = u32::from_le_bytes([
                    data[sub + 4],
                    data[sub + 5],
                    data[sub + 6],
                    data[sub + 7],
                ]) as usize;
                if sub_size == 0 || sub.checked_add(sub_size).map_or(true, |se| se > end) {
                    break;
                }
                patch_arsc_chunk(data, sub, patched_count);
                sub += sub_size;
            }
        }
        // RES_TABLE_TYPE_TYPE (0x0201)
        0x0201 => {
            if header_size < 20 || header_size > chunk_size {
                return;
            }
            let entry_count = u32::from_le_bytes([
                data[pos + 12],
                data[pos + 13],
                data[pos + 14],
                data[pos + 15],
            ]) as usize;
            let entries_start = u32::from_le_bytes([
                data[pos + 16],
                data[pos + 17],
                data[pos + 18],
                data[pos + 19],
            ]) as usize;

            let end = pos + chunk_size;
            for entry_idx in 0..entry_count {
                let off_pos = pos + header_size + entry_idx * 4;
                if off_pos + 4 > end {
                    break;
                }
                let eoff = u32::from_le_bytes([
                    data[off_pos],
                    data[off_pos + 1],
                    data[off_pos + 2],
                    data[off_pos + 3],
                ]);
                if eoff == 0xffff_ffff {
                    continue;
                }

                let ep = pos + entries_start + (eoff as usize);
                if ep + 16 > end {
                    continue;
                }
                let flags = u16::from_le_bytes([data[ep], data[ep + 1]]);
                let is_complex = (flags & 0x0001) != 0;

                if !is_complex {
                    // Simple entry: Res_value starts at ep + 8
                    // ep + 8..ep + 10: size (u16)
                    // ep + 10: res0 (u8)
                    // ep + 11: dataType (u8)
                    // ep + 12..ep + 16: data (u32)
                    let val_type = data[ep + 11];
                    let val_data = u32::from_le_bytes([
                        data[ep + 12],
                        data[ep + 13],
                        data[ep + 14],
                        data[ep + 15],
                    ]);

                    // If TYPE_ATTRIBUTE (0x02) points to 0x0196xxxx (dynamic colors),
                    // patch to TYPE_REFERENCE (0x01)
                    if val_type == 0x02 && (val_data >> 16) == 0x0196 {
                        data[ep + 11] = 0x01; // TYPE_REFERENCE
                        *patched_count += 1;
                    }
                } else {
                    // Complex (map / style) entry:
                    // ep + 8..ep + 12: parent res id
                    // ep + 12..ep + 16: count of map entries
                    let map_count = u32::from_le_bytes([
                        data[ep + 12],
                        data[ep + 13],
                        data[ep + 14],
                        data[ep + 15],
                    ]) as usize;

                    for m in 0..map_count {
                        let mp = ep + 16 + m * 12;
                        if mp + 12 > end {
                            break;
                        }
                        // Map entry Res_value is at mp + 4
                        // mp + 4..mp + 6: size
                        // mp + 6: res0
                        // mp + 7: dataType
                        // mp + 8..mp + 12: data
                        let val_type = data[mp + 7];
                        let val_data = u32::from_le_bytes([
                            data[mp + 8],
                            data[mp + 9],
                            data[mp + 10],
                            data[mp + 11],
                        ]);

                        if val_type == 0x02 && (val_data >> 16) == 0x0196 {
                            data[mp + 7] = 0x01; // TYPE_REFERENCE
                            *patched_count += 1;
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_arsc_buffer() {
        // Construct a synthetic ARSC structure:
        // RES_TABLE_TYPE (0x0002) containing RES_TABLE_PACKAGE_TYPE (0x0200)
        // containing RES_TABLE_TYPE_TYPE (0x0201)
        let header_size_type = 28usize;
        let entry_count = 2usize;
        let entries_start = header_size_type + entry_count * 4; // 28 + 8 = 36
        let entry0_data = [
            0x00, 0x00, // flags = simple (0)
            0x00, 0x00, // key index
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, // size = 8
            0x00,       // res0
            0x02,       // dataType = TYPE_ATTRIBUTE (0x02) -> should be patched
            0x18, 0x00, 0x96, 0x01, // data = 0x01960018
        ];
        let entry1_data = [
            0x00, 0x00, // flags = simple (0)
            0x01, 0x00, // key index
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, // size = 8
            0x00,       // res0
            0x02,       // dataType = TYPE_ATTRIBUTE (0x02) with 0x01010001 -> legitimate attribute, leave alone
            0x01, 0x00, 0x01, 0x01, // data = 0x01010001
        ];

        let type_chunk_size = (entries_start + entry0_data.len() + entry1_data.len()) as u32;
        let mut type_chunk = Vec::new();
        type_chunk.extend_from_slice(&0x0201u16.to_le_bytes()); // type
        type_chunk.extend_from_slice(&(header_size_type as u16).to_le_bytes()); // header_size
        type_chunk.extend_from_slice(&type_chunk_size.to_le_bytes()); // chunk_size
        type_chunk.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // id=6, res0, res1
        type_chunk.extend_from_slice(&(entry_count as u32).to_le_bytes()); // entry_count
        type_chunk.extend_from_slice(&(entries_start as u32).to_le_bytes()); // entries_start
        type_chunk.extend_from_slice(&[0u8; 8]); // config padding to 28 bytes
        assert_eq!(type_chunk.len(), header_size_type);

        // Offsets table
        type_chunk.extend_from_slice(&0u32.to_le_bytes()); // entry 0 offset relative to entries_start
        type_chunk.extend_from_slice(&(entry0_data.len() as u32).to_le_bytes()); // entry 1 offset

        // Entries
        type_chunk.extend_from_slice(&entry0_data);
        type_chunk.extend_from_slice(&entry1_data);
        assert_eq!(type_chunk.len(), type_chunk_size as usize);

        // Package chunk
        let pkg_header_size = 16usize;
        let pkg_chunk_size = (pkg_header_size + type_chunk.len()) as u32;
        let mut pkg_chunk = Vec::new();
        pkg_chunk.extend_from_slice(&0x0200u16.to_le_bytes());
        pkg_chunk.extend_from_slice(&(pkg_header_size as u16).to_le_bytes());
        pkg_chunk.extend_from_slice(&pkg_chunk_size.to_le_bytes());
        pkg_chunk.extend_from_slice(&[0u8; 8]); // package header fields
        pkg_chunk.extend_from_slice(&type_chunk);

        // Table chunk
        let table_header_size = 12usize;
        let table_chunk_size = (table_header_size + pkg_chunk.len()) as u32;
        let mut table = Vec::new();
        table.extend_from_slice(&0x0002u16.to_le_bytes());
        table.extend_from_slice(&(table_header_size as u16).to_le_bytes());
        table.extend_from_slice(&table_chunk_size.to_le_bytes());
        table.extend_from_slice(&1u32.to_le_bytes()); // package_count
        table.extend_from_slice(&pkg_chunk);

        // Run patch
        let patched = patch_arsc_buffer(&mut table);
        assert_eq!(patched, 1, "Exactly 1 bad attribute should be patched");

        // Verify entry 0 changed to TYPE_REFERENCE (0x01)
        let ep0 = table_header_size + pkg_header_size + entries_start;
        assert_eq!(table[ep0 + 11], 0x01, "Entry 0 should now be TYPE_REFERENCE");

        // Verify entry 1 remained TYPE_ATTRIBUTE (0x02)
        let ep1 = ep0 + entry0_data.len();
        assert_eq!(table[ep1 + 11], 0x02, "Entry 1 should still be TYPE_ATTRIBUTE");

        // Second pass should patch 0 (idempotent)
        let second_pass = patch_arsc_buffer(&mut table);
        assert_eq!(second_pass, 0, "Second pass must be a no-op");
    }
}
