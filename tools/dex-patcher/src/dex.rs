#![allow(dead_code)]
use sha1::{Digest, Sha1};

pub fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

pub fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

pub fn write_u16(data: &mut [u8], off: usize, val: u16) {
    let bytes = val.to_le_bytes();
    data[off] = bytes[0];
    data[off + 1] = bytes[1];
}

pub fn write_u32(data: &mut [u8], off: usize, val: u32) {
    let bytes = val.to_le_bytes();
    data[off] = bytes[0];
    data[off + 1] = bytes[1];
    data[off + 2] = bytes[2];
    data[off + 3] = bytes[3];
}

pub fn read_uleb128(data: &[u8], off: &mut usize) -> u32 {
    let mut result = 0u32;
    let mut shift = 0;
    loop {
        let byte = data[*off];
        *off += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    result
}

pub fn read_string(data: &[u8], string_ids_off: usize, string_idx: usize) -> String {
    let off = read_u32(data, string_ids_off + string_idx * 4) as usize;
    let mut cursor = off;
    let _utf16_len = read_uleb128(data, &mut cursor);
    let mut end = cursor;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[cursor..end]).to_string()
}

pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    const MOD_ADLER: u32 = 65521;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

pub fn update_dex_checksums(data: &mut [u8]) {
    // 1. SHA-1 signature over bytes 32..end
    let mut hasher = Sha1::new();
    hasher.update(&data[32..]);
    let hash = hasher.finalize();
    data[12..32].copy_from_slice(&hash);

    // 2. Adler-32 checksum over bytes 12..end
    let checksum = adler32(&data[12..]);
    write_u32(data, 8, checksum);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnType {
    Void,
    True,
    False,
}

impl ReturnType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "void" | "return-void" | "v" => Some(ReturnType::Void),
            "true" | "1" => Some(ReturnType::True),
            "false" | "0" => Some(ReturnType::False),
            _ => None,
        }
    }
}

pub struct PatchResult {
    pub class_name: String,
    pub method_name: String,
    pub return_type: ReturnType,
    pub code_off: usize,
}

pub fn patch_dex_bytes(
    data: &mut [u8],
    class_pattern: &str,
    target_method: &str,
    ret: ReturnType,
) -> Vec<PatchResult> {
    let mut results = Vec::new();

    if data.len() < 112 || &data[0..4] != b"dex\n" {
        return results;
    }

    let string_ids_off = read_u32(data, 60) as usize;
    let type_ids_off = read_u32(data, 68) as usize;
    let method_ids_off = read_u32(data, 92) as usize;
    let class_defs_size = read_u32(data, 96) as usize;
    let class_defs_off = read_u32(data, 100) as usize;

    for i in 0..class_defs_size {
        let def_off = class_defs_off + i * 32;
        let class_idx = read_u32(data, def_off) as usize;
        let descriptor_idx = read_u32(data, type_ids_off + class_idx * 4) as usize;
        let class_name = read_string(data, string_ids_off, descriptor_idx);

        if !class_name.contains(class_pattern) {
            continue;
        }

        let class_data_off = read_u32(data, def_off + 24) as usize;
        if class_data_off == 0 {
            continue;
        }

        let mut cursor = class_data_off;
        let static_fields = read_uleb128(data, &mut cursor);
        let instance_fields = read_uleb128(data, &mut cursor);
        let direct_methods = read_uleb128(data, &mut cursor);
        let virtual_methods = read_uleb128(data, &mut cursor);

        for _ in 0..static_fields {
            let _ = read_uleb128(data, &mut cursor);
            let _ = read_uleb128(data, &mut cursor);
        }
        for _ in 0..instance_fields {
            let _ = read_uleb128(data, &mut cursor);
            let _ = read_uleb128(data, &mut cursor);
        }

        // Process both direct and virtual methods
        for is_virtual in [false, true] {
            let count = if is_virtual { virtual_methods } else { direct_methods };
            let mut method_idx = 0usize;

            for _ in 0..count {
                let diff = read_uleb128(data, &mut cursor) as usize;
                let _access_flags = read_uleb128(data, &mut cursor);
                let code_off = read_uleb128(data, &mut cursor) as usize;
                method_idx += diff;

                let m_entry = method_ids_off + method_idx * 8;
                let name_idx = read_u32(data, m_entry + 4) as usize;
                let method_name = read_string(data, string_ids_off, name_idx);

                let is_match = if target_method == "*" {
                    method_name != "<init>" && method_name != "<clinit>"
                } else {
                    target_method.split(',').any(|m| m.trim() == method_name)
                };

                if is_match {
                    if code_off == 0 {
                        eprintln!("[!] Found method {}::{} but code_off is 0 (native/abstract)", class_name, method_name);
                        continue;
                    }

                    let regs = read_u16(data, code_off);
                    let insns_count = read_u32(data, code_off + 12) as usize;
                    let insns_off = code_off + 16;

                    match ret {
                        ReturnType::Void => {
                            if insns_count >= 1 {
                                // 0x000e: return-void
                                write_u16(data, insns_off, 0x000e);
                                results.push(PatchResult {
                                    class_name: class_name.clone(),
                                    method_name: method_name.clone(),
                                    return_type: ret,
                                    code_off,
                                });
                            }
                        }
                        ReturnType::True => {
                            // Ensure at least 1 register and 2 code units
                            if insns_count >= 2 && regs >= 1 {
                                // const/4 v0, 1 -> 0x1012
                                write_u16(data, insns_off, 0x1012);
                                // return v0 -> 0x000f
                                write_u16(data, insns_off + 2, 0x000f);
                                results.push(PatchResult {
                                    class_name: class_name.clone(),
                                    method_name: method_name.clone(),
                                    return_type: ret,
                                    code_off,
                                });
                            } else if insns_count >= 1 {
                                // Fallback return-void if space not enough
                                write_u16(data, insns_off, 0x000e);
                                results.push(PatchResult {
                                    class_name: class_name.clone(),
                                    method_name: method_name.clone(),
                                    return_type: ReturnType::Void,
                                    code_off,
                                });
                            }
                        }
                        ReturnType::False => {
                            if insns_count >= 2 && regs >= 1 {
                                // const/4 v0, 0 -> 0x0012
                                write_u16(data, insns_off, 0x0012);
                                // return v0 -> 0x000f
                                write_u16(data, insns_off + 2, 0x000f);
                                results.push(PatchResult {
                                    class_name: class_name.clone(),
                                    method_name: method_name.clone(),
                                    return_type: ret,
                                    code_off,
                                });
                            } else if insns_count >= 1 {
                                write_u16(data, insns_off, 0x000e);
                                results.push(PatchResult {
                                    class_name: class_name.clone(),
                                    method_name: method_name.clone(),
                                    return_type: ReturnType::Void,
                                    code_off,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if !results.is_empty() {
        update_dex_checksums(data);
    }

    results
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adler32() {
        let data = b"Hello, World!";
        let sum = adler32(data);
        assert_eq!(sum, 0x1f9e046a);
    }

    #[test]
    fn test_return_type_from_str() {
        assert_eq!(ReturnType::from_str("void"), Some(ReturnType::Void));
        assert_eq!(ReturnType::from_str("true"), Some(ReturnType::True));
        assert_eq!(ReturnType::from_str("false"), Some(ReturnType::False));
        assert_eq!(ReturnType::from_str("unknown"), None);
    }
}


