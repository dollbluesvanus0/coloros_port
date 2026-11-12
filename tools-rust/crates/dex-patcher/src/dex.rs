//! Dalvik Executable (DEX) parser, representation, and binary mutator.
//!
//! Supports reading and mutating:
//! - Header (magic, Adler32 checksum, SHA-1 signature, table offsets/sizes)
//! - String IDs & MUTF-8 `string_data_item`s
//! - Type IDs
//! - Proto IDs & `type_list`s
//! - Field IDs
//! - Method IDs
//! - Class Defs & `class_data_item`s (`encoded_field`, `encoded_method`)
//! - `code_item`s (instructions, registers, tries, handlers)
//! - Dalvik bytecode instruction length decoding & branch/try offset adjustment.

use adler2::adler32_slice;
use anyhow::{bail, ensure, Context, Result};
use sha1::{Digest, Sha1};

pub const DEX_HEADER_SIZE: usize = 0x70; // 112 bytes
pub const ENDIAN_CONSTANT: u32 = 0x1234_5678;
pub const NO_INDEX: u32 = 0xffff_ffff;

pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_ABSTRACT: u32 = 0x0400;

/// Parsed DEX header (112 bytes).
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub parameters: Vec<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ClassDef {
    pub def_offset: usize,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
    /// Byte range in `DexFile::data` where `code_off` ULEB128 is stored.
    pub code_off_span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub offset: usize,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    /// Raw bytes of `tries` and `handlers` (excluding padding before `tries`).
    pub tries_and_handlers: Vec<u8>,
}

/// In-memory DEX file representation supporting parsing and binary mutation.
#[derive(Debug, Clone)]
pub struct DexFile {
    pub data: Vec<u8>,
    pub header: DexHeader,
    pub string_offsets: Vec<u32>,
    pub strings: Vec<String>,
    pub types: Vec<u32>,
    pub protos: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub class_defs: Vec<ClassDef>,
}

impl DexFile {
    /// Parse a DEX image from raw bytes.
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        ensure!(
            data.len() >= DEX_HEADER_SIZE,
            "DEX file too small ({} bytes < 112 bytes)",
            data.len()
        );
        ensure!(
            &data[0..4] == b"dex\n",
            "Invalid DEX magic: {:?}",
            &data[0..8]
        );

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);
        let checksum = read_u32(&data, 0x08);
        let mut signature = [0u8; 20];
        signature.copy_from_slice(&data[0x0C..0x20]);

        let file_size = read_u32(&data, 0x20);
        let header_size = read_u32(&data, 0x24);
        let endian_tag = read_u32(&data, 0x28);
        ensure!(
            endian_tag == ENDIAN_CONSTANT,
            "Unsupported DEX endian tag: 0x{:08x}",
            endian_tag
        );

        let header = DexHeader {
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size: read_u32(&data, 0x2C),
            link_off: read_u32(&data, 0x30),
            map_off: read_u32(&data, 0x34),
            string_ids_size: read_u32(&data, 0x38),
            string_ids_off: read_u32(&data, 0x3C),
            type_ids_size: read_u32(&data, 0x40),
            type_ids_off: read_u32(&data, 0x44),
            proto_ids_size: read_u32(&data, 0x48),
            proto_ids_off: read_u32(&data, 0x4C),
            field_ids_size: read_u32(&data, 0x50),
            field_ids_off: read_u32(&data, 0x54),
            method_ids_size: read_u32(&data, 0x58),
            method_ids_off: read_u32(&data, 0x5C),
            class_defs_size: read_u32(&data, 0x60),
            class_defs_off: read_u32(&data, 0x64),
            data_size: read_u32(&data, 0x68),
            data_off: read_u32(&data, 0x6C),
        };

        let mut dex = Self {
            data,
            header,
            string_offsets: Vec::new(),
            strings: Vec::new(),
            types: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            class_defs: Vec::new(),
        };
        dex.reload_tables()?;
        Ok(dex)
    }

    /// Parse or reload index tables from `self.data`.
    pub fn reload_tables(&mut self) -> Result<()> {
        let data = &self.data;

        // 1. String IDs
        let str_count = self.header.string_ids_size as usize;
        let str_off = self.header.string_ids_off as usize;
        let mut string_offsets = Vec::with_capacity(str_count);
        let mut strings = Vec::with_capacity(str_count);
        for i in 0..str_count {
            let off_pos = str_off + i * 4;
            ensure!(off_pos + 4 <= data.len(), "string_id {} out of bounds", i);
            let s_off = read_u32(data, off_pos);
            string_offsets.push(s_off);
            let s = decode_string_at(data, s_off as usize)
                .with_context(|| format!("Failed to decode string_id {} at 0x{:x}", i, s_off))?;
            strings.push(s);
        }

        // 2. Type IDs
        let type_count = self.header.type_ids_size as usize;
        let type_off = self.header.type_ids_off as usize;
        let mut types = Vec::with_capacity(type_count);
        for i in 0..type_count {
            let pos = type_off + i * 4;
            ensure!(pos + 4 <= data.len(), "type_id {} out of bounds", i);
            types.push(read_u32(data, pos));
        }

        // 3. Proto IDs
        let proto_count = self.header.proto_ids_size as usize;
        let proto_off = self.header.proto_ids_off as usize;
        let mut protos = Vec::with_capacity(proto_count);
        for i in 0..proto_count {
            let pos = proto_off + i * 12;
            ensure!(pos + 12 <= data.len(), "proto_id {} out of bounds", i);
            let shorty_idx = read_u32(data, pos);
            let return_type_idx = read_u32(data, pos + 4);
            let parameters_off = read_u32(data, pos + 8);
            let mut parameters = Vec::new();
            if parameters_off != 0 {
                let p_off = parameters_off as usize;
                ensure!(
                    p_off + 4 <= data.len(),
                    "proto parameters_off out of bounds"
                );
                let size = read_u32(data, p_off) as usize;
                ensure!(
                    p_off + 4 + size * 2 <= data.len(),
                    "proto type_list out of bounds"
                );
                for j in 0..size {
                    parameters.push(read_u16(data, p_off + 4 + j * 2));
                }
            }
            protos.push(ProtoId {
                shorty_idx,
                return_type_idx,
                parameters_off,
                parameters,
            });
        }

        // 4. Field IDs
        let field_count = self.header.field_ids_size as usize;
        let field_off = self.header.field_ids_off as usize;
        let mut fields = Vec::with_capacity(field_count);
        for i in 0..field_count {
            let pos = field_off + i * 8;
            ensure!(pos + 8 <= data.len(), "field_id {} out of bounds", i);
            fields.push(FieldId {
                class_idx: read_u16(data, pos),
                type_idx: read_u16(data, pos + 2),
                name_idx: read_u32(data, pos + 4),
            });
        }

        // 5. Method IDs
        let method_count = self.header.method_ids_size as usize;
        let method_off = self.header.method_ids_off as usize;
        let mut methods = Vec::with_capacity(method_count);
        for i in 0..method_count {
            let pos = method_off + i * 8;
            ensure!(pos + 8 <= data.len(), "method_id {} out of bounds", i);
            methods.push(MethodId {
                class_idx: read_u16(data, pos),
                proto_idx: read_u16(data, pos + 2),
                name_idx: read_u32(data, pos + 4),
            });
        }

        // 6. Class Defs
        let class_count = self.header.class_defs_size as usize;
        let class_off = self.header.class_defs_off as usize;
        let mut class_defs = Vec::with_capacity(class_count);
        for i in 0..class_count {
            let pos = class_off + i * 32;
            ensure!(pos + 32 <= data.len(), "class_def {} out of bounds", i);
            class_defs.push(ClassDef {
                def_offset: pos,
                class_idx: read_u32(data, pos),
                access_flags: read_u32(data, pos + 4),
                superclass_idx: read_u32(data, pos + 8),
                interfaces_off: read_u32(data, pos + 12),
                source_file_idx: read_u32(data, pos + 16),
                annotations_off: read_u32(data, pos + 20),
                class_data_off: read_u32(data, pos + 24),
                static_values_off: read_u32(data, pos + 28),
            });
        }

        self.string_offsets = string_offsets;
        self.strings = strings;
        self.types = types;
        self.protos = protos;
        self.fields = fields;
        self.methods = methods;
        self.class_defs = class_defs;
        Ok(())
    }

    /// Resolve a string by `string_idx`.
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    /// Resolve a type descriptor by `type_idx`.
    pub fn get_type_descriptor(&self, type_idx: u32) -> Option<&str> {
        let desc_idx = *self.types.get(type_idx as usize)?;
        self.get_string(desc_idx)
    }

    /// Resolve a method's `(class_descriptor, method_name, proto_descriptor)`.
    pub fn get_method_signature(&self, method_idx: u32) -> Option<(String, String, String)> {
        let m = self.methods.get(method_idx as usize)?;
        let class_desc = self.get_type_descriptor(m.class_idx as u32)?.to_string();
        let name = self.get_string(m.name_idx)?.to_string();
        let proto = self.get_proto_descriptor(m.proto_idx as u32)?;
        Some((class_desc, name, proto))
    }

    /// Resolve a field's `(class_descriptor, field_name, type_descriptor)`.
    pub fn get_field_signature(&self, field_idx: u32) -> Option<(String, String, String)> {
        let f = self.fields.get(field_idx as usize)?;
        let class_desc = self.get_type_descriptor(f.class_idx as u32)?.to_string();
        let name = self.get_string(f.name_idx)?.to_string();
        let ty = self.get_type_descriptor(f.type_idx as u32)?.to_string();
        Some((class_desc, name, ty))
    }

    /// Format a `proto_idx` as `(param1param2...)returnType`.
    pub fn get_proto_descriptor(&self, proto_idx: u32) -> Option<String> {
        let proto = self.protos.get(proto_idx as usize)?;
        let ret = self.get_type_descriptor(proto.return_type_idx)?;
        let mut s = String::from("(");
        for &p_type in &proto.parameters {
            s.push_str(self.get_type_descriptor(p_type as u32)?);
        }
        s.push(')');
        s.push_str(ret);
        Some(s)
    }

    /// Parse `class_data_item` at `class_data_off`.
    pub fn read_class_data(&self, class_data_off: u32) -> Result<ClassData> {
        ensure!(class_data_off != 0, "class_data_off is 0");
        let mut pos = class_data_off as usize;
        let data = &self.data;

        let (static_fields_size, n) = read_uleb128(data, pos)?;
        pos += n;
        let (instance_fields_size, n) = read_uleb128(data, pos)?;
        pos += n;
        let (direct_methods_size, n) = read_uleb128(data, pos)?;
        pos += n;
        let (virtual_methods_size, n) = read_uleb128(data, pos)?;
        pos += n;

        let mut static_fields = Vec::with_capacity(static_fields_size as usize);
        let mut field_idx = 0u32;
        for _ in 0..static_fields_size {
            let (diff, n) = read_uleb128(data, pos)?;
            pos += n;
            let (access_flags, n) = read_uleb128(data, pos)?;
            pos += n;
            field_idx = field_idx.wrapping_add(diff);
            static_fields.push(EncodedField {
                field_idx,
                access_flags,
            });
        }

        let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
        let mut field_idx = 0u32;
        for _ in 0..instance_fields_size {
            let (diff, n) = read_uleb128(data, pos)?;
            pos += n;
            let (access_flags, n) = read_uleb128(data, pos)?;
            pos += n;
            field_idx = field_idx.wrapping_add(diff);
            instance_fields.push(EncodedField {
                field_idx,
                access_flags,
            });
        }

        let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
        let mut method_idx = 0u32;
        for _ in 0..direct_methods_size {
            let (diff, n) = read_uleb128(data, pos)?;
            pos += n;
            let (access_flags, n) = read_uleb128(data, pos)?;
            pos += n;
            let code_off_start = pos;
            let (code_off, n) = read_uleb128(data, pos)?;
            pos += n;
            let code_off_end = pos;
            method_idx = method_idx.wrapping_add(diff);
            direct_methods.push(EncodedMethod {
                method_idx,
                access_flags,
                code_off,
                code_off_span: (code_off_start, code_off_end),
            });
        }

        let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);
        let mut method_idx = 0u32;
        for _ in 0..virtual_methods_size {
            let (diff, n) = read_uleb128(data, pos)?;
            pos += n;
            let (access_flags, n) = read_uleb128(data, pos)?;
            pos += n;
            let code_off_start = pos;
            let (code_off, n) = read_uleb128(data, pos)?;
            pos += n;
            let code_off_end = pos;
            method_idx = method_idx.wrapping_add(diff);
            virtual_methods.push(EncodedMethod {
                method_idx,
                access_flags,
                code_off,
                code_off_span: (code_off_start, code_off_end),
            });
        }

        Ok(ClassData {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        })
    }

    /// Encode `ClassData` into bytes.
    pub fn encode_class_data(cd: &ClassData) -> Vec<u8> {
        let mut buf = Vec::new();
        write_uleb128(&mut buf, cd.static_fields.len() as u32);
        write_uleb128(&mut buf, cd.instance_fields.len() as u32);
        write_uleb128(&mut buf, cd.direct_methods.len() as u32);
        write_uleb128(&mut buf, cd.virtual_methods.len() as u32);

        let mut prev = 0u32;
        for f in &cd.static_fields {
            write_uleb128(&mut buf, f.field_idx - prev);
            write_uleb128(&mut buf, f.access_flags);
            prev = f.field_idx;
        }

        let mut prev = 0u32;
        for f in &cd.instance_fields {
            write_uleb128(&mut buf, f.field_idx - prev);
            write_uleb128(&mut buf, f.access_flags);
            prev = f.field_idx;
        }

        let mut prev = 0u32;
        for m in &cd.direct_methods {
            write_uleb128(&mut buf, m.method_idx - prev);
            write_uleb128(&mut buf, m.access_flags);
            write_uleb128(&mut buf, m.code_off);
            prev = m.method_idx;
        }

        let mut prev = 0u32;
        for m in &cd.virtual_methods {
            write_uleb128(&mut buf, m.method_idx - prev);
            write_uleb128(&mut buf, m.access_flags);
            write_uleb128(&mut buf, m.code_off);
            prev = m.method_idx;
        }

        buf
    }

    /// Read a `code_item` at `code_off`.
    pub fn read_code_item(&self, code_off: u32) -> Result<CodeItem> {
        let off = code_off as usize;
        let data = &self.data;
        ensure!(off + 16 <= data.len(), "code_item header out of bounds");

        let registers_size = read_u16(data, off);
        let ins_size = read_u16(data, off + 2);
        let outs_size = read_u16(data, off + 4);
        let tries_size = read_u16(data, off + 6);
        let debug_info_off = read_u32(data, off + 8);
        let insns_size = read_u32(data, off + 12) as usize;

        let insns_byte_start = off + 16;
        let insns_byte_end = insns_byte_start + insns_size * 2;
        ensure!(
            insns_byte_end <= data.len(),
            "code_item insns out of bounds (off=0x{:x}, insns_size={})",
            off,
            insns_size
        );

        let mut insns = Vec::with_capacity(insns_size);
        for i in 0..insns_size {
            insns.push(read_u16(data, insns_byte_start + i * 2));
        }

        let mut tries_and_handlers = Vec::new();
        if tries_size > 0 {
            let mut pos = insns_byte_end;
            if insns_size % 2 == 1 {
                pos += 2; // 2-byte alignment padding before tries
            }
            let tries_start = pos;
            pos += (tries_size as usize) * 8;
            ensure!(pos <= data.len(), "code_item tries out of bounds");
            // Read encoded_catch_handler_list to find its end
            let (handlers_size, n) = read_uleb128(data, pos)?;
            pos += n;
            for _ in 0..handlers_size {
                let (size, n) = read_sleb128(data, pos)?;
                pos += n;
                let pair_count = size.unsigned_abs();
                for _ in 0..pair_count {
                    let (_, n1) = read_uleb128(data, pos)?;
                    pos += n1;
                    let (_, n2) = read_uleb128(data, pos)?;
                    pos += n2;
                }
                if size <= 0 {
                    let (_, n_catch_all) = read_uleb128(data, pos)?;
                    pos += n_catch_all;
                }
            }
            tries_and_handlers.extend_from_slice(&data[tries_start..pos]);
        }

        Ok(CodeItem {
            offset: off,
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns,
            tries_and_handlers,
        })
    }

    /// Encode a `CodeItem` into bytes.
    pub fn encode_code_item(ci: &CodeItem) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + ci.insns.len() * 2 + ci.tries_and_handlers.len() + 2);
        buf.extend_from_slice(&ci.registers_size.to_le_bytes());
        buf.extend_from_slice(&ci.ins_size.to_le_bytes());
        buf.extend_from_slice(&ci.outs_size.to_le_bytes());
        buf.extend_from_slice(&ci.tries_size.to_le_bytes());
        buf.extend_from_slice(&ci.debug_info_off.to_le_bytes());
        buf.extend_from_slice(&(ci.insns.len() as u32).to_le_bytes());
        for &u in &ci.insns {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        if ci.tries_size > 0 && !ci.tries_and_handlers.is_empty() {
            if ci.insns.len() % 2 == 1 {
                buf.extend_from_slice(&[0u8, 0u8]);
            }
            buf.extend_from_slice(&ci.tries_and_handlers);
        }
        buf
    }

    /// Write an updated `CodeItem` for a method belonging to `class_def_index`.
    ///
    /// If the new `CodeItem` fits within the old instruction space (and `tries_size == 0`
    /// or `tries_and_handlers` is unchanged in size), it is written in-place at `old_code.offset`.
    /// Otherwise, the new `CodeItem` is appended (4-byte aligned) to the end of `self.data`,
    /// and the owning class's `class_data_item` is updated (either in-place if ULEB128 width matches,
    /// or relocated to the end of `self.data` with `class_def.class_data_off` updated).
    pub fn write_code_item(
        &mut self,
        class_def_index: usize,
        method_idx: u32,
        old_code: &CodeItem,
        new_code: &CodeItem,
    ) -> Result<u32> {
        let ref_count = crate::relocate::count_code_off_refs(self, old_code.offset as u32)?;
        if self.header.map_off != 0 {
            let old_encoded_len = Self::encode_code_item(old_code).len();
            let new_encoded = Self::encode_code_item(new_code);
            let same_size_in_place = ref_count <= 1 && old_encoded_len == new_encoded.len();
            if same_size_in_place {
                let off = old_code.offset;
                self.data[off..off + new_encoded.len()].copy_from_slice(&new_encoded);
                return Ok(old_code.offset as u32);
            }
            return crate::relocate::rewrite_code_item_with_map(
                self,
                class_def_index,
                method_idx,
                old_code,
                new_code,
            );
        }

        let can_fit_in_place = ref_count <= 1
            && new_code.insns.len() <= old_code.insns.len()
            && (new_code.tries_size == 0
                || (new_code.insns.len() == old_code.insns.len()
                    && new_code.tries_and_handlers.len() <= old_code.tries_and_handlers.len()));

        if can_fit_in_place {
            let off = old_code.offset;
            write_u16(&mut self.data, off, new_code.registers_size);
            write_u16(&mut self.data, off + 2, new_code.ins_size);
            write_u16(&mut self.data, off + 4, new_code.outs_size);
            write_u16(&mut self.data, off + 6, new_code.tries_size);
            write_u32(&mut self.data, off + 8, new_code.debug_info_off);
            write_u32(&mut self.data, off + 12, new_code.insns.len() as u32);
            let insns_start = off + 16;
            for (i, &word) in new_code.insns.iter().enumerate() {
                write_u16(&mut self.data, insns_start + i * 2, word);
            }
            // Zero-fill any leftover instruction slots from the old code item
            for i in new_code.insns.len()..old_code.insns.len() {
                write_u16(&mut self.data, insns_start + i * 2, 0);
            }
            if new_code.tries_size > 0 && !new_code.tries_and_handlers.is_empty() {
                let mut pos = insns_start + new_code.insns.len() * 2;
                if new_code.insns.len() % 2 == 1 {
                    write_u16(&mut self.data, pos, 0);
                    pos += 2;
                }
                self.data[pos..pos + new_code.tries_and_handlers.len()]
                    .copy_from_slice(&new_code.tries_and_handlers);
            }
            return Ok(old_code.offset as u32);
        }

        // Align end of `self.data` to 4 bytes and append the new `code_item`.
        while self.data.len() % 4 != 0 {
            self.data.push(0);
        }
        let new_code_off = self.data.len() as u32;
        let encoded_ci = Self::encode_code_item(new_code);
        self.data.extend_from_slice(&encoded_ci);

        // Update `code_off` in `class_data_item` for `class_def_index`.
        let class_data_off = self.class_defs[class_def_index].class_data_off;
        let mut class_data = self.read_class_data(class_data_off)?;
        let mut updated = false;
        for m in class_data
            .direct_methods
            .iter_mut()
            .chain(class_data.virtual_methods.iter_mut())
        {
            if m.method_idx == method_idx {
                m.code_off = new_code_off;
                updated = true;
            }
        }
        ensure!(
            updated,
            "method_idx {} not found in class_def {}",
            method_idx,
            class_def_index
        );

        let new_cd_bytes = Self::encode_class_data(&class_data);
        let new_class_data_off = self.data.len() as u32;
        self.data.extend_from_slice(&new_cd_bytes);

        let def_offset = self.class_defs[class_def_index].def_offset;
        write_u32(&mut self.data, def_offset + 24, new_class_data_off);
        self.class_defs[class_def_index].class_data_off = new_class_data_off;

        self.sync_size_headers();
        Ok(new_code_off)
    }

    /// Find `s` in `self.strings`, or insert it into `string_ids` in sorted MUTF-8 order
    /// (preserving `map_list` and all DEX references).
    pub fn add_or_get_string(&mut self, s: &str) -> Result<u32> {
        crate::relocate::add_or_get_string(self, s)
    }

    /// Update a string table entry at `string_idx` to `new_value`.
    /// Overwrites in-place if the encoded `string_data_item` fits in the existing space;
    /// otherwise appends a new `string_data_item` to `self.data` and updates `string_id_item`.
    pub fn set_string(&mut self, string_idx: u32, new_value: &str) -> Result<()> {
        let idx = string_idx as usize;
        ensure!(idx < self.strings.len(), "string_idx {} out of bounds", idx);

        let old_off = self.string_offsets[idx] as usize;
        let old_encoded_len = encoded_string_item_len(&self.data, old_off)?;
        let new_encoded = encode_string_data_item(new_value);

        let str_id_pos = (self.header.string_ids_off as usize) + idx * 4;
        if new_encoded.len() <= old_encoded_len {
            self.data[old_off..old_off + new_encoded.len()].copy_from_slice(&new_encoded);
            for b in &mut self.data[old_off + new_encoded.len()..old_off + old_encoded_len] {
                *b = 0;
            }
        } else {
            let new_off = self.data.len() as u32;
            self.data.extend_from_slice(&new_encoded);
            write_u32(&mut self.data, str_id_pos, new_off);
            self.string_offsets[idx] = new_off;
            self.sync_size_headers();
        }
        self.strings[idx] = new_value.to_string();
        Ok(())
    }

    /// Synchronize `file_size` and `data_size` in the DEX header when `self.data` grows.
    pub fn sync_size_headers(&mut self) {
        let file_size = self.data.len() as u32;
        self.header.file_size = file_size;
        write_u32(&mut self.data, 0x20, file_size);

        if self.header.data_off > 0 && file_size >= self.header.data_off {
            let data_size = file_size - self.header.data_off;
            self.header.data_size = data_size;
            write_u32(&mut self.data, 0x68, data_size);
        }
    }

    /// Recalculate and write the DEX SHA-1 signature (bytes 12..32) and
    /// Adler32 checksum (bytes 8..12).
    pub fn update_hashes(&mut self) {
        self.sync_size_headers();

        // 1. SHA-1 signature over bytes 32..end
        let mut hasher = Sha1::new();
        hasher.update(&self.data[32..]);
        let digest = hasher.finalize();
        self.data[12..32].copy_from_slice(&digest);
        self.header.signature.copy_from_slice(&digest);

        // 2. Adler32 checksum over bytes 12..end (including the new SHA-1 signature)
        let checksum = adler32_slice(&self.data[12..]);
        write_u32(&mut self.data, 8, checksum);
        self.header.checksum = checksum;
    }

    /// Verify that the stored SHA-1 signature and Adler32 checksum match the DEX bytes.
    pub fn verify_hashes(&self) -> bool {
        if self.data.len() < DEX_HEADER_SIZE {
            return false;
        }
        let mut hasher = Sha1::new();
        hasher.update(&self.data[32..]);
        let expected_sha1 = hasher.finalize();
        if &self.data[12..32] != expected_sha1.as_slice() {
            return false;
        }
        let expected_adler = adler32_slice(&self.data[12..]);
        let actual_adler = read_u32(&self.data, 8);
        expected_adler == actual_adler
    }
}

/// Return the length in 16-bit code units of the Dalvik instruction at `insns[pc]`.
pub fn insn_len(insns: &[u16], pc: usize) -> usize {
    if pc >= insns.len() {
        return 1;
    }
    let word = insns[pc];
    // Handle pseudo-instruction payloads (0x0100, 0x0200, 0x0300)
    match word {
        0x0100 => {
            // packed-switch-payload: 4 + size * 2
            let size = insns.get(pc + 1).copied().unwrap_or(0) as usize;
            return (4 + size * 2).min(insns.len() - pc);
        }
        0x0200 => {
            // sparse-switch-payload: 2 + size * 4
            let size = insns.get(pc + 1).copied().unwrap_or(0) as usize;
            return (2 + size * 4).min(insns.len() - pc);
        }
        0x0300 => {
            // fill-array-data-payload: 4 + (size * element_width + 1) / 2
            let elem_width = insns.get(pc + 1).copied().unwrap_or(0) as usize;
            let size_lo = insns.get(pc + 2).copied().unwrap_or(0) as usize;
            let size_hi = insns.get(pc + 3).copied().unwrap_or(0) as usize;
            let size = size_lo | (size_hi << 16);
            return (4 + (size * elem_width + 1) / 2).min(insns.len() - pc);
        }
        _ => {}
    }

    let op = (word & 0xff) as u8;
    let len = match op {
        0x00 | 0x01 | 0x04 | 0x07 | 0x0a..=0x12 | 0x1d | 0x1e | 0x21 | 0x27 | 0x28
        | 0x3e..=0x43 | 0x73 | 0x79 | 0x7a | 0x7b..=0x8f | 0xb0..=0xcf => 1,
        0x02 | 0x05 | 0x08 | 0x13 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1c | 0x1f | 0x20 | 0x22
        | 0x23 | 0x29 | 0x2d..=0x3d | 0x44..=0x6d | 0x90..=0xaf | 0xd0..=0xe2 | 0xfe | 0xff => 2,
        0x03 | 0x06 | 0x09 | 0x14 | 0x17 | 0x1b | 0x24..=0x26 | 0x2a..=0x2c | 0x6e..=0x72
        | 0x74..=0x78 | 0xfc | 0xfd => 3,
        0xfa | 0xfb => 4,
        0x18 => 5,
        _ => 1,
    };
    len.min(insns.len() - pc).max(1)
}

/// Insert `inserted_units` at `insert_pc` in `CodeItem`, automatically adjusting
/// relative branch offsets in `insns` and try/catch addresses in `tries_and_handlers`.
pub fn insert_insns_at(code: &mut CodeItem, insert_pc: usize, inserted_units: &[u16]) -> Result<()> {
    let shift = inserted_units.len();
    if shift == 0 {
        return Ok(());
    }

    let map_pc = |old_pc: usize| -> usize {
        if old_pc < insert_pc {
            old_pc
        } else {
            old_pc + shift
        }
    };

    // First, adjust relative branch offsets in `code.insns` before splicing.
    let mut pc = 0;
    while pc < code.insns.len() {
        let len = insn_len(&code.insns, pc);
        let word = code.insns[pc];
        if word != 0x0100 && word != 0x0200 && word != 0x0300 {
            let op = (word & 0xff) as u8;
            match op {
                0x28 => {
                    // goto (10t): signed 8-bit branch offset in high byte
                    let rel = ((word >> 8) as u8) as i8 as isize;
                    let old_target = (pc as isize + rel) as usize;
                    let new_src = map_pc(pc) as isize;
                    // If branching directly to `insert_pc` from after, or across `insert_pc`
                    let new_target = map_pc(old_target) as isize;
                    let new_rel = new_target - new_src;
                    ensure!(
                        (-128..=127).contains(&new_rel),
                        "goto (10t) overflow after instruction insertion"
                    );
                    code.insns[pc] = (op as u16) | (((new_rel as i8 as u8) as u16) << 8);
                }
                0x29 | 0x32..=0x3d => {
                    // goto/16 (20t), if-* (22t / 21t): signed 16-bit branch offset in insns[pc + 1]
                    if pc + 1 < code.insns.len() {
                        let rel = (code.insns[pc + 1] as i16) as isize;
                        let old_target = (pc as isize + rel) as usize;
                        let new_src = map_pc(pc) as isize;
                        let new_target = map_pc(old_target) as isize;
                        let new_rel = new_target - new_src;
                        ensure!(
                            (i16::MIN as isize..=i16::MAX as isize).contains(&new_rel),
                            "16-bit branch overflow after instruction insertion"
                        );
                        code.insns[pc + 1] = (new_rel as i16) as u16;
                    }
                }
                0x2a | 0x26 | 0x2b | 0x2c => {
                    // goto/32 (30t), fill-array-data, packed-switch, sparse-switch (31t)
                    if pc + 2 < code.insns.len() {
                        let lo = code.insns[pc + 1] as u32;
                        let hi = code.insns[pc + 2] as u32;
                        let rel = ((lo | (hi << 16)) as i32) as isize;
                        let old_target = (pc as isize + rel) as usize;
                        let new_src = map_pc(pc) as isize;
                        let new_target = map_pc(old_target) as isize;
                        let new_rel = (new_target - new_src) as i32 as u32;
                        code.insns[pc + 1] = (new_rel & 0xffff) as u16;
                        code.insns[pc + 2] = (new_rel >> 16) as u16;
                    }
                }
                _ => {}
            }
        }
        pc += len;
    }

    // Collect switch payloads (`0x2b` packed-switch, `0x2c` sparse-switch) and data payloads (`0x26`)
    // so we can update switch case offsets and maintain 4-byte (even-PC) payload alignment.
    let mut payload_refs: Vec<(usize, usize, u8)> = Vec::new();
    let mut p_scan = 0;
    while p_scan < code.insns.len() {
        let len = insn_len(&code.insns, p_scan);
        let word = code.insns[p_scan];
        if word != 0x0100 && word != 0x0200 && word != 0x0300 {
            let op = (word & 0xff) as u8;
            if matches!(op, 0x26 | 0x2b | 0x2c) && p_scan + 2 < code.insns.len() {
                let lo = code.insns[p_scan + 1] as u32;
                let hi = code.insns[p_scan + 2] as u32;
                let rel = ((lo | (hi << 16)) as i32) as isize;
                let target_pc = (p_scan as isize + rel) as usize;
                payload_refs.push((p_scan, target_pc, op));
            }
        }
        p_scan += len;
    }

    // Update targets inside packed-switch / sparse-switch payloads before splicing.
    for &(switch_pc, payload_pc, op) in &payload_refs {
        let new_switch_pc = map_pc(switch_pc) as isize;
        if op == 0x2b
            && payload_pc + 4 <= code.insns.len()
            && code.insns[payload_pc] == 0x0100
        {
            let size = code.insns[payload_pc + 1] as usize;
            let targets_start = payload_pc + 4;
            for i in 0..size {
                let tp = targets_start + i * 2;
                if tp + 1 < code.insns.len() {
                    let lo = code.insns[tp] as u32;
                    let hi = code.insns[tp + 1] as u32;
                    let rel = ((lo | (hi << 16)) as i32) as isize;
                    let old_target = (switch_pc as isize + rel) as usize;
                    let new_rel = (map_pc(old_target) as isize - new_switch_pc) as i32 as u32;
                    code.insns[tp] = (new_rel & 0xffff) as u16;
                    code.insns[tp + 1] = (new_rel >> 16) as u16;
                }
            }
        } else if op == 0x2c
            && payload_pc + 2 <= code.insns.len()
            && code.insns[payload_pc] == 0x0200
        {
            let size = code.insns[payload_pc + 1] as usize;
            let targets_start = payload_pc + 2 + size * 2;
            for i in 0..size {
                let tp = targets_start + i * 2;
                if tp + 1 < code.insns.len() {
                    let lo = code.insns[tp] as u32;
                    let hi = code.insns[tp + 1] as u32;
                    let rel = ((lo | (hi << 16)) as i32) as isize;
                    let old_target = (switch_pc as isize + rel) as usize;
                    let new_rel = (map_pc(old_target) as isize - new_switch_pc) as i32 as u32;
                    code.insns[tp] = (new_rel & 0xffff) as u16;
                    code.insns[tp + 1] = (new_rel >> 16) as u16;
                }
            }
        }
    }

    // Splice the new instructions into `code.insns`.
    code.insns
        .splice(insert_pc..insert_pc, inserted_units.iter().copied());

    // Adjust `tries` and `encoded_catch_handler_list` if present.
    if code.tries_size > 0 && !code.tries_and_handlers.is_empty() {
        code.tries_and_handlers =
            adjust_tries_and_handlers(&code.tries_and_handlers, code.tries_size, insert_pc, shift)?;
    }

    // Maintain 4-byte (even code-unit) alignment for any switch/array-data payload shifted to an odd PC.
    if shift % 2 == 1 {
        let mut distinct_payloads: Vec<usize> = payload_refs
            .iter()
            .filter_map(|&(_, old_p_pc, _)| {
                let new_p_pc = map_pc(old_p_pc);
                if old_p_pc % 2 == 0 && new_p_pc % 2 == 1 && new_p_pc >= insert_pc {
                    Some(new_p_pc)
                } else {
                    None
                }
            })
            .collect();
        distinct_payloads.sort_unstable();
        distinct_payloads.dedup();
        if let Some(&first_odd_payload) = distinct_payloads.first() {
            // Re-insert a `nop` directly before the payload block; only 31t references to payloads >= first_odd_payload shift by +1,
            // Wait: simpler & always exact is calling `insert_insns_at` if we weren't already aligned,
            // EXCEPT wait: inserting `nop` before `first_odd_payload` might lie after all branches!
            // Using a dedicated 1-nop shift on `first_odd_payload` via `insert_insns_at` (with shift=2? No, infinite recursion!)
            // Wait: we only need to align each payload individually by inserting 1 nop right before `first_odd_payload`
            // and shifting `insns`, branch targets, switch payload targets, and tries once.
            code.insns.insert(first_odd_payload, 0x0000);
            let fix_pc = |p: usize| if p < first_odd_payload { p } else { p + 1 };
            let mut pc = 0;
            while pc < code.insns.len() {
                if pc == first_odd_payload {
                    pc += 1;
                    continue;
                }
                let len = insn_len(&code.insns, pc);
                let word = code.insns[pc];
                if word != 0x0100 && word != 0x0200 && word != 0x0300 {
                    let op = (word & 0xff) as u8;
                    let orig_pc = if pc < first_odd_payload { pc } else { pc - 1 };
                    match op {
                        0x28 => {
                            let rel = ((word >> 8) as u8) as i8 as isize;
                            let old_t = (orig_pc as isize + rel) as usize;
                            let new_rel = fix_pc(old_t) as isize - pc as isize;
                            if (-128..=127).contains(&new_rel) {
                                code.insns[pc] = (op as u16) | (((new_rel as i8 as u8) as u16) << 8);
                            }
                        }
                        0x29 | 0x32..=0x3d if pc + 1 < code.insns.len() => {
                            let rel = (code.insns[pc + 1] as i16) as isize;
                            let old_t = (orig_pc as isize + rel) as usize;
                            let new_rel = fix_pc(old_t) as isize - pc as isize;
                            if (i16::MIN as isize..=i16::MAX as isize).contains(&new_rel) {
                                code.insns[pc + 1] = (new_rel as i16) as u16;
                            }
                        }
                        0x2a | 0x26 | 0x2b | 0x2c if pc + 2 < code.insns.len() => {
                            let lo = code.insns[pc + 1] as u32;
                            let hi = code.insns[pc + 2] as u32;
                            let rel = ((lo | (hi << 16)) as i32) as isize;
                            let old_t = (orig_pc as isize + rel) as usize;
                            let new_rel = (fix_pc(old_t) as isize - pc as isize) as i32 as u32;
                            code.insns[pc + 1] = (new_rel & 0xffff) as u16;
                            code.insns[pc + 2] = (new_rel >> 16) as u16;
                        }
                        _ => {}
                    }
                }
                pc += len;
            }
            if code.tries_size > 0 && !code.tries_and_handlers.is_empty() {
                code.tries_and_handlers = adjust_tries_and_handlers(
                    &code.tries_and_handlers,
                    code.tries_size,
                    first_odd_payload,
                    1,
                )?;
            }
        }
    }

    Ok(())
}

fn adjust_tries_and_handlers(
    raw: &[u8],
    tries_size: u16,
    insert_pc: usize,
    shift: usize,
) -> Result<Vec<u8>> {
    let tries_count = tries_size as usize;
    let handlers_base = tries_count * 8;
    ensure!(raw.len() >= handlers_base, "tries_and_handlers too short");

    #[derive(Clone)]
    struct TryItem {
        start_addr: u32,
        insn_count: u16,
        old_handler_off: u16,
    }

    let mut tries = Vec::with_capacity(tries_count);
    for i in 0..tries_count {
        let base = i * 8;
        let mut start_addr = read_u32(raw, base);
        let mut insn_count = read_u16(raw, base + 4);
        let old_handler_off = read_u16(raw, base + 6);

        let end_addr = start_addr + insn_count as u32;
        if (insert_pc as u32) < start_addr {
            start_addr += shift as u32;
        } else if (insert_pc as u32) < end_addr {
            insn_count = insn_count.saturating_add(shift as u16);
        }
        tries.push(TryItem {
            start_addr,
            insn_count,
            old_handler_off,
        });
    }

    let map_addr = |addr: u32| -> u32 {
        if (addr as usize) < insert_pc {
            addr
        } else {
            addr + shift as u32
        }
    };

    // Parse and re-encode `encoded_catch_handler_list`, tracking old_offset -> new_offset.
    let mut pos = handlers_base;
    let (handlers_size, n) = read_uleb128(raw, pos)?;
    pos += n;

    let mut new_handlers = Vec::new();
    write_uleb128(&mut new_handlers, handlers_size);

    let mut offset_map = std::collections::HashMap::new();
    for _ in 0..handlers_size {
        let old_rel_off = (pos - handlers_base) as u16;
        let new_rel_off = new_handlers.len() as u16;
        offset_map.insert(old_rel_off, new_rel_off);

        let (size, n) = read_sleb128(raw, pos)?;
        pos += n;
        write_sleb128(&mut new_handlers, size);

        let pair_count = size.unsigned_abs();
        for _ in 0..pair_count {
            let (type_idx, n1) = read_uleb128(raw, pos)?;
            pos += n1;
            let (addr, n2) = read_uleb128(raw, pos)?;
            pos += n2;
            write_uleb128(&mut new_handlers, type_idx);
            write_uleb128(&mut new_handlers, map_addr(addr));
        }
        if size <= 0 {
            let (catch_all_addr, n_ca) = read_uleb128(raw, pos)?;
            pos += n_ca;
            write_uleb128(&mut new_handlers, map_addr(catch_all_addr));
        }
    }

    let mut out = Vec::with_capacity(handlers_base + new_handlers.len());
    for t in &tries {
        let new_handler_off = offset_map
            .get(&t.old_handler_off)
            .copied()
            .unwrap_or(t.old_handler_off);
        out.extend_from_slice(&t.start_addr.to_le_bytes());
        out.extend_from_slice(&t.insn_count.to_le_bytes());
        out.extend_from_slice(&new_handler_off.to_le_bytes());
    }
    out.extend_from_slice(&new_handlers);
    Ok(out)
}

pub fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

pub fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

pub fn write_u16(data: &mut [u8], off: usize, val: u16) {
    data[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

pub fn write_u32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

/// Read an unsigned LEB128 integer at `off`, returning `(value, bytes_consumed)`.
pub fn read_uleb128(data: &[u8], off: usize) -> Result<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    for i in 0..5 {
        ensure!(off + i < data.len(), "ULEB128 out of bounds at 0x{:x}", off);
        let byte = data[off + i];
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    bail!("Invalid ULEB128 (>5 bytes) at 0x{:x}", off)
}

/// Write an unsigned LEB128 integer into `buf`.
pub fn write_uleb128(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Read a signed LEB128 integer at `off`, returning `(value, bytes_consumed)`.
pub fn read_sleb128(data: &[u8], off: usize) -> Result<(i32, usize)> {
    let mut result = 0i32;
    let mut shift = 0;
    for i in 0..5 {
        ensure!(off + i < data.len(), "SLEB128 out of bounds at 0x{:x}", off);
        let byte = data[off + i];
        result |= ((byte & 0x7f) as i32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            if shift < 32 && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok((result, i + 1));
        }
    }
    bail!("Invalid SLEB128 (>5 bytes) at 0x{:x}", off)
}

/// Write a signed LEB128 integer into `buf`.
pub fn write_sleb128(buf: &mut Vec<u8>, mut val: i32) {
    let mut more = true;
    while more {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if (val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0) {
            more = false;
        } else {
            byte |= 0x80;
        }
        buf.push(byte);
    }
}

/// Decode a `string_data_item` at `offset` (ULEB128 utf16_size + MUTF-8 bytes + NUL).
pub fn decode_string_at(data: &[u8], offset: usize) -> Result<String> {
    let (_utf16_len, n) = read_uleb128(data, offset)?;
    let start = offset + n;
    let nul_pos = data[start..]
        .iter()
        .position(|&b| b == 0)
        .context("Untruncated string_data_item (missing NUL terminator)")?;
    let raw = &data[start..start + nul_pos];
    Ok(String::from_utf8_lossy(raw).into_owned())
}

/// Return the total byte length of the `string_data_item` at `offset` (including ULEB128 header and NUL).
pub fn encoded_string_item_len(data: &[u8], offset: usize) -> Result<usize> {
    let (_utf16_len, n) = read_uleb128(data, offset)?;
    let start = offset + n;
    let nul_pos = data[start..]
        .iter()
        .position(|&b| b == 0)
        .context("Missing NUL in string_data_item")?;
    Ok(n + nul_pos + 1)
}

/// Encode a Rust `&str` as a DEX `string_data_item` (ULEB128 utf16_size + UTF-8/MUTF-8 bytes + NUL).
pub fn encode_string_data_item(s: &str) -> Vec<u8> {
    let utf16_size = s.encode_utf16().count() as u32;
    let mut out = Vec::with_capacity(5 + s.len() + 1);
    write_uleb128(&mut out, utf16_size);
    for ch in s.chars() {
        if ch == '\0' {
            // MUTF-8 encodes NUL as 0xC0 0x80
            out.push(0xC0);
            out.push(0x80);
        } else {
            let mut tmp = [0u8; 4];
            let encoded = ch.encode_utf8(&mut tmp);
            out.extend_from_slice(encoded.as_bytes());
        }
    }
    out.push(0);
    out
}
