//! Synthetic DEX file builder for constructing valid, spec-compliant DEX binaries
//! for testing bytecode mutations, string replacements, and APK/JAR patching.

use crate::dex::{
    encode_string_data_item, write_sleb128, write_u16, write_u32, write_uleb128, DexFile,
    DEX_HEADER_SIZE, ENDIAN_CONSTANT, NO_INDEX,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub class_desc: String,
    pub name: String,
    pub params: Vec<String>,
    pub return_type: String,
    pub access_flags: u32,
    pub is_direct: bool,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<u16>,
    pub tries_size: u16,
    pub tries_and_handlers: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub class_desc: String,
    pub name: String,
    pub field_type: String,
    pub access_flags: u32,
    pub is_static: bool,
}

/// Builder for generating valid DEX binaries in memory.
#[derive(Debug, Default, Clone)]
pub struct DexBuilder {
    extra_strings: BTreeSet<String>,
    extra_types: BTreeSet<String>,
    extra_method_refs: Vec<(String, String, Vec<String>, String)>,
    extra_field_refs: Vec<(String, String, String)>,
    classes: BTreeMap<String, String>, // class_desc -> superclass_desc
    fields: Vec<FieldSpec>,
    methods: Vec<MethodSpec>,
}

impl DexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_string(&mut self, s: &str) -> &mut Self {
        self.extra_strings.insert(s.to_string());
        self
    }

    pub fn add_type(&mut self, desc: &str) -> &mut Self {
        self.extra_types.insert(desc.to_string());
        self.extra_strings.insert(desc.to_string());
        self
    }

    pub fn add_class(&mut self, class_desc: &str, superclass_desc: &str) -> &mut Self {
        self.add_type(class_desc);
        self.add_type(superclass_desc);
        self.classes
            .insert(class_desc.to_string(), superclass_desc.to_string());
        self
    }

    pub fn add_method_ref(
        &mut self,
        class_desc: &str,
        name: &str,
        params: &[&str],
        return_type: &str,
    ) -> &mut Self {
        self.add_type(class_desc);
        self.add_string(name);
        self.add_type(return_type);
        let mut p_vec = Vec::with_capacity(params.len());
        for &p in params {
            self.add_type(p);
            p_vec.push(p.to_string());
        }
        let shorty = compute_shorty(&p_vec, return_type);
        self.add_string(&shorty);
        self.extra_method_refs.push((
            class_desc.to_string(),
            name.to_string(),
            p_vec,
            return_type.to_string(),
        ));
        self
    }

    pub fn add_field_ref(&mut self, class_desc: &str, name: &str, field_type: &str) -> &mut Self {
        self.add_type(class_desc);
        self.add_string(name);
        self.add_type(field_type);
        self.extra_field_refs.push((
            class_desc.to_string(),
            name.to_string(),
            field_type.to_string(),
        ));
        self
    }

    pub fn add_field(&mut self, spec: FieldSpec) -> &mut Self {
        if !self.classes.contains_key(&spec.class_desc) {
            self.add_class(&spec.class_desc, "Ljava/lang/Object;");
        }
        self.add_field_ref(&spec.class_desc, &spec.name, &spec.field_type);
        self.fields.push(spec);
        self
    }

    pub fn add_method(&mut self, spec: MethodSpec) -> &mut Self {
        if !self.classes.contains_key(&spec.class_desc) {
            self.add_class(&spec.class_desc, "Ljava/lang/Object;");
        }
        let p_refs: Vec<&str> = spec.params.iter().map(|s| s.as_str()).collect();
        self.add_method_ref(&spec.class_desc, &spec.name, &p_refs, &spec.return_type);
        self.methods.push(spec);
        self
    }

    /// Predict the sorted index of a string, type, field, or method so callers can construct
    /// instructions referencing exact table indices before calling `build()`.
    pub fn build(&self) -> Vec<u8> {
        let mut strings_set = self.extra_strings.clone();
        let mut types_set = self.extra_types.clone();

        for (c, sup) in &self.classes {
            types_set.insert(c.clone());
            types_set.insert(sup.clone());
            strings_set.insert(c.clone());
            strings_set.insert(sup.clone());
        }

        let mut protos_set: BTreeSet<(String, Vec<String>)> = BTreeSet::new();
        for (c, name, params, ret) in &self.extra_method_refs {
            types_set.insert(c.clone());
            strings_set.insert(c.clone());
            strings_set.insert(name.clone());
            types_set.insert(ret.clone());
            strings_set.insert(ret.clone());
            for p in params {
                types_set.insert(p.clone());
                strings_set.insert(p.clone());
            }
            let shorty = compute_shorty(params, ret);
            strings_set.insert(shorty);
            protos_set.insert((ret.clone(), params.clone()));
        }

        let mut fields_set: BTreeSet<(String, String, String)> = BTreeSet::new();
        for (c, name, ft) in &self.extra_field_refs {
            types_set.insert(c.clone());
            strings_set.insert(c.clone());
            strings_set.insert(name.clone());
            types_set.insert(ft.clone());
            strings_set.insert(ft.clone());
            fields_set.insert((c.clone(), name.clone(), ft.clone()));
        }

        let strings: Vec<String> = strings_set.into_iter().collect();
        let str_idx = |s: &str| -> u32 { strings.binary_search(&s.to_string()).unwrap() as u32 };

        let mut types: Vec<String> = types_set.into_iter().collect();
        types.sort_by_key(|t| str_idx(t));
        let type_idx = |t: &str| -> u32 {
            types
                .iter()
                .position(|x| x == t)
                .expect("type must exist") as u32
        };

        // Protos sorted by (return_type_idx, parameters type_idxs)
        let mut protos: Vec<(String, Vec<String>)> = protos_set.into_iter().collect();
        protos.sort_by(|a, b| {
            let ra = type_idx(&a.0);
            let rb = type_idx(&b.0);
            let pa: Vec<u32> = a.1.iter().map(|p| type_idx(p)).collect();
            let pb: Vec<u32> = b.1.iter().map(|p| type_idx(p)).collect();
            (ra, pa).cmp(&(rb, pb))
        });
        let proto_idx = |ret: &str, params: &[String]| -> u16 {
            protos
                .iter()
                .position(|(r, p)| r == ret && p.as_slice() == params)
                .expect("proto must exist") as u16
        };

        // Fields sorted by (class_idx, name_idx, type_idx)
        let mut fields: Vec<(String, String, String)> = fields_set.into_iter().collect();
        fields.sort_by_key(|(c, n, t)| (type_idx(c), str_idx(n), type_idx(t)));
        let field_idx = |c: &str, n: &str, t: &str| -> u32 {
            fields
                .iter()
                .position(|(fc, fn_, ft)| fc == c && fn_ == n && ft == t)
                .expect("field must exist") as u32
        };

        // Methods sorted by (class_idx, name_idx, proto_idx)
        let mut method_refs: Vec<(String, String, Vec<String>, String)> =
            self.extra_method_refs.clone();
        method_refs.sort_by_key(|(c, n, p, r)| (type_idx(c), str_idx(n), proto_idx(r, p)));
        method_refs.dedup();
        let method_idx = |c: &str, n: &str, p: &[String], r: &str| -> u32 {
            method_refs
                .iter()
                .position(|(mc, mn, mp, mr)| mc == c && mn == n && mp.as_slice() == p && mr == r)
                .expect("method must exist") as u32
        };

        let class_list: Vec<(String, String)> =
            self.classes.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        // Compute fixed table offsets
        let string_ids_off = DEX_HEADER_SIZE;
        let type_ids_off = string_ids_off + strings.len() * 4;
        let proto_ids_off = type_ids_off + types.len() * 4;
        let field_ids_off = proto_ids_off + protos.len() * 12;
        let method_ids_off = field_ids_off + fields.len() * 8;
        let class_defs_off = method_ids_off + method_refs.len() * 8;
        let mut data_off = class_defs_off + class_list.len() * 32;
        while data_off % 4 != 0 {
            data_off += 1;
        }

        let mut buf = vec![0u8; data_off];

        // 1. Emit type_lists for protos with parameters
        let mut proto_param_offs = vec![0u32; protos.len()];
        for (i, (_ret, params)) in protos.iter().enumerate() {
            if !params.is_empty() {
                while buf.len() % 4 != 0 {
                    buf.push(0);
                }
                proto_param_offs[i] = buf.len() as u32;
                buf.extend_from_slice(&(params.len() as u32).to_le_bytes());
                for p in params {
                    buf.extend_from_slice(&(type_idx(p) as u16).to_le_bytes());
                }
            }
        }

        // 2. Emit string_data_items
        let mut string_data_offs = Vec::with_capacity(strings.len());
        for s in &strings {
            let off = buf.len() as u32;
            string_data_offs.push(off);
            buf.extend_from_slice(&encode_string_data_item(s));
        }

        // 3. Emit code_items for methods
        let mut method_code_offs = vec![0u32; self.methods.len()];
        for (i, m) in self.methods.iter().enumerate() {
            if !m.insns.is_empty() {
                while buf.len() % 4 != 0 {
                    buf.push(0);
                }
                let code_off = buf.len() as u32;
                method_code_offs[i] = code_off;
                buf.extend_from_slice(&m.registers_size.to_le_bytes());
                buf.extend_from_slice(&m.ins_size.to_le_bytes());
                buf.extend_from_slice(&m.outs_size.to_le_bytes());
                buf.extend_from_slice(&m.tries_size.to_le_bytes());
                buf.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
                buf.extend_from_slice(&(m.insns.len() as u32).to_le_bytes());
                for &u in &m.insns {
                    buf.extend_from_slice(&u.to_le_bytes());
                }
                if m.tries_size > 0 && !m.tries_and_handlers.is_empty() {
                    if m.insns.len() % 2 == 1 {
                        buf.extend_from_slice(&[0u8, 0u8]);
                    }
                    buf.extend_from_slice(&m.tries_and_handlers);
                }
            }
        }

        // 4. Emit class_data_items
        let mut class_data_offs = vec![0u32; class_list.len()];
        for (c_i, (class_desc, _)) in class_list.iter().enumerate() {
            let mut static_f: Vec<(u32, u32)> = self
                .fields
                .iter()
                .filter(|f| &f.class_desc == class_desc && f.is_static)
                .map(|f| (field_idx(&f.class_desc, &f.name, &f.field_type), f.access_flags))
                .collect();
            static_f.sort_by_key(|x| x.0);

            let mut instance_f: Vec<(u32, u32)> = self
                .fields
                .iter()
                .filter(|f| &f.class_desc == class_desc && !f.is_static)
                .map(|f| (field_idx(&f.class_desc, &f.name, &f.field_type), f.access_flags))
                .collect();
            instance_f.sort_by_key(|x| x.0);

            let mut direct_m: Vec<(u32, u32, u32)> = self
                .methods
                .iter()
                .enumerate()
                .filter(|(_, m)| &m.class_desc == class_desc && m.is_direct)
                .map(|(idx, m)| {
                    (
                        method_idx(&m.class_desc, &m.name, &m.params, &m.return_type),
                        m.access_flags,
                        method_code_offs[idx],
                    )
                })
                .collect();
            direct_m.sort_by_key(|x| x.0);

            let mut virtual_m: Vec<(u32, u32, u32)> = self
                .methods
                .iter()
                .enumerate()
                .filter(|(_, m)| &m.class_desc == class_desc && !m.is_direct)
                .map(|(idx, m)| {
                    (
                        method_idx(&m.class_desc, &m.name, &m.params, &m.return_type),
                        m.access_flags,
                        method_code_offs[idx],
                    )
                })
                .collect();
            virtual_m.sort_by_key(|x| x.0);

            if static_f.is_empty()
                && instance_f.is_empty()
                && direct_m.is_empty()
                && virtual_m.is_empty()
            {
                continue;
            }

            let cd_off = buf.len() as u32;
            class_data_offs[c_i] = cd_off;
            write_uleb128(&mut buf, static_f.len() as u32);
            write_uleb128(&mut buf, instance_f.len() as u32);
            write_uleb128(&mut buf, direct_m.len() as u32);
            write_uleb128(&mut buf, virtual_m.len() as u32);

            let mut prev = 0;
            for (f_i, flags) in static_f {
                write_uleb128(&mut buf, f_i - prev);
                write_uleb128(&mut buf, flags);
                prev = f_i;
            }
            let mut prev = 0;
            for (f_i, flags) in instance_f {
                write_uleb128(&mut buf, f_i - prev);
                write_uleb128(&mut buf, flags);
                prev = f_i;
            }
            let mut prev = 0;
            for (m_i, flags, c_off) in direct_m {
                write_uleb128(&mut buf, m_i - prev);
                write_uleb128(&mut buf, flags);
                write_uleb128(&mut buf, c_off);
                prev = m_i;
            }
            let mut prev = 0;
            for (m_i, flags, c_off) in virtual_m {
                write_uleb128(&mut buf, m_i - prev);
                write_uleb128(&mut buf, flags);
                write_uleb128(&mut buf, c_off);
                prev = m_i;
            }
        }

        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // Write index tables
        for (i, &s_off) in string_data_offs.iter().enumerate() {
            write_u32(&mut buf, string_ids_off + i * 4, s_off);
        }
        for (i, t) in types.iter().enumerate() {
            write_u32(&mut buf, type_ids_off + i * 4, str_idx(t));
        }
        for (i, (ret, params)) in protos.iter().enumerate() {
            let shorty = compute_shorty(params, ret);
            let pos = proto_ids_off + i * 12;
            write_u32(&mut buf, pos, str_idx(&shorty));
            write_u32(&mut buf, pos + 4, type_idx(ret));
            write_u32(&mut buf, pos + 8, proto_param_offs[i]);
        }
        for (i, (c, n, ft)) in fields.iter().enumerate() {
            let pos = field_ids_off + i * 8;
            write_u16(&mut buf, pos, type_idx(c) as u16);
            write_u16(&mut buf, pos + 2, type_idx(ft) as u16);
            write_u32(&mut buf, pos + 4, str_idx(n));
        }
        for (i, (c, n, p, r)) in method_refs.iter().enumerate() {
            let pos = method_ids_off + i * 8;
            write_u16(&mut buf, pos, type_idx(c) as u16);
            write_u16(&mut buf, pos + 2, proto_idx(r, p));
            write_u32(&mut buf, pos + 4, str_idx(n));
        }
        for (i, (c, sup)) in class_list.iter().enumerate() {
            let pos = class_defs_off + i * 32;
            write_u32(&mut buf, pos, type_idx(c));
            write_u32(&mut buf, pos + 4, 0x0001); // ACC_PUBLIC
            write_u32(&mut buf, pos + 8, type_idx(sup));
            write_u32(&mut buf, pos + 12, 0); // interfaces_off
            write_u32(&mut buf, pos + 16, NO_INDEX); // source_file_idx
            write_u32(&mut buf, pos + 20, 0); // annotations_off
            write_u32(&mut buf, pos + 24, class_data_offs[i]);
            write_u32(&mut buf, pos + 28, 0); // static_values_off
        }

        // Write DEX header
        let file_size = buf.len() as u32;
        let data_size = file_size - (data_off as u32);
        buf[0..8].copy_from_slice(b"dex\n039\0");
        write_u32(&mut buf, 0x20, file_size);
        write_u32(&mut buf, 0x24, DEX_HEADER_SIZE as u32);
        write_u32(&mut buf, 0x28, ENDIAN_CONSTANT);
        write_u32(&mut buf, 0x2C, 0); // link_size
        write_u32(&mut buf, 0x30, 0); // link_off
        write_u32(&mut buf, 0x34, 0); // map_off
        write_u32(&mut buf, 0x38, strings.len() as u32);
        write_u32(&mut buf, 0x3C, string_ids_off as u32);
        write_u32(&mut buf, 0x40, types.len() as u32);
        write_u32(&mut buf, 0x44, type_ids_off as u32);
        write_u32(&mut buf, 0x48, protos.len() as u32);
        write_u32(&mut buf, 0x4C, proto_ids_off as u32);
        write_u32(&mut buf, 0x50, fields.len() as u32);
        write_u32(&mut buf, 0x54, field_ids_off as u32);
        write_u32(&mut buf, 0x58, method_refs.len() as u32);
        write_u32(&mut buf, 0x5C, method_ids_off as u32);
        write_u32(&mut buf, 0x60, class_list.len() as u32);
        write_u32(&mut buf, 0x64, class_defs_off as u32);
        write_u32(&mut buf, 0x68, data_size);
        write_u32(&mut buf, 0x6C, data_off as u32);

        let mut dex = DexFile::parse(buf).expect("DexBuilder must produce valid DEX");
        dex.update_hashes();
        dex.data
    }
}

/// Encode a single try/catch-all block for testing `CodeItem` try/handler adjustment.
pub fn encode_single_try_catch_all(start_addr: u32, insn_count: u16, catch_all_addr: u32) -> Vec<u8> {
    let mut handlers = Vec::new();
    write_uleb128(&mut handlers, 1); // 1 handler
    let handler_off = (handlers.len() - 1) as u16;
    write_sleb128(&mut handlers, 0); // size 0 -> catch-all only
    write_uleb128(&mut handlers, catch_all_addr);

    let mut out = Vec::with_capacity(8 + handlers.len());
    out.extend_from_slice(&start_addr.to_le_bytes());
    out.extend_from_slice(&insn_count.to_le_bytes());
    out.extend_from_slice(&handler_off.to_le_bytes());
    out.extend_from_slice(&handlers);
    out
}

fn compute_shorty(params: &[String], return_type: &str) -> String {
    let mut s = String::with_capacity(1 + params.len());
    s.push(type_to_shorty_char(return_type));
    for p in params {
        s.push(type_to_shorty_char(p));
    }
    s
}

fn type_to_shorty_char(desc: &str) -> char {
    match desc.chars().next().unwrap_or('V') {
        '[' => 'L',
        c => c,
    }
}
