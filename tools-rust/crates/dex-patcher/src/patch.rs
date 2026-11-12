//! High-level DEX bytecode patching operations:
//! - `stub_method` (`--return true|false`, `--return-void`, `--return-int <val>`)
//! - `replace_string` (string table entry mutation and `const-string` reference rewriting)
//! - `replace_sget_with_const_string` (`sget-object Build->MODEL` -> `const-string "<MODEL>"`)
//! - `patch_apk_protection` (`ApkSignatureVerifier` in `framework.jar`)
//! - `patch_services_jar` (`ScanPackageUtils`, `getMinimumSignatureSchemeVersionForTargetSdk`, `ReconcilePackageUtils`)
//! - `patch_inspiration_aod_gate` (`oplus_keyguard_workshop_aod_support` in `Aod.apk` / `Wallpapers.apk`)

use crate::dex::{
    insert_insns_at, insn_len, CodeItem, DexFile, ACC_ABSTRACT, ACC_NATIVE,
};
use anyhow::{bail, Result};
use regex::Regex;

/// Return value specification for `stub-method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnSpec {
    /// `const/4 v0, 0x1` + `return v0`
    True,
    /// `const/4 v0, 0x0` + `return v0`
    False,
    /// `return-void`
    Void,
    /// `const/4 v0, <val>` or `const/16 v0, <val>` or `const v0, <val>` + `return v0`
    Int(i32),
}

impl ReturnSpec {
    /// Parse a string like `"true"`, `"false"`, `"void"`, `"1"`, `"0"`, `"0x22"`, `"-1"`.
    pub fn parse_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("true") {
            return Ok(Self::True);
        }
        if trimmed.eq_ignore_ascii_case("false") {
            return Ok(Self::False);
        }
        if trimmed.eq_ignore_ascii_case("void") {
            return Ok(Self::Void);
        }
        let val = parse_int_literal(trimmed)?;
        Ok(Self::Int(val))
    }

    /// Encode the Dalvik bytecode instructions (in 16-bit code units) for this stub return.
    pub fn encode_insns(self) -> Vec<u16> {
        match self {
            Self::Void => vec![0x000e], // return-void
            Self::True => vec![0x1012, 0x000f], // const/4 v0, 0x1; return v0
            Self::False => vec![0x0012, 0x000f], // const/4 v0, 0x0; return v0
            Self::Int(val) => {
                if (-8..=7).contains(&val) {
                    // const/4 v0, #+B (11n): high nibble of high byte is 4-bit signed B, low nibble is reg 0
                    let nibble = ((val as i8 as u8) & 0x0f) as u16;
                    vec![0x0012 | (nibble << 12), 0x000f]
                } else if (i16::MIN as i32..=i16::MAX as i32).contains(&val) {
                    // const/16 v0, #+BBBB (21s): [0x0013, val as u16], return v0: [0x000f]
                    vec![0x0013, (val as i16) as u16, 0x000f]
                } else {
                    // const v0, #+BBBBBBBB (31i): [0x0014, lo16, hi16], return v0: [0x000f]
                    let bits = val as u32;
                    vec![
                        0x0014,
                        (bits & 0xffff) as u16,
                        (bits >> 16) as u16,
                        0x000f,
                    ]
                }
            }
        }
    }

    /// Always encode as `const/16 v0, <val>; return v0` when `val` fits in `i16`.
    pub fn encode_insns_const16(val: i16) -> Vec<u16> {
        vec![0x0013, val as u16, 0x000f]
    }
}

/// Parse a decimal or hexadecimal (`0x...` / `-0x...`) integer literal.
pub fn parse_int_literal(s: &str) -> Result<i32> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Ok(i32::from_str_radix(hex, 16)?)
    } else if let Some(hex) = trimmed
        .strip_prefix("-0x")
        .or_else(|| trimmed.strip_prefix("-0X"))
    {
        let v = i32::from_str_radix(hex, 16)?;
        Ok(-v)
    } else {
        Ok(trimmed.parse::<i32>()?)
    }
}

/// Check if a DEX class descriptor (e.g. `"Landroid/util/apk/ApkSignatureVerifier;"`)
/// matches a user-supplied filter (e.g. `"Landroid/util/apk/ApkSignatureVerifier;"`,
/// `"android/util/apk/ApkSignatureVerifier"`, `"android.util.apk.ApkSignatureVerifier"`,
/// or simple class name `"ApkSignatureVerifier"`).
pub fn class_matches(class_descriptor: &str, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }
    if class_descriptor == filter {
        return true;
    }
    let stripped_desc = class_descriptor
        .strip_prefix('L')
        .unwrap_or(class_descriptor);
    let stripped_desc = stripped_desc
        .strip_suffix(';')
        .unwrap_or(stripped_desc);
    let normalized_filter = filter
        .strip_prefix('L')
        .unwrap_or(filter);
    let normalized_filter = normalized_filter
        .strip_suffix(';')
        .unwrap_or(normalized_filter)
        .replace('.', "/");

    if stripped_desc == normalized_filter {
        return true;
    }
    // Match by simple class name (after last '/')
    let simple_name = stripped_desc.rsplit('/').next().unwrap_or(stripped_desc);
    simple_name == normalized_filter || stripped_desc.ends_with(&format!("/{}", normalized_filter))
}

/// Split a method spec like `"onBootPhase(I)V"` into `("onBootPhase", Some("(I)V"))`,
/// or `"isGmsRestricted"` into `("isGmsRestricted", None)`.
pub fn split_method_spec<'a>(
    method_spec: &'a str,
    explicit_proto: Option<&'a str>,
) -> (&'a str, Option<&'a str>) {
    if let Some(paren_idx) = method_spec.find('(') {
        let name = &method_spec[..paren_idx];
        let proto = &method_spec[paren_idx..];
        (name, explicit_proto.or(Some(proto)))
    } else {
        (method_spec, explicit_proto)
    }
}

/// Stub matching method(s) in `dex` with `return_spec`.
/// Returns the number of methods patched.
pub fn stub_method(
    dex: &mut DexFile,
    class_filter: Option<&str>,
    method_spec: &str,
    proto_filter: Option<&str>,
    return_spec: ReturnSpec,
) -> Result<usize> {
    let (target_name, target_proto) = split_method_spec(method_spec, proto_filter);
    let stub_insns = return_spec.encode_insns();
    let mut patched_count = 0usize;

    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        let Some(class_desc) = dex.get_type_descriptor(class_def.class_idx) else {
            continue;
        };
        if let Some(cf) = class_filter {
            if !class_matches(class_desc, cf) {
                continue;
            }
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            let Some((_, m_name, m_proto)) = dex.get_method_signature(em.method_idx) else {
                continue;
            };
            let name_matches = m_name == target_name
                || (target_name.eq_ignore_ascii_case("onBootPhase")
                    && m_name.eq_ignore_ascii_case(target_name));
            if !name_matches {
                continue;
            }
            if let Some(tp) = target_proto {
                if m_proto != tp {
                    continue;
                }
            }

            if (em.access_flags & (ACC_ABSTRACT | ACC_NATIVE)) != 0 || em.code_off == 0 {
                bail!(
                    "Cannot stub abstract/native method {}->{}{}",
                    dex.get_type_descriptor(class_def.class_idx).unwrap_or("?"),
                    m_name,
                    m_proto
                );
            }

            let old_code = dex.read_code_item(em.code_off)?;
            let registers_size = match return_spec {
                ReturnSpec::Void => old_code.ins_size.max(old_code.registers_size),
                _ => old_code.registers_size.max(old_code.ins_size + 1).max(1),
            };
            let new_code = CodeItem {
                offset: old_code.offset,
                registers_size,
                ins_size: old_code.ins_size,
                outs_size: 0,
                tries_size: 0,
                debug_info_off: 0,
                insns: stub_insns.clone(),
                tries_and_handlers: Vec::new(),
            };

            dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            patched_count += 1;
        }
    }

    if patched_count > 0 {
        dex.update_hashes();
    }
    Ok(patched_count)
}

/// Replace string occurrences in `dex`:
/// - When `class_filter` and `method_filter` are both `None`:
///   Replaces the string table entry for `old_str` with `new_str` (affecting all references),
///   and if `new_str` already existed at another index `new_idx`, also rewrites `const-string`
///   and `const-string/jumbo` instructions from `old_idx` to `new_idx`.
/// - When `class_filter` or `method_filter` is `Some`:
///   Rewrites `const-string` / `const-string/jumbo` instructions in matching methods.
pub fn replace_string(
    dex: &mut DexFile,
    old_str: &str,
    new_str: &str,
    class_filter: Option<&str>,
    method_filter: Option<&str>,
) -> Result<usize> {
    let Some(old_idx) = dex.strings.iter().position(|s| s == old_str) else {
        return Ok(0);
    };
    let old_idx = old_idx as u32;
    let existing_new_idx = dex
        .strings
        .iter()
        .position(|s| s == new_str)
        .map(|i| i as u32);

    let mut count = 0usize;

    if class_filter.is_none() && method_filter.is_none() && dex.header.map_off == 0 {
        // Synthetic / unmapped DEX: mutate string entry directly at `old_idx` and update any
        // duplicate references if `new_str` also existed at `new_idx`.
        if let Some(new_idx) = existing_new_idx {
            if new_idx != old_idx {
                count += rewrite_const_string_insns(dex, old_idx, new_idx, None, None)?;
            }
        }
        dex.set_string(old_idx, new_str)?;
        count += 1;
        dex.update_hashes();
        return Ok(count);
    }

    // Mapped DEX (`map_off != 0`) or scoped replacement: insert `new_str` cleanly in sorted
    // `string_ids` order without breaking sort order or unrelated references, then rewrite
    // `const-string` / `const-string/jumbo` instructions. Note `insert_string` shifts indices >= k,
    // so resolve `old_idx` again right after inserting `new_str`.
    let target_new_idx = if let Some(new_idx) = existing_new_idx {
        new_idx
    } else {
        dex.add_or_get_string(new_str)?
    };
    let updated_old_idx = dex
        .strings
        .iter()
        .position(|s| s == old_str)
        .map(|i| i as u32)
        .unwrap_or(old_idx);

    count += rewrite_const_string_insns(dex, updated_old_idx, target_new_idx, class_filter, method_filter)?;
    if count > 0 {
        dex.update_hashes();
    }
    Ok(count)
}

fn rewrite_const_string_insns(
    dex: &mut DexFile,
    old_idx: u32,
    new_idx: u32,
    class_filter: Option<&str>,
    method_filter: Option<&str>,
) -> Result<usize> {
    let mut rewritten = 0usize;

    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        if let Some(cf) = class_filter {
            let Some(cd) = dex.get_type_descriptor(class_def.class_idx) else {
                continue;
            };
            if !class_matches(cd, cf) {
                continue;
            }
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            if let Some(mf) = method_filter {
                let Some((_, m_name, _)) = dex.get_method_signature(em.method_idx) else {
                    continue;
                };
                if m_name != mf {
                    continue;
                }
            }

            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();
            let mut changed = false;

            let mut pc = 0;
            while pc < new_code.insns.len() {
                let len = insn_len(&new_code.insns, pc);
                let op = (new_code.insns[pc] & 0xff) as u8;
                if op == 0x1a && pc + 1 < new_code.insns.len() {
                    // const-string vAA, string@BBBB
                    let s_idx = new_code.insns[pc + 1] as u32;
                    if s_idx == old_idx && new_idx <= u16::MAX as u32 {
                        new_code.insns[pc + 1] = new_idx as u16;
                        changed = true;
                        rewritten += 1;
                    }
                } else if op == 0x1b && pc + 2 < new_code.insns.len() {
                    // const-string/jumbo vAA, string@BBBBBBBB
                    let s_idx =
                        (new_code.insns[pc + 1] as u32) | ((new_code.insns[pc + 2] as u32) << 16);
                    if s_idx == old_idx {
                        new_code.insns[pc + 1] = (new_idx & 0xffff) as u16;
                        new_code.insns[pc + 2] = (new_idx >> 16) as u16;
                        changed = true;
                        rewritten += 1;
                    }
                }
                pc += len;
            }

            if changed {
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            }
        }
    }

    Ok(rewritten)
}

/// Apply the APK Protection patch to a `DexFile` (`framework.jar` / `ApkSignatureVerifier`):
/// 1. Stub `Landroid/util/apk/ApkSignatureVerifier;->getMinimumSignatureSchemeVersionForTargetSdk`
///    to return `1` (`const/4 v0, 0x1; return v0`).
/// 2. In `Landroid/util/apk/ApkSignatureVerifier;->verifySignaturesInternal`, inject
///    `const/4 p3, 0x0` before calls to `Landroid/util/apk/ApkSignatureVerifier;->verifyV*`.
pub fn patch_apk_protection_dex(dex: &mut DexFile) -> Result<usize> {
    let mut modifications = 0usize;

    // 1. Stub getMinimumSignatureSchemeVersionForTargetSdk -> return 1 (True / Int(1))
    modifications += stub_method(
        dex,
        Some("Landroid/util/apk/ApkSignatureVerifier;"),
        "getMinimumSignatureSchemeVersionForTargetSdk",
        None,
        ReturnSpec::True,
    )?;

    // 2. In verifySignaturesInternal, inject `const/4 p3, 0x0` before `ApkSignatureVerifier->verifyV*`
    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        let Some(class_desc) = dex.get_type_descriptor(class_def.class_idx) else {
            continue;
        };
        if !class_matches(class_desc, "Landroid/util/apk/ApkSignatureVerifier;") {
            continue;
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            let Some((_, m_name, _)) = dex.get_method_signature(em.method_idx) else {
                continue;
            };
            if m_name != "verifySignaturesInternal" {
                continue;
            }

            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();

            // Determine the register index corresponding to parameter `p3`.
            // For a method with `registers_size` total registers and `ins_size` parameter words,
            // `p0` is `registers_size - ins_size`, so `p3` is `registers_size - ins_size + 3`.
            let p3_reg = if new_code.ins_size >= 4 && new_code.registers_size >= new_code.ins_size {
                new_code.registers_size - new_code.ins_size + 3
            } else if new_code.registers_size >= 4 {
                new_code.registers_size - 1
            } else {
                new_code.registers_size = 4;
                3
            };

            let const_p3_zero: Vec<u16> = if p3_reg < 16 {
                // const/4 v{p3_reg}, 0x0 -> opcode 0x12, high byte = (0 << 4) | p3_reg
                vec![0x0012 | ((p3_reg & 0x0f) << 8)]
            } else {
                // const/16 v{p3_reg}, 0x0 -> opcode 0x13, high byte = p3_reg, second word = 0x0000
                vec![0x0013 | ((p3_reg & 0xff) << 8), 0x0000]
            };

            // Collect PCs of `invoke-*` calls to `Landroid/util/apk/ApkSignatureVerifier;->verifyV*`
            // that are not already preceded by `const/4 p3, 0x0`.
            let mut insert_pcs = Vec::new();
            let mut pc = 0;
            let mut prev_pc: Option<usize> = None;
            while pc < new_code.insns.len() {
                let len = insn_len(&new_code.insns, pc);
                let op = (new_code.insns[pc] & 0xff) as u8;
                let is_invoke = matches!(op, 0x6e..=0x72 | 0x74..=0x78);
                if is_invoke && pc + 1 < new_code.insns.len() {
                    let callee_idx = new_code.insns[pc + 1] as u32;
                    if let Some((callee_class, callee_name, _)) =
                        dex.get_method_signature(callee_idx)
                    {
                        if class_matches(&callee_class, "Landroid/util/apk/ApkSignatureVerifier;")
                            && callee_name.starts_with("verifyV")
                        {
                            let already_patched = if let Some(prev) = prev_pc {
                                new_code.insns.get(prev..pc) == Some(const_p3_zero.as_slice())
                            } else {
                                false
                            };
                            if !already_patched {
                                insert_pcs.push(pc);
                            }
                        }
                    }
                }
                prev_pc = Some(pc);
                pc += len;
            }

            if !insert_pcs.is_empty() {
                // Insert in reverse PC order (or track cumulative shift) so earlier insertions
                // adjust all branch offsets accurately.
                let mut cumulative_shift = 0usize;
                for orig_pc in insert_pcs {
                    let target_pc = orig_pc + cumulative_shift;
                    insert_insns_at(&mut new_code, target_pc, &const_p3_zero)?;
                    cumulative_shift += const_p3_zero.len();
                    modifications += 1;
                }
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            }
        }
    }

    if modifications > 0 {
        dex.update_hashes();
    }
    Ok(modifications)
}

/// Replace `sget-object vAA, <field_descriptor>` (e.g. `Landroid/os/Build;->MODEL:Ljava/lang/String;`)
/// with `const-string vAA, "<replacement_value>"` in matching classes.
pub fn replace_sget_with_const_string(
    dex: &mut DexFile,
    target_class_desc: &str,
    target_field_name: &str,
    replacement_value: &str,
    class_filter: Option<&str>,
) -> Result<usize> {
    // Find target field_idx
    let Some(target_field_idx) = (0..dex.fields.len()).find(|&idx| {
        if let Some((c_desc, f_name, _)) = dex.get_field_signature(idx as u32) {
            class_matches(&c_desc, target_class_desc) && f_name == target_field_name
        } else {
            false
        }
    }) else {
        return Ok(0);
    };
    let target_field_idx = target_field_idx as u16;

    // Quick scan: only insert `replacement_value` into `string_ids` if `sget-object` target actually appears.
    let mut has_matching_sget = false;
    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        if let Some(cf) = class_filter {
            let Some(cd) = dex.get_type_descriptor(class_def.class_idx) else {
                continue;
            };
            if !class_matches(cd, cf) {
                continue;
            }
        }
        let class_data = dex.read_class_data(class_def.class_data_off)?;
        for em in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            if em.code_off == 0 {
                continue;
            }
            let code = dex.read_code_item(em.code_off)?;
            let mut pc = 0;
            while pc < code.insns.len() {
                let len = insn_len(&code.insns, pc);
                let op = (code.insns[pc] & 0xff) as u8;
                if op == 0x62 && pc + 1 < code.insns.len() && code.insns[pc + 1] == target_field_idx {
                    has_matching_sget = true;
                    break;
                }
                pc += len;
            }
            if has_matching_sget {
                break;
            }
        }
        if has_matching_sget {
            break;
        }
    }
    if !has_matching_sget {
        return Ok(0);
    }

    // Safely obtain or insert `replacement_value` in sorted MUTF-8 order without mutating `f.name_idx`.
    let string_idx = dex.add_or_get_string(replacement_value)?;

    let mut patched = 0usize;
    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        if let Some(cf) = class_filter {
            let Some(cd) = dex.get_type_descriptor(class_def.class_idx) else {
                continue;
            };
            if !class_matches(cd, cf) {
                continue;
            }
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();
            let mut changed = false;

            if string_idx <= u16::MAX as u32 {
                let mut pc = 0;
                while pc < new_code.insns.len() {
                    let len = insn_len(&new_code.insns, pc);
                    let word = new_code.insns[pc];
                    let op = (word & 0xff) as u8;
                    // 0x62 = sget-object vAA, field@BBBB (21c)
                    if op == 0x62 && pc + 1 < new_code.insns.len() && new_code.insns[pc + 1] == target_field_idx {
                        let reg_aa = word & 0xff00;
                        // 0x1a = const-string vAA, string@BBBB (21c)
                        new_code.insns[pc] = reg_aa | 0x001a;
                        new_code.insns[pc + 1] = string_idx as u16;
                        changed = true;
                        patched += 1;
                    }
                    pc += len;
                }
            } else {
                // `string_idx > 0xFFFF`: upgrade 2-unit sget-object -> 3-unit const-string/jumbo (0x1b).
                let lo = (string_idx & 0xffff) as u16;
                let hi = (string_idx >> 16) as u16;
                let mut match_pcs = Vec::new();
                let mut pc = 0;
                while pc < new_code.insns.len() {
                    let len = insn_len(&new_code.insns, pc);
                    let word = new_code.insns[pc];
                    let op = (word & 0xff) as u8;
                    if op == 0x62 && pc + 1 < new_code.insns.len() && new_code.insns[pc + 1] == target_field_idx {
                        match_pcs.push((pc, word & 0xff00));
                    }
                    pc += len;
                }
                for (orig_pc, reg_aa) in match_pcs.into_iter().rev() {
                    insert_insns_at(&mut new_code, orig_pc + 2, &[hi])?;
                    new_code.insns[orig_pc] = reg_aa | 0x001b;
                    new_code.insns[orig_pc + 1] = lo;
                    changed = true;
                    patched += 1;
                }
            }

            if changed {
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            }
        }
    }

    if patched > 0 {
        dex.update_hashes();
    }
    Ok(patched)
}

/// Apply the `services.jar` signature & shared-UID patches from `port.sh`:
/// 1. In `ScanPackageUtils`: stub `assertMinSignatureSchemeIsValid` to `return-void`.
/// 2. In `Lcom/android/server/pm/` classes: replace `invoke-* ...->getMinimumSignatureSchemeVersionForTargetSdk`
///    + `move-result vX` with `const/4 vX, 0x0` (and `nop` padding).
/// 3. In `ReconcilePackageUtils`: force register `vX` to `0x1` (`const/4 vX, 0x1`) before
///    `sput-boolean vX, ...->ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS:Z`.
pub fn patch_services_dex(dex: &mut DexFile) -> Result<usize> {
    let mut modifications = 0usize;

    // 1. ScanPackageUtils -> assertMinSignatureSchemeIsValid (return-void)
    modifications += stub_method(
        dex,
        Some("ScanPackageUtils"),
        "assertMinSignatureSchemeIsValid",
        None,
        ReturnSpec::Void,
    )?;

    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        let Some(class_desc) = dex
            .get_type_descriptor(class_def.class_idx)
            .map(|s| s.to_string())
        else {
            continue;
        };

        let is_pm_class = class_desc.starts_with("Lcom/android/server/pm/");
        let is_reconcile = class_matches(&class_desc, "ReconcilePackageUtils");
        if !is_pm_class && !is_reconcile {
            continue;
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();
            let mut changed = false;

            // 2. Replace invoke-* getMinimumSignatureSchemeVersionForTargetSdk + move-result vX -> const/4 vX, 0x0
            if is_pm_class {
                let mut pc = 0;
                while pc < new_code.insns.len() {
                    let len = insn_len(&new_code.insns, pc);
                    let op = (new_code.insns[pc] & 0xff) as u8;
                    if matches!(op, 0x6e..=0x72 | 0x74..=0x78) && pc + 3 < new_code.insns.len() {
                        let callee_idx = new_code.insns[pc + 1] as u32;
                        let next_word = new_code.insns[pc + 3];
                        let next_op = (next_word & 0xff) as u8;
                        if next_op == 0x0a {
                            // 0x0a = move-result vAA
                            if let Some((_, callee_name, _)) = dex.get_method_signature(callee_idx)
                            {
                                if callee_name == "getMinimumSignatureSchemeVersionForTargetSdk" {
                                    let reg = (next_word >> 8) & 0xff;
                                    if reg < 16 {
                                        // const/4 v{reg}, 0x0 (1 unit) + 3 nop units
                                        new_code.insns[pc] = 0x0012 | (reg << 8);
                                        new_code.insns[pc + 1] = 0x0000;
                                        new_code.insns[pc + 2] = 0x0000;
                                        new_code.insns[pc + 3] = 0x0000;
                                    } else {
                                        // const/16 v{reg}, 0x0 (2 units) + 2 nop units
                                        new_code.insns[pc] = 0x0013 | (reg << 8);
                                        new_code.insns[pc + 1] = 0x0000;
                                        new_code.insns[pc + 2] = 0x0000;
                                        new_code.insns[pc + 3] = 0x0000;
                                    }
                                    changed = true;
                                    modifications += 1;
                                }
                            }
                        }
                    }
                    pc += len;
                }
            }

            // 3. ReconcilePackageUtils -> ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS set to 0x1
            if is_reconcile {
                let mut insert_pcs = Vec::new();
                let mut pc = 0;
                let mut prev_pc: Option<usize> = None;
                while pc < new_code.insns.len() {
                    let len = insn_len(&new_code.insns, pc);
                    let word = new_code.insns[pc];
                    let op = (word & 0xff) as u8;
                    // 0x6a = sput-boolean vAA, field@BBBB
                    if op == 0x6a && pc + 1 < new_code.insns.len() {
                        let f_idx = new_code.insns[pc + 1] as u32;
                        if let Some((_, f_name, _)) = dex.get_field_signature(f_idx) {
                            if f_name == "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS" {
                                let reg = (word >> 8) & 0xff;
                                let const_one = if reg < 16 {
                                    vec![0x1012 | (reg << 8)]
                                } else {
                                    vec![0x0013 | (reg << 8), 0x0001]
                                };
                                let already_set = if let Some(prev) = prev_pc {
                                    new_code.insns.get(prev..pc) == Some(const_one.as_slice())
                                } else {
                                    false
                                };
                                if !already_set {
                                    // If immediately preceded by `const/4 v{reg}, <lit>` and not targeted by a branch,
                                    // overwrite in-place to avoid growing the code_item.
                                    let replaced_in_place = if let Some(prev) = prev_pc {
                                        if reg < 16
                                            && prev + 1 == pc
                                            && (new_code.insns[prev] & 0x0fff) == (0x0012 | (reg << 8))
                                            && !is_branch_target(&new_code.insns, pc)
                                        {
                                            new_code.insns[prev] = 0x1012 | (reg << 8);
                                            changed = true;
                                            modifications += 1;
                                            true
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    };
                                    if !replaced_in_place {
                                        insert_pcs.push((pc, const_one));
                                    }
                                }
                            }
                        }
                    }
                    prev_pc = Some(pc);
                    pc += len;
                }

                let mut shift = 0usize;
                for (orig_pc, insn_to_insert) in insert_pcs {
                    insert_insns_at(&mut new_code, orig_pc + shift, &insn_to_insert)?;
                    shift += insn_to_insert.len();
                    changed = true;
                    modifications += 1;
                }
            }

            if changed {
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            }
        }
    }

    if modifications > 0 {
        dex.update_hashes();
    }
    Ok(modifications)
}

fn is_branch_target(insns: &[u16], target_pc: usize) -> bool {
    let mut pc = 0;
    while pc < insns.len() {
        let len = insn_len(insns, pc);
        let word = insns[pc];
        if word != 0x0100 && word != 0x0200 && word != 0x0300 {
            let op = (word & 0xff) as u8;
            match op {
                0x28 => {
                    let rel = ((word >> 8) as u8) as i8 as isize;
                    if pc as isize + rel == target_pc as isize {
                        return true;
                    }
                }
                0x29 | 0x32..=0x3d if pc + 1 < insns.len() => {
                    let rel = (insns[pc + 1] as i16) as isize;
                    if pc as isize + rel == target_pc as isize {
                        return true;
                    }
                }
                0x2a if pc + 2 < insns.len() => {
                    let rel =
                        ((insns[pc + 1] as u32) | ((insns[pc + 2] as u32) << 16)) as i32 as isize;
                    if pc as isize + rel == target_pc as isize {
                        return true;
                    }
                }
                _ => {}
            }
        }
        pc += len;
    }
    false
}

/// Apply the ColorOS 16 inspiration AOD gate patch (`bin/patch_inspiration_aod_gate.py`) directly on DEX:
/// In methods referencing `"oplus_keyguard_workshop_aod_support"` and invoking
/// `Landroid/provider/Settings$Secure;->getInt` or `->b(Landroid/content/ContentResolver;Ljava/lang/String;I)I`,
/// injects `const/4 vX, 0x1` immediately after the following `move-result vX`.
pub fn patch_inspiration_aod_gate_dex(dex: &mut DexFile) -> Result<usize> {
    let Some(setting_str_idx) = dex
        .strings
        .iter()
        .position(|s| s == "oplus_keyguard_workshop_aod_support")
    else {
        return Ok(0);
    };
    let setting_str_idx = setting_str_idx as u32;

    let mut modifications = 0usize;
    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();

            // Scan for const-string "oplus_keyguard_workshop_aod_support", then invoke-* getInt/b, then move-result vX
            let mut pc = 0;
            let mut seen_key = false;
            let mut waiting_for_move_result = false;
            let mut insert_action: Option<(usize, Vec<u16>)> = None;

            while pc < new_code.insns.len() {
                let len = insn_len(&new_code.insns, pc);
                let word = new_code.insns[pc];
                let op = (word & 0xff) as u8;

                if op == 0x1a && pc + 1 < new_code.insns.len() {
                    if new_code.insns[pc + 1] as u32 == setting_str_idx {
                        seen_key = true;
                    }
                } else if op == 0x1b && pc + 2 < new_code.insns.len() {
                    let idx =
                        (new_code.insns[pc + 1] as u32) | ((new_code.insns[pc + 2] as u32) << 16);
                    if idx == setting_str_idx {
                        seen_key = true;
                    }
                } else if seen_key && matches!(op, 0x6e..=0x72 | 0x74..=0x78) && pc + 1 < new_code.insns.len() {
                    let callee_idx = new_code.insns[pc + 1] as u32;
                    if let Some((c_desc, m_name, m_proto)) = dex.get_method_signature(callee_idx) {
                        let is_marker = (c_desc == "Landroid/provider/Settings$Secure;"
                            && m_name == "getInt")
                            || (m_name == "b"
                                && m_proto
                                    == "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");
                        if is_marker {
                            waiting_for_move_result = true;
                        } else if waiting_for_move_result {
                            // Another invoke before move-result cancels waiting
                            waiting_for_move_result = false;
                        }
                    }
                } else if waiting_for_move_result && (op == 0x0a || op == 0x0b) {
                    let reg = (word >> 8) & 0xff;
                    let patch_insn = if reg < 16 {
                        vec![0x1012 | (reg << 8)] // const/4 v{reg}, 0x1
                    } else {
                        vec![0x0013 | (reg << 8), 0x0001] // const/16 v{reg}, 0x1
                    };
                    let after_pc = pc + len;
                    let already_patched = new_code
                        .insns
                        .get(after_pc..after_pc + patch_insn.len())
                        == Some(patch_insn.as_slice());
                    if !already_patched {
                        insert_action = Some((after_pc, patch_insn));
                    }
                    break;
                }

                pc += len;
            }

            if let Some((insert_pc, patch_insn)) = insert_action {
                insert_insns_at(&mut new_code, insert_pc, &patch_insn)?;
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
                modifications += 1;
            }
        }
    }

    if modifications > 0 {
        dex.update_hashes();
    }
    Ok(modifications)
}

/// Replace the `move-result vX` (`0x0a`) following a `const-string` matching `string_pattern`
/// with `const/16 vX, <replacement_int>` (or `const vX, <replacement_int>` if outside `i16`),
/// matching `bin/patchmethod_v2.py -k 'const-string.*"ro.product.first_api_level"' -hook 'const/16 reg, 0x22'`
/// (used for `OppoGallery2.apk`).
pub fn hook_move_result_after_string(
    dex: &mut DexFile,
    string_pattern: &str,
    replacement_int: i32,
    class_filter: Option<&str>,
    method_filter: Option<&str>,
) -> Result<usize> {
    // Allow both bare string (`"ro.product.first_api_level"`) and smali-style pattern
    // (`'const-string.*"ro.product.first_api_level"'`).
    let normalized_pattern = if string_pattern.starts_with("const-string") {
        Regex::new(r#"const-string[^\n"]*"([^"]+)""#)
            .ok()
            .and_then(|re| re.captures(string_pattern))
            .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| string_pattern.to_string())
    } else {
        string_pattern.to_string()
    };

    let regex = Regex::new(&normalized_pattern).ok();
    let matching_str_indices: std::collections::HashSet<u32> = dex
        .strings
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            *s == &normalized_pattern
                || regex
                    .as_ref()
                    .map(|re| re.is_match(s))
                    .unwrap_or(false)
        })
        .map(|(i, _)| i as u32)
        .collect();

    if matching_str_indices.is_empty() {
        return Ok(0);
    }

    let mut modifications = 0usize;
    for class_def_idx in 0..dex.class_defs.len() {
        let class_def = dex.class_defs[class_def_idx];
        if class_def.class_data_off == 0 {
            continue;
        }
        if let Some(cf) = class_filter {
            let Some(cd) = dex.get_type_descriptor(class_def.class_idx) else {
                continue;
            };
            if !class_matches(cd, cf) {
                continue;
            }
        }

        let class_data = dex.read_class_data(class_def.class_data_off)?;
        let all_methods: Vec<_> = class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
            .copied()
            .collect();

        for em in all_methods {
            if em.code_off == 0 {
                continue;
            }
            if let Some(mf) = method_filter {
                let Some((_, m_name, m_proto)) = dex.get_method_signature(em.method_idx) else {
                    continue;
                };
                let (t_name, t_proto) = split_method_spec(mf, None);
                if m_name != t_name {
                    continue;
                }
                if let Some(tp) = t_proto {
                    if m_proto != tp {
                        continue;
                    }
                }
            }

            let old_code = dex.read_code_item(em.code_off)?;
            let mut new_code = old_code.clone();
            let mut found_keyword = false;
            let mut seen_invoke = false;
            let mut replacements: Vec<(usize, Vec<u16>)> = Vec::new();

            let mut pc = 0;
            while pc < new_code.insns.len() {
                let len = insn_len(&new_code.insns, pc);
                let word = new_code.insns[pc];
                let op = (word & 0xff) as u8;

                if op == 0x1a && pc + 1 < new_code.insns.len() {
                    if matching_str_indices.contains(&(new_code.insns[pc + 1] as u32)) {
                        found_keyword = true;
                        seen_invoke = false;
                    }
                } else if op == 0x1b && pc + 2 < new_code.insns.len() {
                    let s_idx =
                        (new_code.insns[pc + 1] as u32) | ((new_code.insns[pc + 2] as u32) << 16);
                    if matching_str_indices.contains(&s_idx) {
                        found_keyword = true;
                        seen_invoke = false;
                    }
                } else if found_keyword {
                    if matches!(op, 0x6e..=0x72 | 0x74..=0x78) {
                        seen_invoke = true;
                    } else if op == 0x0a {
                        // move-result vAA -> replace with const/16 vAA, <val> (or const vAA, <val>)
                        let reg = (word >> 8) & 0xff;
                        let hook_insns = if (i16::MIN as i32..=i16::MAX as i32)
                            .contains(&replacement_int)
                        {
                            vec![0x0013 | (reg << 8), (replacement_int as i16) as u16]
                        } else {
                            let bits = replacement_int as u32;
                            vec![
                                0x0014 | (reg << 8),
                                (bits & 0xffff) as u16,
                                (bits >> 16) as u16,
                            ]
                        };
                        replacements.push((pc, hook_insns));
                        found_keyword = false;
                        seen_invoke = false;
                    } else if seen_invoke {
                        // Already patched (e.g. `const/16 vX, 0x22` immediately after invoke-static)
                        let already_hooked = (op == 0x13
                            && pc + 1 < new_code.insns.len()
                            && (new_code.insns[pc + 1] as i16 as i32) == replacement_int)
                            || (op == 0x14
                                && pc + 2 < new_code.insns.len()
                                && ((new_code.insns[pc + 1] as u32)
                                    | ((new_code.insns[pc + 2] as u32) << 16))
                                    == replacement_int as u32);
                        if already_hooked {
                            found_keyword = false;
                        }
                        seen_invoke = false;
                    }
                }

                pc += len;
            }

            if !replacements.is_empty() {
                // Apply in reverse PC order so earlier offsets stay valid before insertion.
                for (mr_pc, hook_insns) in replacements.into_iter().rev() {
                    if hook_insns.len() > 1 {
                        insert_insns_at(&mut new_code, mr_pc + 1, &hook_insns[1..])?;
                    }
                    new_code.insns[mr_pc] = hook_insns[0];
                    modifications += 1;
                }
                dex.write_code_item(class_def_idx, em.method_idx, &old_code, &new_code)?;
            }
        }
    }

    if modifications > 0 {
        dex.update_hashes();
    }
    Ok(modifications)
}


