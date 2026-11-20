//! Pure-Rust RSA PKCS#1 v1.5 SHA-256 signing, X.509 verification, and Base64 utilities.
//!
//! Supports:
//! - PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`, e.g. `otatools/key/testkey.key`)
//! - PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) and PKCS#8 DER (`otatools/key/testkey.pk8`)
//! - X.509 Certificate PEM (`-----BEGIN CERTIFICATE-----`, e.g. `otatools/key/testkey.x509.pem`)

use std::cmp::Ordering;
use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

/// SHA-256 DigestInfo DER prefix (RFC 8017 Section 9.2):
/// `SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING (32 bytes) }`
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard Base64 with `=` padding.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard Base64 (ignoring ASCII whitespace).
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut count = 0usize;
    let mut pad = 0usize;

    for b in input.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            buf[count] = 0;
            count += 1;
            pad += 1;
        } else {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => bail!("Invalid base64 byte: 0x{b:02x}"),
            };
            ensure!(pad == 0, "Unexpected base64 character after padding");
            buf[count] = val;
            count += 1;
        }
        if count == 4 {
            let v = ((buf[0] as u32) << 18)
                | ((buf[1] as u32) << 12)
                | ((buf[2] as u32) << 6)
                | (buf[3] as u32);
            out.push(((v >> 16) & 0xFF) as u8);
            if pad < 2 {
                out.push(((v >> 8) & 0xFF) as u8);
            }
            if pad == 0 {
                out.push((v & 0xFF) as u8);
            }
            count = 0;
            pad = 0;
        }
    }
    ensure!(count == 0, "Truncated base64 input");
    Ok(out)
}

fn decode_pem_block(pem: &str, header_marker: &str, footer_marker: &str) -> Result<Vec<u8>> {
    let start = pem
        .find(header_marker)
        .with_context(|| format!("Missing PEM header {header_marker}"))?
        + header_marker.len();
    let end = pem[start..]
        .find(footer_marker)
        .with_context(|| format!("Missing PEM footer {footer_marker}"))?
        + start;
    base64_decode(&pem[start..end])
}

// --- Minimal ASN.1 DER Reader ---

fn read_der_tlv<'a>(data: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8])> {
    ensure!(*pos < data.len(), "Truncated ASN.1 DER tag");
    let tag = data[*pos];
    *pos += 1;
    ensure!(*pos < data.len(), "Truncated ASN.1 DER length");
    let first_len = data[*pos];
    *pos += 1;

    let len = if first_len < 0x80 {
        first_len as usize
    } else {
        let num_bytes = (first_len & 0x7F) as usize;
        ensure!(
            num_bytes > 0 && num_bytes <= 4 && *pos + num_bytes <= data.len(),
            "Invalid ASN.1 DER length"
        );
        let mut v = 0usize;
        for _ in 0..num_bytes {
            v = (v << 8) | (data[*pos] as usize);
            *pos += 1;
        }
        v
    };
    ensure!(*pos + len <= data.len(), "Truncated ASN.1 DER value");
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok((tag, slice))
}

fn read_der_sequence<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let (tag, val) = read_der_tlv(data, pos)?;
    ensure!(tag == 0x30, "Expected ASN.1 SEQUENCE (0x30), got 0x{tag:02x}");
    Ok(val)
}

fn read_der_integer_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let (tag, val) = read_der_tlv(data, pos)?;
    ensure!(tag == 0x02, "Expected ASN.1 INTEGER (0x02), got 0x{tag:02x}");
    Ok(val)
}

// --- Arbitrary-precision unsigned integer (base 2^32, little-endian limbs) ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let first_nz = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let trimmed = &bytes[first_nz..];
        if trimmed.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::with_capacity(trimmed.len().div_ceil(4));
        let mut i = trimmed.len();
        while i > 0 {
            let start = i.saturating_sub(4);
            let mut word = 0u32;
            for &b in &trimmed[start..i] {
                word = (word << 8) | (b as u32);
            }
            limbs.push(word);
            i = start;
        }
        let mut res = Self { limbs };
        res.trim();
        res
    }

    pub fn to_be_bytes_padded(&self, out_len: usize) -> Result<Vec<u8>> {
        let mut raw = Vec::with_capacity(self.limbs.len() * 4);
        for &limb in self.limbs.iter().rev() {
            raw.extend_from_slice(&limb.to_be_bytes());
        }
        let first_nz = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
        let sig = &raw[first_nz..];
        ensure!(
            sig.len() <= out_len,
            "Integer ({} bytes) exceeds target size {out_len}",
            sig.len()
        );
        let mut out = vec![0u8; out_len];
        out[out_len - sig.len()..].copy_from_slice(sig);
        Ok(out)
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    fn get_bit(&self, bit_idx: usize) -> u32 {
        let limb_idx = bit_idx / 32;
        if limb_idx >= self.limbs.len() {
            return 0;
        }
        (self.limbs[limb_idx] >> (bit_idx % 32)) & 1
    }

    fn shl1_add_bit(&mut self, bit: u32) {
        let mut carry = bit;
        for limb in &mut self.limbs {
            let next_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    pub fn cmp_val(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (&a, &b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match a.cmp(&b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }

    pub fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = *self.limbs.get(i).unwrap_or(&0) as u64;
            let b = *other.limbs.get(i).unwrap_or(&0) as u64;
            let sum = a + b + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = *other.limbs.get(i).unwrap_or(&0) as i64;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            self.limbs[i] = diff as u32;
        }
        debug_assert_eq!(borrow, 0);
        self.trim();
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            let a64 = a as u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = out[i + j] as u64 + a64 * (b as u64) + carry;
                out[i + j] = cur as u32;
                carry = cur >> 32;
            }
            out[i + other.limbs.len()] = carry as u32;
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        if self.cmp_val(modulus) == Ordering::Less {
            return self.clone();
        }
        let bits = self.bit_len();
        let mut rem = Self::zero();
        for bit_idx in (0..bits).rev() {
            rem.shl1_add_bit(self.get_bit(bit_idx));
            if rem.cmp_val(modulus) != Ordering::Less {
                rem.sub_assign(modulus);
            }
        }
        rem
    }

    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        let mut result = Self::one().rem(modulus);
        let mut base = self.rem(modulus);
        let bits = exp.bit_len();
        for bit_idx in 0..bits {
            if exp.get_bit(bit_idx) == 1 {
                result = result.mul(&base).rem(modulus);
            }
            if bit_idx + 1 < bits {
                base = base.mul(&base).rem(modulus);
            }
        }
        result
    }
}

/// RSA private key parsed from PKCS#1 PEM or PKCS#8 DER/PEM.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub dp: BigUint,
    pub dq: BigUint,
    pub qinv: BigUint,
    pub modulus_bytes: usize,
}

impl RsaPrivateKey {
    /// Load an RSA private key from PKCS#1 PEM, PKCS#8 PEM, or PKCS#8/PKCS#1 DER bytes.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("Failed to read key {}", path.display()))?;
        Self::from_bytes(&bytes)
            .with_context(|| format!("Failed to parse RSA private key {}", path.display()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if let Ok(text) = std::str::from_utf8(bytes) {
            if text.contains("-----BEGIN RSA PRIVATE KEY-----") {
                let der = decode_pem_block(
                    text,
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----END RSA PRIVATE KEY-----",
                )?;
                return Self::from_pkcs1_der(&der);
            }
            if text.contains("-----BEGIN PRIVATE KEY-----") {
                let der = decode_pem_block(
                    text,
                    "-----BEGIN PRIVATE KEY-----",
                    "-----END PRIVATE KEY-----",
                )?;
                return Self::from_pkcs8_der(&der);
            }
        }
        if let Ok(k) = Self::from_pkcs8_der(bytes) {
            return Ok(k);
        }
        Self::from_pkcs1_der(bytes)
    }

    fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let seq = read_der_sequence(der, &mut pos)?;
        let mut inner_pos = 0usize;
        let _version = read_der_integer_bytes(seq, &mut inner_pos)?;
        let _alg_id = read_der_sequence(seq, &mut inner_pos)?;
        let (tag, pk_octets) = read_der_tlv(seq, &mut inner_pos)?;
        ensure!(tag == 0x04, "Expected PKCS#8 OCTET STRING, got 0x{tag:02x}");
        Self::from_pkcs1_der(pk_octets)
    }

    fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let seq = read_der_sequence(der, &mut pos)?;
        let mut p = 0usize;
        let _version = read_der_integer_bytes(seq, &mut p)?;
        let n = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let e = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let d = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let prime_p = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let prime_q = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let dp = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let dq = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let qinv = BigUint::from_be_bytes(read_der_integer_bytes(seq, &mut p)?);
        let modulus_bytes = n.bit_len().div_ceil(8);
        ensure!(modulus_bytes > 64, "RSA modulus too small");
        Ok(Self {
            n,
            e,
            d,
            p: prime_p,
            q: prime_q,
            dp,
            dq,
            qinv,
            modulus_bytes,
        })
    }

    /// Sign a 32-byte SHA-256 digest using RSASSA-PKCS1-v1_5-SIGN.
    pub fn sign_sha256_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let em = emsa_pkcs1_v1_5_sha256(digest, self.modulus_bytes)?;
        let m = BigUint::from_be_bytes(&em);

        let sig = if !self.p.is_zero()
            && !self.q.is_zero()
            && !self.dp.is_zero()
            && !self.dq.is_zero()
            && !self.qinv.is_zero()
        {
            let m1 = m.mod_pow(&self.dp, &self.p);
            let m2 = m.mod_pow(&self.dq, &self.q);
            let m2_mod_p = m2.rem(&self.p);
            let mut diff = if m1.cmp_val(&m2_mod_p) != Ordering::Less {
                m1.clone()
            } else {
                m1.add(&self.p)
            };
            diff.sub_assign(&m2_mod_p);
            let h = self.qinv.mul(&diff).rem(&self.p);
            m2.add(&h.mul(&self.q))
        } else {
            m.mod_pow(&self.d, &self.n)
        };

        sig.to_be_bytes_padded(self.modulus_bytes)
    }
}

/// RSA public key extracted from an X.509 certificate PEM (`testkey.x509.pem`).
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
    pub modulus_bytes: usize,
}

impl RsaPublicKey {
    pub fn from_x509_pem_file(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("Failed to read certificate {}", path.display()))?;
        Self::from_x509_pem(&text)
    }

    pub fn from_x509_pem(pem: &str) -> Result<Self> {
        let der = decode_pem_block(pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")?;
        let mut pos = 0usize;
        let cert_seq = read_der_sequence(&der, &mut pos)?;
        let mut cp = 0usize;
        let tbs = read_der_sequence(cert_seq, &mut cp)?;

        // Walk TBSCertificate: optional [0] version, serial, sigAlg, issuer, validity, subject, SubjectPublicKeyInfo
        let mut tp = 0usize;
        if tp < tbs.len() && tbs[tp] == 0xA0 {
            let _ = read_der_tlv(tbs, &mut tp)?;
        }
        for _ in 0..5 {
            let _ = read_der_tlv(tbs, &mut tp)?;
        }
        let spki = read_der_sequence(tbs, &mut tp)?;
        let mut sp = 0usize;
        let _alg = read_der_sequence(spki, &mut sp)?;
        let (tag, bit_str) = read_der_tlv(spki, &mut sp)?;
        ensure!(tag == 0x03 && !bit_str.is_empty(), "Expected BIT STRING in SPKI");
        ensure!(bit_str[0] == 0, "Expected 0 unused bits in RSA SPKI BIT STRING");

        let mut pk_pos = 0usize;
        let pk_seq = read_der_sequence(&bit_str[1..], &mut pk_pos)?;
        let mut pp = 0usize;
        let n = BigUint::from_be_bytes(read_der_integer_bytes(pk_seq, &mut pp)?);
        let e = BigUint::from_be_bytes(read_der_integer_bytes(pk_seq, &mut pp)?);
        let modulus_bytes = n.bit_len().div_ceil(8);
        Ok(Self {
            n,
            e,
            modulus_bytes,
        })
    }

    /// Verify a PKCS#1 v1.5 SHA-256 signature against `digest`.
    pub fn verify_sha256_digest(&self, digest: &[u8; 32], signature: &[u8]) -> Result<()> {
        let sig_slice = if signature.len() > self.modulus_bytes {
            &signature[..self.modulus_bytes]
        } else {
            signature
        };
        let s = BigUint::from_be_bytes(sig_slice);
        ensure!(
            s.cmp_val(&self.n) == Ordering::Less,
            "Signature representative out of range"
        );
        let m = s.mod_pow(&self.e, &self.n);
        let em_actual = m.to_be_bytes_padded(self.modulus_bytes)?;
        let em_expected = emsa_pkcs1_v1_5_sha256(digest, self.modulus_bytes)?;
        ensure!(em_actual == em_expected, "RSA PKCS#1 v1.5 signature mismatch");
        Ok(())
    }
}

fn emsa_pkcs1_v1_5_sha256(digest: &[u8; 32], em_len: usize) -> Result<Vec<u8>> {
    let t_len = SHA256_DIGEST_INFO_PREFIX.len() + 32;
    ensure!(em_len >= t_len + 11, "Intended encoded message length too short");
    let ps_len = em_len - t_len - 3;
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x01);
    em.resize(em.len() + ps_len, 0xFF);
    em.push(0x00);
    em.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
    em.extend_from_slice(digest);
    Ok(em)
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"CrAU payload test 12345!";
        let enc = base64_encode(data);
        let dec = base64_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_sign_and_verify_with_repo_testkeys() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..");
        let key_pem = repo_root.join("otatools/key/testkey.key");
        let key_pk8 = repo_root.join("otatools/key/testkey.pk8");
        let cert_pem = repo_root.join("otatools/key/testkey.x509.pem");

        let k1 = RsaPrivateKey::from_file(&key_pem).unwrap();
        let k2 = RsaPrivateKey::from_file(&key_pk8).unwrap();
        let cert_pub = RsaPublicKey::from_x509_pem_file(&cert_pem).unwrap();

        assert_eq!(k2.n, cert_pub.n);
        assert_eq!(k2.e, cert_pub.e);
        assert_eq!(k1.modulus_bytes, 256);
        assert_eq!(k2.modulus_bytes, 256);

        let k1_pub = RsaPublicKey {
            n: k1.n.clone(),
            e: k1.e.clone(),
            modulus_bytes: k1.modulus_bytes,
        };

        let digest = sha256_bytes(b"hello android ota payload");
        let sig1 = k1.sign_sha256_digest(&digest).unwrap();
        let sig2 = k2.sign_sha256_digest(&digest).unwrap();
        assert_eq!(sig1.len(), 256);
        assert_eq!(sig2.len(), 256);

        k1_pub.verify_sha256_digest(&digest, &sig1).unwrap();
        cert_pub.verify_sha256_digest(&digest, &sig2).unwrap();

        let bad_digest = sha256_bytes(b"tampered");
        assert!(cert_pub.verify_sha256_digest(&bad_digest, &sig2).is_err());
    }
}
