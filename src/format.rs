use std::io::{self, Read, Write};

use anyhow::{bail, Context, Result};
use rand::RngExt;

pub const MAGIC: &[u8; 4] = b"ZSC\x02";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const CHUNK_PLAINTEXT_SIZE: usize = 1024 * 1024; // 1 MiB
pub const HEADER_LEN: usize = 4 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 52

// Default Argon2id parameters
pub const DEFAULT_M_COST: u32 = 256 * 1024; // 256 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

// Sanity bounds enforced when reading a header. Argon2id with parameters above
// these would either be unusable in practice (multi-GB key derivation) or a
// signal that the file is corrupt/malicious. Bounding these protects callers
// from OOM-via-tampered-archive, since the KDF runs before any chunk is
// authenticated.
pub const MAX_M_COST: u32 = 4 * 1024 * 1024; // 4 GiB
pub const MAX_T_COST: u32 = 100;
pub const MAX_P_COST: u32 = 256;

pub struct ZscHeader {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl ZscHeader {
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut salt);
        rng.fill(&mut nonce);
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            salt,
            nonce,
        }
    }

    /// Serialized header bytes. Used both for on-disk write and as AEAD associated
    /// data so that any tampering with magic, KDF params, salt, or nonce fails
    /// authentication on the first chunk.
    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4..8].copy_from_slice(&self.m_cost.to_le_bytes());
        buf[8..12].copy_from_slice(&self.t_cost.to_le_bytes());
        buf[12..16].copy_from_slice(&self.p_cost.to_le_bytes());
        buf[16..16 + SALT_LEN].copy_from_slice(&self.salt);
        buf[16 + SALT_LEN..].copy_from_slice(&self.nonce);
        buf
    }

    pub fn write_to(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&self.serialize())?;
        Ok(())
    }

    pub fn read_from(r: &mut impl Read) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .context("failed to read file header")?;
        if &magic != MAGIC {
            bail!("not a .zsc file or unsupported version");
        }

        let mut buf4 = [0u8; 4];

        r.read_exact(&mut buf4)?;
        let m_cost = u32::from_le_bytes(buf4);
        r.read_exact(&mut buf4)?;
        let t_cost = u32::from_le_bytes(buf4);
        r.read_exact(&mut buf4)?;
        let p_cost = u32::from_le_bytes(buf4);

        let mut salt = [0u8; SALT_LEN];
        r.read_exact(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce)?;

        if m_cost > MAX_M_COST {
            bail!("archive m_cost={m_cost} KiB exceeds bound {MAX_M_COST}; refusing to derive key");
        }
        if t_cost > MAX_T_COST {
            bail!("archive t_cost={t_cost} exceeds bound {MAX_T_COST}");
        }
        if p_cost > MAX_P_COST {
            bail!("archive p_cost={p_cost} exceeds bound {MAX_P_COST}");
        }

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            salt,
            nonce,
        })
    }
}

pub fn read_chunk_len(r: &mut impl Read) -> io::Result<usize> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn header_roundtrip() {
        let hdr = ZscHeader::generate();
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_LEN);

        let mut cursor = Cursor::new(&buf);
        let hdr2 = ZscHeader::read_from(&mut cursor).unwrap();
        assert_eq!(hdr.m_cost, hdr2.m_cost);
        assert_eq!(hdr.t_cost, hdr2.t_cost);
        assert_eq!(hdr.p_cost, hdr2.p_cost);
        assert_eq!(hdr.salt, hdr2.salt);
        assert_eq!(hdr.nonce, hdr2.nonce);
    }

    #[test]
    fn serialize_matches_write() {
        let hdr = ZscHeader::generate();
        let mut writer_buf = Vec::new();
        hdr.write_to(&mut writer_buf).unwrap();
        assert_eq!(writer_buf, hdr.serialize().to_vec());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bad = [0u8; HEADER_LEN];
        bad[0..4].copy_from_slice(b"XXXX");
        let mut cursor = Cursor::new(&bad[..]);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn rejects_old_v1_magic() {
        // The v1 (ZSC\x01) format is incompatible with v2 AAD authentication;
        // new code must refuse old archives rather than silently mis-decrypt.
        let mut bad = [0u8; HEADER_LEN];
        bad[0..4].copy_from_slice(b"ZSC\x01");
        let mut cursor = Cursor::new(&bad[..]);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let bad = [0u8; 10];
        let mut cursor = Cursor::new(&bad[..]);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn rejects_oversize_m_cost() {
        let mut hdr = ZscHeader::generate();
        hdr.m_cost = MAX_M_COST + 1;
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn rejects_oversize_t_cost() {
        let mut hdr = ZscHeader::generate();
        hdr.t_cost = MAX_T_COST + 1;
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn rejects_oversize_p_cost() {
        let mut hdr = ZscHeader::generate();
        hdr.p_cost = MAX_P_COST + 1;
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        assert!(ZscHeader::read_from(&mut cursor).is_err());
    }
}
