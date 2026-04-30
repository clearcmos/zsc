use std::io::{self, Read, Write};

use anyhow::{bail, Context, Result};
use rand::RngExt;

pub const MAGIC: &[u8; 4] = b"ZSC\x01";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const CHUNK_PLAINTEXT_SIZE: usize = 1024 * 1024; // 1 MiB
// Default Argon2id parameters
pub const DEFAULT_M_COST: u32 = 256 * 1024; // 256 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

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

    pub fn write_to(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&self.m_cost.to_le_bytes())?;
        w.write_all(&self.t_cost.to_le_bytes())?;
        w.write_all(&self.p_cost.to_le_bytes())?;
        w.write_all(&self.salt)?;
        w.write_all(&self.nonce)?;
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
