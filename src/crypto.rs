use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::format::{ZscHeader, NONCE_LEN};

pub fn derive_key(passphrase: &str, header: &ZscHeader) -> Result<[u8; 32]> {
    let params = Params::new(header.m_cost, header.t_cost, header.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &header.salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

pub fn make_cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

pub fn chunk_nonce(base: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    let counter_bytes = counter.to_le_bytes();
    // XOR counter into last 8 bytes of the 24-byte nonce
    for i in 0..8 {
        nonce[NONCE_LEN - 8 + i] ^= counter_bytes[i];
    }
    nonce
}

pub fn encrypt_chunk(
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; NONCE_LEN],
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = chunk_nonce(base_nonce, counter);
    cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))
}

pub fn decrypt_chunk(
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; NONCE_LEN],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = chunk_nonce(base_nonce, counter);
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| {
            if counter == 0 {
                anyhow::anyhow!("decryption failed -- wrong passphrase")
            } else {
                anyhow::anyhow!("chunk {counter} authentication failed -- archive corrupted")
            }
        })
}
