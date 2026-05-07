use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::format::{ZscHeader, NONCE_LEN};

pub fn derive_key(passphrase: &str, header: &ZscHeader) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(header.m_cost, header.t_cost, header.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), &header.salt, key.as_mut())
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
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = chunk_nonce(base_nonce, counter);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))
}

pub fn decrypt_chunk(
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; NONCE_LEN],
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = chunk_nonce(base_nonce, counter);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            if counter == 0 {
                anyhow::anyhow!("decryption failed: wrong passphrase or tampered header")
            } else {
                anyhow::anyhow!("chunk {counter} authentication failed: archive corrupted")
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> ZscHeader {
        // Tiny Argon2 params so tests run fast.
        ZscHeader {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [42u8; 16],
            nonce: [7u8; 24],
        }
    }

    #[test]
    fn derive_key_is_deterministic() {
        let h = test_header();
        let k1 = derive_key("hunter2", &h).unwrap();
        let k2 = derive_key("hunter2", &h).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_for_different_passphrase() {
        let h = test_header();
        let k1 = derive_key("hunter2", &h).unwrap();
        let k2 = derive_key("hunter3", &h).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_for_different_salt() {
        let mut h1 = test_header();
        let mut h2 = test_header();
        h1.salt = [1u8; 16];
        h2.salt = [2u8; 16];
        let k1 = derive_key("p", &h1).unwrap();
        let k2 = derive_key("p", &h2).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let h = test_header();
        let key = derive_key("p", &h).unwrap();
        let cipher = make_cipher(&key);
        let aad = h.serialize();
        let pt = b"hello world".to_vec();
        let ct = encrypt_chunk(&cipher, &h.nonce, 0, &pt, &aad).unwrap();
        let dec = decrypt_chunk(&cipher, &h.nonce, 0, &ct, &aad).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn decrypt_with_tampered_header_aad_fails() {
        let h = test_header();
        let key = derive_key("p", &h).unwrap();
        let cipher = make_cipher(&key);
        let aad = h.serialize();
        let ct = encrypt_chunk(&cipher, &h.nonce, 0, b"hello", &aad).unwrap();

        // Flip a single bit in m_cost field of AAD.
        let mut tampered = aad;
        tampered[4] ^= 1;
        assert!(decrypt_chunk(&cipher, &h.nonce, 0, &ct, &tampered).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let h = test_header();
        let key = derive_key("p", &h).unwrap();
        let cipher = make_cipher(&key);
        let aad = h.serialize();
        let mut ct = encrypt_chunk(&cipher, &h.nonce, 0, b"hello", &aad).unwrap();
        ct[0] ^= 1;
        assert!(decrypt_chunk(&cipher, &h.nonce, 0, &ct, &aad).is_err());
    }

    #[test]
    fn decrypt_wrong_counter_fails() {
        let h = test_header();
        let key = derive_key("p", &h).unwrap();
        let cipher = make_cipher(&key);
        let aad = h.serialize();
        let ct = encrypt_chunk(&cipher, &h.nonce, 0, b"hello", &aad).unwrap();
        // Treat chunk 0 as if it were chunk 1: nonce mismatches, auth fails.
        assert!(decrypt_chunk(&cipher, &h.nonce, 1, &ct, &aad).is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let h = test_header();
        let key1 = derive_key("p1", &h).unwrap();
        let key2 = derive_key("p2", &h).unwrap();
        let cipher1 = make_cipher(&key1);
        let cipher2 = make_cipher(&key2);
        let aad = h.serialize();
        let ct = encrypt_chunk(&cipher1, &h.nonce, 0, b"x", &aad).unwrap();
        assert!(decrypt_chunk(&cipher2, &h.nonce, 0, &ct, &aad).is_err());
    }

    #[test]
    fn chunk_nonces_are_distinct() {
        let base = [0u8; NONCE_LEN];
        let n0 = chunk_nonce(&base, 0);
        let n1 = chunk_nonce(&base, 1);
        let n2 = chunk_nonce(&base, 2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn ciphertext_overhead_is_poly1305_tag() {
        let h = test_header();
        let key = derive_key("p", &h).unwrap();
        let cipher = make_cipher(&key);
        let aad = h.serialize();
        let pt = vec![0u8; 1024];
        let ct = encrypt_chunk(&cipher, &h.nonce, 0, &pt, &aad).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
    }
}
