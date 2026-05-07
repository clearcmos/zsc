# zsc

[![CI](https://github.com/clearcmos/zsc/actions/workflows/ci.yml/badge.svg)](https://github.com/clearcmos/zsc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fast encrypted compressed archives. Combines zstd compression with XChaCha20-Poly1305 authenticated encryption and Argon2id key derivation in a single streaming pipeline.

## Why

Existing options either lack authenticated encryption (openssl enc), require gluing multiple commands together (tar | zstd | age), or are significantly slower (zip takes ~12x longer on the same data). zsc produces a single `.zsc` file with proper AEAD: every chunk is independently authenticated, so tampered or corrupted data is detected immediately.

## Performance

Benchmarked on 3.3 GB of mixed files (documents, images, videos) with an Intel i7-13700K:

| Operation | Time |
|---|---|
| Seal (compress + encrypt) | ~4s |
| Open (decrypt + extract) | ~5s |

For comparison: `zip` takes 48s for the same data and achieves a similar size reduction (~9%).

## Install

Runtime requirements: `tar` and `zstd` for the streaming pipeline; `xdg-open` is additionally needed for `--explore`.

From source (any Linux):

```
cargo build --release
cp target/release/zsc ~/.local/bin/
```

Arch Linux (via the bundled `PKGBUILD`):

```
makepkg -si
```

For optimal performance on x86_64, the repo includes `.cargo/config.toml` with:

```toml
[build]
rustflags = ['--cfg', 'chacha20_backend="avx2"', '-C', 'target-cpu=native']
```

Run the test suite with `cargo test --release`. Unit tests cover the crypto and format modules; integration tests in `tests/roundtrip.rs` exercise the full binary and skip automatically if `tar` or `zstd` are not on PATH.

## Usage

```
# Encrypt a directory (auto-detected; creates photos.zsc)
zsc photos/

# Encrypt a single file (creates document.zsc; extension is dropped)
zsc document.pdf

# Encrypt with custom output path
zsc -e photos/ photos-backup.zsc

# Decrypt and extract (auto-detected by .zsc extension; extracts to photos/)
zsc photos.zsc

# Decrypt and extract to a specific directory
zsc -d photos.zsc /mnt/restore

# Decrypt to RAM and browse in your archive viewer (e.g. Ark; Linux only - uses /dev/shm + xdg-open)
zsc --explore photos.zsc

# Non-interactive (passphrase via file descriptor)
zsc -e backup/ --passphrase-fd 3 3<<< "$PASSWORD"
zsc -d backup.zsc /mnt/restore --passphrase-fd 3 3<<< "$PASSWORD"
```

### Secret manager integration (optional)

zsc can fetch the passphrase from any command that prints it to stdout. Create `~/.config/zsc/config.toml`:

```toml
passphrase_cmd = "op read op://Personal/zsc/password"
```

Any shell command works: 1Password CLI (`op`), `pass`, `secret-tool`, a script wrapping a biometric prompt, etc. Without this config, zsc prompts interactively as usual.

## File Format

`.zsc` files are self-describing and contain everything needed to decrypt:

```
Header (52 bytes):
  [4B]  Magic: "ZSC\x02"
  [4B]  Argon2id memory cost (KiB, LE)
  [4B]  Argon2id time cost (LE)
  [4B]  Argon2id parallelism (LE)
  [16B] Salt (random)
  [24B] Nonce (random)

Body:
  Repeating chunks:
    [4B]  Chunk ciphertext length (LE)
    [var] XChaCha20-Poly1305 encrypted data (1 MiB plaintext + 16B auth tag)
  Sentinel:
    [4B]  0x00000000 (marks end of chunks)
```

The plaintext stream is a zstd-compressed tar archive. Each chunk uses a unique nonce derived from the base nonce XOR'd with the chunk counter. The full 52-byte header is also fed to every chunk's AEAD as associated data, so any tampering with the KDF parameters, salt, or nonce causes the first chunk to fail authentication.

## Cryptography

- **Compression**: zstd (multi-threaded, default level)
- **KDF**: Argon2id with 256 MiB memory, 3 iterations, 4 lanes. Parameters are stored in the header so they can be tuned without breaking existing files.
- **AEAD**: XChaCha20-Poly1305 with 1 MiB chunks. Each chunk is independently authenticated. The 24-byte nonce eliminates nonce-reuse concerns with random generation.
- **Header authentication**: The serialized header is bound into every chunk's AEAD as associated data, so the KDF params, salt, and nonce cannot be tampered with undetected. Sanity bounds on the params (`m_cost <= 4 GiB`, `t_cost <= 100`, `p_cost <= 256`) are enforced before the KDF runs, so a crafted archive cannot trigger an unbounded allocation.
- **Wrong password**: Detected immediately by the first chunk's Poly1305 tag failing.
- **Corruption**: Detected at the exact chunk that was tampered with.
- **Memory hygiene**: The passphrase string and derived key are zeroed on drop via the `zeroize` crate.

These are the same primitives used by age, WireGuard, and libsodium.

## License

MIT
