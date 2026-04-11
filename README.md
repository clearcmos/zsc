# zsc

Fast encrypted compressed archives. Combines zstd compression with XChaCha20-Poly1305 authenticated encryption and Argon2id key derivation in a single streaming pipeline.

## Why

Existing options either lack authenticated encryption (openssl enc), require gluing multiple commands together (tar | zstd | age), or are significantly slower (zip takes ~12x longer on the same data). zsc produces a single `.zsc` file with proper AEAD -- every chunk is independently authenticated, so tampered or corrupted data is detected immediately.

## Performance

Benchmarked on 3.3 GB of mixed files (documents, images, videos) with an Intel i7-13700K:

| Operation | Time |
|---|---|
| Seal (compress + encrypt) | ~4s |
| Open (decrypt + extract) | ~5s |

For comparison: `zip` takes 48s for the same data. zsc's compression ratio is comparable (~9%).

## Install

Requires Rust and a system `zstd` + `tar` (used for the streaming pipeline):

```
cargo build --release
cp target/release/zsc ~/.local/bin/
```

For optimal performance on x86_64, create `.cargo/config.toml`:

```toml
[build]
rustflags = ['--cfg', 'chacha20_backend="avx2"', '-C', 'target-cpu=native']
```

## Usage

```
# Encrypt a directory
zsc -e photos/

# Encrypt with custom output path
zsc -e photos/ photos-backup.zsc

# Decrypt and extract
zsc -d photos.zsc

# Decrypt and extract to a specific directory
zsc -d photos.zsc /mnt/restore

# Decrypt to RAM and browse in your archive viewer (e.g. Ark)
zsc --explore photos.zsc

# Non-interactive (passphrase via file descriptor)
zsc -e backup/ --passphrase-fd 3 3<<< "$PASSWORD"
zsc -d backup.zsc /mnt/restore --passphrase-fd 3 3<<< "$PASSWORD"
```

## File Format

`.zsc` files are self-describing and contain everything needed to decrypt:

```
Header (52 bytes):
  [4B]  Magic: "ZSC\x01"
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

The plaintext stream is a zstd-compressed tar archive. Each chunk uses a unique nonce derived from the base nonce XOR'd with the chunk counter.

## Cryptography

- **Compression**: zstd (multi-threaded, default level)
- **KDF**: Argon2id -- 256 MiB memory, 3 iterations, 4 lanes. Parameters are stored in the header so they can be tuned without breaking existing files.
- **AEAD**: XChaCha20-Poly1305 with 1 MiB chunks. Each chunk is independently authenticated. The 24-byte nonce eliminates nonce-reuse concerns with random generation.
- **Wrong password**: Detected immediately by the first chunk's Poly1305 tag failing.
- **Corruption**: Detected at the exact chunk that was tampered with.

These are the same primitives used by age, WireGuard, and libsodium.

## KDE Integration

zsc includes a Dolphin file manager integration for double-click decrypt/extract:

- MIME type registration for `.zsc` files (with magic byte detection)
- `.desktop` file that launches a wrapper script
- KDE password dialog (kdialog)
- Action picker: "Extract Here", "Extract To...", or "Explore in Ark"
- Explore mode decrypts to tmpfs (/dev/shm) so unencrypted data never touches disk

See the wrapper scripts in the companion [arch](https://github.com/nicholasgasior/arch) repo under `bin/decrypt-extract` and `bin/qt-menu`.

## License

MIT
