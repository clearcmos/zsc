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
# Encrypt a directory (auto-detected)
zsc photos/

# Encrypt a single file
zsc document.pdf

# Encrypt with custom output path
zsc -e photos/ photos-backup.zsc

# Decrypt and extract (auto-detected by .zsc extension)
zsc photos.zsc

# Decrypt and extract to a specific directory
zsc -d photos.zsc /mnt/restore

# Decrypt to RAM and browse in your archive viewer (e.g. Ark)
zsc --explore photos.zsc

# Non-interactive (passphrase via file descriptor)
zsc -e backup/ --passphrase-fd 3 3<<< "$PASSWORD"
zsc -d backup.zsc /mnt/restore --passphrase-fd 3 3<<< "$PASSWORD"
```

### Bitwarden integration (optional)

If you use [Bitwarden CLI](https://bitwarden.com/help/cli/), zsc can fetch the passphrase automatically. Create `~/.config/zsc/config.toml`:

```toml
bw_item = "my-archive-key"
```

The item can be a friendly name or a UUID. Friendly names use `bw list items` with exact matching, so they work even when the name is a substring of other items. UUIDs use the faster `bw get password` path.

If you use a CLI wrapper instead of `bw` directly, set `bw_cmd`:

```toml
bw_cmd = "bwbio"
bw_item = "my-archive-key"
```

You can also pass it per-command with `--bw`:

```
zsc photos/ --bw "my-archive-key"
```

This is entirely optional - without the config file or `bw` on PATH, zsc prompts interactively as usual.

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

## License

MIT
