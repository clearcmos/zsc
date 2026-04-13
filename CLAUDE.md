# zsc

Fast encrypted compressed archive tool. Single Rust binary (~2 MB) producing `.zsc` files.

## Architecture

Streaming pipeline -- data flows through without buffering the entire archive in memory:

- **Seal**: external `tar` + `zstd -T0` processes (for multi-core compression) pipe into the Rust binary which reads 1 MiB chunks, encrypts each with XChaCha20-Poly1305, and writes to the output file.
- **Open**: Rust binary reads chunks from the `.zsc` file, decrypts, and pipes plaintext into external `zstd -d` + `tar x` processes.
- **Explore**: Same as open but writes decrypted compressed stream to `/dev/shm/<name>.tar.zst` (tmpfs/RAM), opens with `xdg-open`, polls with `fuser`, and cleans up when the viewer closes.

External `tar`/`zstd` processes are used intentionally -- zstd's multi-threaded compression performs significantly better in its own process than through the Rust `zstd` crate's streaming API due to internal job scheduling.

## Source Layout

```
src/
  main.rs      -- CLI (clap derive), config file loading, passphrase resolution (bw/fd/tty), dispatch
  format.rs    -- ZscHeader: magic bytes, Argon2id params, salt, nonce, serialize/deserialize
  crypto.rs    -- Argon2id KDF, XChaCha20-Poly1305 chunk encrypt/decrypt, nonce derivation
  seal.rs      -- Seal command: spawn tar|zstd (files or directories), read chunks, encrypt, write .zsc
  open.rs      -- Open command: read .zsc, decrypt chunks, pipe to zstd|tar
  explore.rs   -- Explore command: decrypt to /dev/shm, xdg-open, cleanup
```

No unsafe code except `from_raw_fd` for `--passphrase-fd`.

## Build

```
cargo build --release
```

The `.cargo/config.toml` enables AVX2 for the ChaCha20 backend and native CPU tuning. This is critical for performance -- without it, the chacha20 crate uses its scalar backend which is ~5x slower.

## File Format

52-byte header: magic `ZSC\x01`, Argon2id params (m/t/p as u32 LE), 16-byte salt, 24-byte nonce. Body is a sequence of `[u32 LE chunk_len][ciphertext]` pairs terminated by a zero-length sentinel. Each chunk is 1 MiB of plaintext encrypted to 1 MiB + 16 bytes (Poly1305 tag). Per-chunk nonce is base nonce XOR little-endian chunk counter in the last 8 bytes.

## Crypto Choices

- **XChaCha20-Poly1305** over AES-256-GCM: 24-byte nonce eliminates nonce-reuse risk, consistent performance across platforms, same primitives as age/WireGuard/libsodium. AES-GCM is ~2x faster on x86 with AES-NI but the bottleneck is disk I/O and zstd compression, not the cipher.
- **Argon2id** over PBKDF2/scrypt: memory-hard, GPU-resistant, modern standard. Params stored in header for forward compatibility.
- **1 MiB chunks**: balances per-chunk overhead vs memory usage. Each chunk independently authenticated for corruption localization.

## Config File

Optional `~/.config/zsc/config.toml` with a single field:

```toml
bw_item = "item-name-or-uuid"
```

When set, passphrase is fetched via `bwbio get password <bw_item>` instead of prompting. The `--bw` CLI flag overrides this, and `--passphrase-fd` bypasses both. Requires `bwbio` (Bitwarden CLI wrapper) on PATH. Entirely optional - without it, behavior is unchanged.

## Dependencies

All crypto is from audited RustCrypto crates (`chacha20poly1305`, `argon2`). No custom cryptographic code. Config/CLI uses `serde`, `toml`, `dirs`, `clap`.

## Integration

The companion `~/arch` repo contains KDE Dolphin integration:
- `bin/decrypt-extract` -- bash wrapper with kdialog password prompt and action picker
- `bin/qt-menu` -- PyQt6 double-click list dialog
- `config/mime/x-zsc.xml` -- MIME type with magic byte matching
- `config/applications/decrypt-extract.desktop` -- file association

## Key Conventions

- Seal accepts both files and directories. Auto-detect: `.zsc` extension means decrypt, anything else means encrypt.
- Passphrase resolution: `--passphrase-fd` > `--bw` flag > `bw_item` config > interactive TTY prompt.
- Runtime dependencies: `tar`, `zstd`, `fuser`, `xdg-open` must be on PATH. `bwbio` only needed if using Bitwarden integration.
- Error messages are user-facing: "wrong passphrase", "archive corrupted", "archive truncated".
- Exit code 0 on success, 1 on any error.
- Passphrase never logged or printed. Cleared from memory after key derivation (Rust String drop).
