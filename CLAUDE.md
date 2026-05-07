# zsc

Fast encrypted compressed archive tool. Single Rust binary (~1.2 MB stripped) producing `.zsc` files.

## Architecture

Streaming pipeline; data flows through without buffering the entire archive in memory:

- **Seal**: external `tar` + `zstd -T0` processes (for multi-core compression) pipe into the Rust binary which reads 1 MiB chunks, encrypts each with XChaCha20-Poly1305, and writes to the output file.
- **Open**: Rust binary reads chunks from the `.zsc` file, decrypts, and pipes plaintext into external `zstd -d` + `tar x` processes.
- **Explore**: Same as open but writes decrypted compressed stream to `/dev/shm/<name>.tar.zst` (tmpfs/RAM), opens with `xdg-open`, polls `/proc/*/cmdline` for a process holding the path in argv, and cleans up when that process exits. Argv-based tracking (not open-fd via `fuser`) is required because viewers like Ark only hold the file open while reading the central directory and reopen it on demand for previews/extraction.

External `tar`/`zstd` processes are used intentionally; zstd's multi-threaded compression performs significantly better in its own process than through the Rust `zstd` crate's streaming API due to internal job scheduling.

## Source Layout

```
src/
  main.rs       CLI (clap derive), config file loading, passphrase resolution, dispatch
  format.rs     ZscHeader: magic bytes, Argon2id params, salt, nonce, serialize/deserialize
  crypto.rs     Argon2id KDF, XChaCha20-Poly1305 chunk encrypt/decrypt, nonce derivation
  seal.rs       Seal command: spawn tar|zstd (files or directories), read chunks, encrypt, write .zsc
  open.rs       Open command: read .zsc, decrypt chunks, pipe to zstd|tar
  explore.rs    Explore command: decrypt to /dev/shm, xdg-open, cleanup
tests/
  roundtrip.rs  Integration tests: spawn the binary end-to-end (skipped when tar/zstd missing)
```

No unsafe code except `from_raw_fd` for `--passphrase-fd`.

## Build

```
cargo build --release
cargo test --release
```

The `.cargo/config.toml` enables AVX2 for the ChaCha20 backend and native CPU tuning. This is critical for performance; without it, the chacha20 crate uses its scalar backend which is ~5x slower.

Unit tests live next to the modules they cover (`src/crypto.rs`, `src/format.rs`) and are pure; the integration tests in `tests/roundtrip.rs` shell out to `tar` and `zstd` and self-skip when those binaries are absent, so `cargo test` succeeds in minimal environments.

## File Format

52-byte header: magic `ZSC\x02`, Argon2id params (m/t/p as u32 LE), 16-byte salt, 24-byte nonce. Body is a sequence of `[u32 LE chunk_len][ciphertext]` pairs terminated by a zero-length sentinel. Each chunk is 1 MiB of plaintext encrypted to 1 MiB + 16 bytes (Poly1305 tag). Per-chunk nonce is base nonce XOR little-endian chunk counter in the last 8 bytes.

The full serialized header is fed to every chunk's AEAD as associated data (AAD), so any tampering with magic, KDF params, salt, or nonce causes chunk 0 to fail authentication. The v0.1 format used magic `ZSC\x01` without AAD; that format is incompatible and v2 binaries refuse to read it.

`read_from` also enforces sanity bounds on the KDF params (`m_cost <= 4 GiB`, `t_cost <= 100`, `p_cost <= 256`) and rejects archives that exceed them. The KDF runs before any chunk is authenticated, so without these bounds a crafted archive could trigger a multi-GB allocation before the AAD check could reject it.

## Crypto Choices

- **XChaCha20-Poly1305** over AES-256-GCM: 24-byte nonce eliminates nonce-reuse risk, consistent performance across platforms, same primitives as age/WireGuard/libsodium. AES-GCM is ~2x faster on x86 with AES-NI but the bottleneck is disk I/O and zstd compression, not the cipher.
- **Argon2id** over PBKDF2/scrypt: memory-hard, GPU-resistant, modern standard. Params stored in header for forward compatibility.
- **1 MiB chunks**: balances per-chunk overhead vs memory usage. Each chunk independently authenticated for corruption localization.
- **Header AAD**: serialized header bytes are bound into chunk authentication; cheap insurance against header tampering.

## Config File

Optional `~/.config/zsc/config.toml`:

```toml
passphrase_cmd = "op read op://Personal/zsc/password"
```

- `passphrase_cmd`: arbitrary shell command that prints the passphrase to stdout. Works with any secret manager (1Password `op`, `pass`, `secret-tool`, custom scripts, etc.).

Priority: `--passphrase-fd` > `passphrase_cmd` config > interactive TTY prompt. Entirely optional; without config, behavior is unchanged.

## Dependencies

All crypto is from audited RustCrypto crates (`chacha20poly1305`, `argon2`). No custom cryptographic code. Config/CLI uses `serde`, `toml`, `dirs`, `clap`. Memory hygiene uses `zeroize`.

## Integration

The companion `~/arch` repo contains KDE Dolphin integration:
- `bin/decrypt-extract`: bash wrapper with kdialog password prompt and action picker
- `bin/qt-menu`: PyQt6 double-click list dialog
- `config/mime/x-zsc.xml`: MIME type with magic byte matching
- `config/applications/decrypt-extract.desktop`: file association

## Key Conventions

- Seal accepts both files and directories. Auto-detect: `.zsc` extension means decrypt, anything else means encrypt.
- Passphrase resolution: `--passphrase-fd` > `passphrase_cmd` config > interactive TTY prompt.
- Runtime dependencies: `tar` and `zstd` must be on PATH for seal/open; `xdg-open` is additionally required for `--explore`.
- Error messages are user-facing: "wrong passphrase", "archive corrupted", "archive truncated".
- Exit code 0 on success, 1 on any error.
- Passphrase never logged or printed. Passphrase `String` and derived `[u8; 32]` key are wrapped in `zeroize::Zeroizing` so they are zeroed on drop. The cipher's internal copy of the key is not explicitly zeroed but its lifetime is bounded by the seal/open call.
