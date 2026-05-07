use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use crate::crypto;
use crate::format::{self, ZscHeader};

pub fn open(file: &Path, output_dir: &Path, passphrase: &str) -> Result<()> {
    if !file.is_file() {
        bail!("not a file: {}", file.display());
    }
    if output_dir.exists() {
        bail!("output already exists: {}", output_dir.display());
    }

    let mut input = BufReader::new(
        File::open(file).with_context(|| format!("cannot open {}", file.display()))?,
    );
    let header = ZscHeader::read_from(&mut input)?;
    let aad = header.serialize();

    eprint!("deriving key...");
    let key = crypto::derive_key(passphrase, &header)?;
    eprintln!(" done");

    let cipher = crypto::make_cipher(&key);

    std::fs::create_dir_all(output_dir)?;

    // Pipe decrypted compressed stream through external zstd -d | tar x
    let mut zstd_proc = Command::new("zstd")
        .args(["-d", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn zstd")?;

    let mut tar_proc = Command::new("tar")
        .args(["xf", "-", "-C"])
        .arg(output_dir)
        .stdin(zstd_proc.stdout.take().unwrap())
        .spawn()
        .context("failed to spawn tar")?;

    let mut writer = zstd_proc.stdin.take().unwrap();
    let mut counter: u64 = 0;

    let decrypt_result = (|| -> Result<()> {
        loop {
            let chunk_len = format::read_chunk_len(&mut input).context("archive is truncated")?;
            if chunk_len == 0 {
                break;
            }

            let mut ciphertext = vec![0u8; chunk_len];
            input
                .read_exact(&mut ciphertext)
                .context("archive is truncated")?;

            let plaintext =
                crypto::decrypt_chunk(&cipher, &header.nonce, counter, &ciphertext, &aad)?;
            writer.write_all(&plaintext)?;
            counter += 1;
        }
        Ok(())
    })();

    drop(writer);

    if let Err(e) = decrypt_result {
        let _ = zstd_proc.wait();
        let _ = tar_proc.wait();
        let _ = std::fs::remove_dir_all(output_dir);
        return Err(e);
    }

    let zstd_status = zstd_proc.wait()?;
    let tar_status = tar_proc.wait()?;
    if !zstd_status.success() {
        let _ = std::fs::remove_dir_all(output_dir);
        bail!("zstd decompression failed");
    }
    if !tar_status.success() {
        let _ = std::fs::remove_dir_all(output_dir);
        bail!("tar extraction failed");
    }

    eprintln!("extracted: {}", output_dir.display());
    Ok(())
}
