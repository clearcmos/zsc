use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use crate::crypto;
use crate::format::{ZscHeader, CHUNK_PLAINTEXT_SIZE};

pub fn seal(directory: &Path, output: &Path, passphrase: &str) -> Result<()> {
    if !directory.is_dir() {
        bail!("not a directory: {}", directory.display());
    }
    if output.exists() {
        bail!("output already exists: {}", output.display());
    }

    let header = ZscHeader::generate();

    eprint!("deriving key...");
    let key = crypto::derive_key(passphrase, &header)?;
    eprintln!(" done");

    let cipher = crypto::make_cipher(&key);

    let mut out = BufWriter::with_capacity(
        4 * 1024 * 1024,
        File::create(output).with_context(|| format!("cannot create {}", output.display()))?,
    );
    header.write_to(&mut out)?;

    // Use external tar | zstd pipeline for maximum throughput.
    // zstd -T0 uses all cores and its internal job scheduler works best this way.
    let mut tar_proc = Command::new("tar")
        .args(["cf", "-", "-C"])
        .arg(directory)
        .arg(".")
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn tar")?;

    let mut zstd_proc = Command::new("zstd")
        .args(["-T0", "--stdout"])
        .stdin(tar_proc.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn zstd")?;

    let mut reader = zstd_proc.stdout.take().unwrap();
    let mut chunk_buf = vec![0u8; CHUNK_PLAINTEXT_SIZE];
    let mut counter: u64 = 0;

    let encrypt_result = (|| -> Result<()> {
        loop {
            let n = read_fill(&mut reader, &mut chunk_buf)?;
            if n == 0 {
                break;
            }
            let encrypted =
                crypto::encrypt_chunk(&cipher, &header.nonce, counter, &chunk_buf[..n])?;
            out.write_all(&(encrypted.len() as u32).to_le_bytes())?;
            out.write_all(&encrypted)?;
            counter += 1;
        }
        out.write_all(&0u32.to_le_bytes())?;
        out.flush()?;
        Ok(())
    })();

    if let Err(e) = encrypt_result {
        drop(out);
        let _ = std::fs::remove_file(output);
        let _ = tar_proc.wait();
        let _ = zstd_proc.wait();
        return Err(e);
    }

    let tar_status = tar_proc.wait()?;
    let zstd_status = zstd_proc.wait()?;
    if !tar_status.success() {
        let _ = std::fs::remove_file(output);
        bail!("tar failed with {tar_status}");
    }
    if !zstd_status.success() {
        let _ = std::fs::remove_file(output);
        bail!("zstd failed with {zstd_status}");
    }

    let input_size = dir_size(directory);
    let output_size = std::fs::metadata(output)?.len();
    let ratio = if input_size > 0 {
        (1.0 - output_size as f64 / input_size as f64) * 100.0
    } else {
        0.0
    };

    eprintln!(
        "created: {} ({} -> {}, {:.1}% reduction)",
        output.display(),
        human_size(input_size),
        human_size(output_size),
        ratio
    );

    Ok(())
}

/// Read until buf is full or EOF. Returns number of bytes read.
fn read_fill(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn dir_size(path: &Path) -> u64 {
    walkdir(path)
}

fn walkdir(path: &Path) -> u64 {
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                size += walkdir(&entry.path());
            } else {
                size += meta.len();
            }
        }
    }
    size
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1}{unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1}P")
}
