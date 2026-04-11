use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::crypto;
use crate::format::{self, ZscHeader};

pub fn explore(file: &Path, passphrase: &str) -> Result<()> {
    let mut input = BufReader::new(
        File::open(file).with_context(|| format!("cannot open {}", file.display()))?,
    );
    let header = ZscHeader::read_from(&mut input)?;

    eprint!("deriving key...");
    let key = crypto::derive_key(passphrase, &header)?;
    eprintln!(" done");

    let cipher = crypto::make_cipher(&key);

    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");
    let tmppath = PathBuf::from(format!("/dev/shm/{stem}.tar.zst"));

    let tmp = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmppath)
            .with_context(|| format!("cannot create {}", tmppath.display()))?
    };
    let mut tmpfile = BufWriter::with_capacity(4 * 1024 * 1024, tmp);

    let mut counter: u64 = 0;

    let result = (|| -> Result<()> {
        loop {
            let chunk_len = format::read_chunk_len(&mut input)
                .context("archive is truncated")?;
            if chunk_len == 0 {
                break;
            }
            let mut ciphertext = vec![0u8; chunk_len];
            input
                .read_exact(&mut ciphertext)
                .context("archive is truncated")?;
            let plaintext =
                crypto::decrypt_chunk(&cipher, &header.nonce, counter, &ciphertext)?;
            tmpfile.write_all(&plaintext)?;
            counter += 1;
        }
        tmpfile.flush()?;
        Ok(())
    })();

    if let Err(e) = result {
        drop(tmpfile);
        let _ = std::fs::remove_file(&tmppath);
        return Err(e);
    }
    drop(tmpfile);

    // Open in default archive handler
    Command::new("xdg-open")
        .arg(&tmppath)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to launch xdg-open")?;

    thread::sleep(Duration::from_secs(1));

    // Poll until no process has the file open
    loop {
        let status = Command::new("fuser")
            .arg(&tmppath)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => thread::sleep(Duration::from_secs(2)),
            _ => break,
        }
    }

    let _ = std::fs::remove_file(&tmppath);
    Ok(())
}

