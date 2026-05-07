//! End-to-end seal/open roundtrip exercising the actual binary, including
//! the external tar + zstd pipeline. Skipped if either tool is missing
//! (e.g. minimal CI containers without `tar` or `zstd` on PATH).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("zsc-test-{label}-{nanos}-{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn require_tools() -> bool {
    for tool in ["tar", "zstd"] {
        let ok = Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("skipping: `{tool}` not on PATH");
            return false;
        }
    }
    true
}

fn zsc_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zsc"))
}

fn run_zsc_with_pass(args: &[&Path], pass: &str) -> std::process::Output {
    let mut child = Command::new(zsc_bin())
        .args(args)
        .arg("--passphrase-fd")
        .arg("0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zsc");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{pass}\n").as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait zsc")
}

fn dir_eq(a: &Path, b: &Path) -> bool {
    let status = Command::new("diff")
        .args(["-r", "-q"])
        .arg(a)
        .arg(b)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn diff");
    status.success()
}

#[test]
fn seal_open_directory_roundtrip() {
    if !require_tools() {
        return;
    }

    let work = unique_tmp("roundtrip");
    let input = work.join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"hello world\n").unwrap();
    fs::write(input.join("b.bin"), [0u8, 1, 2, 3, 4, 5]).unwrap();
    fs::create_dir_all(input.join("sub")).unwrap();
    fs::write(input.join("sub/c.txt"), b"nested\n").unwrap();

    let archive = work.join("out.zsc");
    let restored = work.join("restored");

    let pass = "correct horse battery staple";

    let seal = run_zsc_with_pass(&[Path::new("-e"), &input, &archive], pass);
    assert!(
        seal.status.success(),
        "seal failed: stderr={}",
        String::from_utf8_lossy(&seal.stderr)
    );
    assert!(archive.is_file());

    let open = run_zsc_with_pass(&[Path::new("-d"), &archive, &restored], pass);
    assert!(
        open.status.success(),
        "open failed: stderr={}",
        String::from_utf8_lossy(&open.stderr)
    );

    assert!(dir_eq(&input, &restored), "input and restored differ");

    fs::remove_dir_all(&work).ok();
}

#[test]
fn open_with_wrong_passphrase_fails() {
    if !require_tools() {
        return;
    }

    let work = unique_tmp("wrongpass");
    let input = work.join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("file.txt"), b"data\n").unwrap();

    let archive = work.join("out.zsc");
    let seal = run_zsc_with_pass(&[Path::new("-e"), &input, &archive], "right");
    assert!(seal.status.success());

    let restored = work.join("restored");
    let open = run_zsc_with_pass(&[Path::new("-d"), &archive, &restored], "wrong");
    assert!(!open.status.success());
    let stderr = String::from_utf8_lossy(&open.stderr);
    assert!(
        stderr.contains("wrong passphrase") || stderr.contains("authentication failed"),
        "unexpected stderr: {stderr}"
    );

    fs::remove_dir_all(&work).ok();
}

#[test]
fn open_rejects_tampered_header() {
    if !require_tools() {
        return;
    }

    let work = unique_tmp("tamper");
    let input = work.join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("file.txt"), b"data\n").unwrap();

    let archive = work.join("out.zsc");
    let pass = "p";
    let seal = run_zsc_with_pass(&[Path::new("-e"), &input, &archive], pass);
    assert!(seal.status.success());

    // Flip a bit in the m_cost field of the header (offset 4..8 from start).
    let mut bytes = fs::read(&archive).unwrap();
    bytes[4] ^= 0x01;
    fs::write(&archive, &bytes).unwrap();

    let restored = work.join("restored");
    let open = run_zsc_with_pass(&[Path::new("-d"), &archive, &restored], pass);
    assert!(!open.status.success(), "tampered archive must not decrypt");

    fs::remove_dir_all(&work).ok();
}
