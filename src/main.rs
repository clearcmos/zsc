mod crypto;
mod explore;
mod format;
mod open;
mod seal;

use std::io::{BufRead, BufReader};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "zsc",
    version,
    about = "Encrypted compressed archives",
    long_about = "Encrypted compressed archives.\n\n\
        With no flag, the action is auto-detected from the input: a path ending \
        in .zsc is decrypted, anything else is encrypted."
)]
struct Cli {
    /// Encrypt a file or directory
    #[arg(short = 'e', conflicts_with_all = ["decrypt", "explore"])]
    encrypt: bool,

    /// Decrypt and extract an archive
    #[arg(short = 'd', conflicts_with_all = ["encrypt", "explore"])]
    decrypt: bool,

    /// Decrypt to tmpfs and open in the default archive viewer (Linux only)
    #[arg(long, conflicts_with_all = ["encrypt", "decrypt"])]
    explore: bool,

    /// Read passphrase from this file descriptor (one line, trailing newline stripped)
    #[arg(long)]
    passphrase_fd: Option<i32>,

    /// Input path (file/directory to encrypt, or .zsc archive to decrypt)
    input: PathBuf,

    /// Output path (defaults to <input>.zsc for encrypt, <input-stem>/ for decrypt)
    output: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
struct Config {
    passphrase_cmd: Option<String>,
}

fn load_config() -> Result<Config> {
    let Some(config_dir) = dirs::config_dir() else {
        return Ok(Config::default());
    };
    let path = config_dir.join("zsc").join("config.toml");
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    toml::from_str(&contents).with_context(|| format!("cannot parse {}", path.display()))
}

fn read_passphrase_cmd(cmd: &str) -> Result<Zeroizing<String>> {
    let output = Command::new("sh")
        .args(["-c", cmd])
        .output()
        .with_context(|| format!("failed to run passphrase_cmd: {cmd}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("passphrase_cmd failed: {}", stderr.trim());
    }

    let pass = String::from_utf8(output.stdout)
        .context("invalid UTF-8 from passphrase_cmd")?
        .trim_end_matches('\n')
        .to_string();

    if pass.is_empty() {
        bail!("passphrase_cmd returned an empty passphrase");
    }

    Ok(Zeroizing::new(pass))
}

fn read_passphrase(
    fd: Option<i32>,
    passphrase_cmd: Option<&str>,
    confirm: bool,
) -> Result<Zeroizing<String>> {
    let pass = if let Some(fd) = fd {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches('\n').to_string())
    } else if let Some(cmd) = passphrase_cmd {
        read_passphrase_cmd(cmd)?
    } else {
        let pass = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
        if confirm {
            let pass2 = Zeroizing::new(rpassword::prompt_password("Confirm: ")?);
            if *pass != *pass2 {
                bail!("passphrases do not match");
            }
        }
        pass
    };

    if pass.is_empty() {
        bail!("passphrase cannot be empty");
    }

    Ok(pass)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config()?;

    let passphrase_cmd = config.passphrase_cmd.as_deref();

    let is_zsc = cli.input.extension().is_some_and(|e| e == "zsc");
    let encrypt = cli.encrypt || (!cli.decrypt && !cli.explore && !is_zsc && cli.input.exists());
    let decrypt = cli.decrypt || (!cli.encrypt && !cli.explore && is_zsc);

    if !encrypt && !decrypt && !cli.explore {
        bail!("specify -e (encrypt), -d (decrypt), or --explore");
    }

    if encrypt {
        let input = &cli.input;
        let auto = passphrase_cmd.is_some();
        let confirm = cli.passphrase_fd.is_none() && !auto;
        let passphrase = read_passphrase(cli.passphrase_fd, passphrase_cmd, confirm)?;
        let output = cli.output.unwrap_or_else(|| {
            let stem = if input.is_dir() {
                input
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "archive".to_string())
            } else {
                input
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "archive".to_string())
            };
            PathBuf::from(format!("{stem}.zsc"))
        });
        seal::seal(input, &output, &passphrase)?;
    } else if decrypt {
        let file = &cli.input;
        let passphrase = read_passphrase(cli.passphrase_fd, passphrase_cmd, false)?;
        let output_dir = cli.output.unwrap_or_else(|| {
            let stem = file
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "output".to_string());
            PathBuf::from(stem)
        });
        open::open(file, &output_dir, &passphrase)?;
    } else {
        let file = &cli.input;
        let passphrase = read_passphrase(cli.passphrase_fd, passphrase_cmd, false)?;
        explore::explore(file, &passphrase)?;
    }

    Ok(())
}
