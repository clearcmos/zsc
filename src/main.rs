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

#[derive(Parser)]
#[command(name = "zsc", about = "Encrypted compressed archives")]
struct Cli {
    /// Encrypt a directory
    #[arg(short = 'e', conflicts_with_all = ["decrypt", "explore"])]
    encrypt: bool,

    /// Decrypt and extract an archive
    #[arg(short = 'd', conflicts_with_all = ["encrypt", "explore"])]
    decrypt: bool,

    /// Decrypt to tmpfs and open in archive viewer
    #[arg(long, conflicts_with_all = ["encrypt", "decrypt"])]
    explore: bool,

    /// Read passphrase from this file descriptor
    #[arg(long)]
    passphrase_fd: Option<i32>,

    /// Fetch passphrase from Bitwarden (item name or ID)
    #[arg(long, conflicts_with = "passphrase_fd")]
    bw: Option<String>,

    /// Input path (directory for -e, archive for -d/--explore)
    input: PathBuf,

    /// Output path (archive for -e, directory for -d)
    output: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
struct Config {
    passphrase_cmd: Option<String>,
    bw_item: Option<String>,
}

fn load_config() -> Config {
    let Some(config_dir) = dirs::config_dir() else {
        return Config::default();
    };
    let path = config_dir.join("zsc").join("config.toml");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Config::default();
    };
    toml::from_str(&contents).unwrap_or_default()
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes()
            .enumerate()
            .all(|(i, b)| match i {
                8 | 13 | 18 | 23 => b == b'-',
                _ => b.is_ascii_hexdigit(),
            })
}

fn read_passphrase_cmd(cmd: &str) -> Result<String> {
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

    Ok(pass)
}

fn read_passphrase_bw(item: &str) -> Result<String> {
    if is_uuid(item) {
        // UUID: direct lookup
        let output = Command::new("bw")
            .args(["get", "password", item])
            .output()
            .context("failed to run bw - is it installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("bw failed: {}", stderr.trim());
        }

        let pass = String::from_utf8(output.stdout)
            .context("invalid UTF-8 in password")?
            .trim_end_matches('\n')
            .to_string();

        if pass.is_empty() {
            bail!("bw returned an empty password");
        }

        Ok(pass)
    } else {
        // Friendly name: list + exact match
        let output = Command::new("bw")
            .args(["list", "items", "--search", item])
            .output()
            .context("failed to run bw - is it installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("bw failed: {}", stderr.trim());
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse vault response")?;

        let items = json.as_array().context("unexpected vault response format")?;

        let matches: Vec<&serde_json::Value> = items
            .iter()
            .filter(|v| v.get("name").and_then(|n| n.as_str()) == Some(item))
            .collect();

        match matches.len() {
            0 => bail!("no vault item named '{item}'"),
            1 => {},
            n => bail!("{n} vault items named '{item}' - use the item ID instead"),
        }

        let pass = matches[0]
            .get("login")
            .and_then(|l| l.get("password"))
            .and_then(|p| p.as_str())
            .context("vault item has no password")?;

        if pass.is_empty() {
            bail!("vault item '{item}' has an empty password");
        }

        Ok(pass.to_string())
    }
}

fn read_passphrase(
    fd: Option<i32>,
    bw: Option<&str>,
    passphrase_cmd: Option<&str>,
    bw_item: Option<&str>,
    confirm: bool,
) -> Result<String> {
    let pass = if let Some(fd) = fd {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line.trim_end_matches('\n').to_string()
    } else if let Some(item) = bw {
        read_passphrase_bw(item)?
    } else if let Some(cmd) = passphrase_cmd {
        read_passphrase_cmd(cmd)?
    } else if let Some(item) = bw_item {
        read_passphrase_bw(item)?
    } else {
        let pass = rpassword::prompt_password("Passphrase: ")?;
        if confirm {
            let pass2 = rpassword::prompt_password("Confirm: ")?;
            if pass != pass2 {
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
    let config = load_config();

    let passphrase_cmd = config.passphrase_cmd.as_deref();
    let bw_item = config.bw_item.as_deref();

    let is_zsc = cli.input.extension().map_or(false, |e| e == "zsc");
    let encrypt = cli.encrypt
        || (!cli.decrypt && !cli.explore && !is_zsc && cli.input.exists());
    let decrypt = cli.decrypt
        || (!cli.encrypt && !cli.explore && is_zsc);

    if !encrypt && !decrypt && !cli.explore {
        bail!("specify -e (encrypt), -d (decrypt), or --explore");
    }

    if encrypt {
        let input = &cli.input;
        let auto = cli.bw.is_some() || passphrase_cmd.is_some() || bw_item.is_some();
        let confirm = cli.passphrase_fd.is_none() && !auto;
        let passphrase = read_passphrase(cli.passphrase_fd, cli.bw.as_deref(), passphrase_cmd, bw_item, confirm)?;
        let output = cli.output.unwrap_or_else(|| {
            let stem = if input.is_dir() {
                input.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "archive".to_string())
            } else {
                input.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "archive".to_string())
            };
            PathBuf::from(format!("{stem}.zsc"))
        });
        seal::seal(input, &output, &passphrase)?;
    } else if decrypt {
        let file = &cli.input;
        let passphrase = read_passphrase(cli.passphrase_fd, cli.bw.as_deref(), passphrase_cmd, bw_item, false)?;
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
        let passphrase = read_passphrase(cli.passphrase_fd, cli.bw.as_deref(), passphrase_cmd, bw_item, false)?;
        explore::explore(file, &passphrase)?;
    }

    Ok(())
}
