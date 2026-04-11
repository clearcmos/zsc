mod crypto;
mod explore;
mod format;
mod open;
mod seal;

use std::io::{BufRead, BufReader};
use std::os::fd::FromRawFd;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;

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

    /// Input path (directory for -e, archive for -d/--explore)
    input: PathBuf,

    /// Output path (archive for -e, directory for -d)
    output: Option<PathBuf>,
}

fn read_passphrase(fd: Option<i32>, confirm: bool) -> Result<String> {
    let pass = if let Some(fd) = fd {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line.trim_end_matches('\n').to_string()
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

    let encrypt = cli.encrypt
        || (!cli.decrypt && !cli.explore && cli.input.is_dir());
    let decrypt = cli.decrypt
        || (!cli.encrypt && !cli.explore && !cli.input.is_dir()
            && cli.input.extension().map_or(false, |e| e == "zsc"));

    if !encrypt && !decrypt && !cli.explore {
        bail!("specify -e (encrypt), -d (decrypt), or --explore");
    }

    if encrypt {
        let directory = &cli.input;
        let passphrase = read_passphrase(cli.passphrase_fd, cli.passphrase_fd.is_none())?;
        let output = cli.output.unwrap_or_else(|| {
            let name = directory
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "archive".to_string());
            PathBuf::from(format!("{name}.zsc"))
        });
        seal::seal(directory, &output, &passphrase)?;
    } else if decrypt {
        let file = &cli.input;
        let passphrase = read_passphrase(cli.passphrase_fd, false)?;
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
        let passphrase = read_passphrase(cli.passphrase_fd, false)?;
        explore::explore(file, &passphrase)?;
    }

    Ok(())
}
