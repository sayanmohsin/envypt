//! Native SOPS-over-age encryption for openenvcrypt.
//!
//! This crate implements the SOPS file format for dotenv documents with age
//! recipients, so `openenvcrypt` needs no external `sops`/`rage` binaries and
//! files remain interchangeable with official SOPS. See [`store`] for the
//! format and [`keys`] for age key handling.

pub mod keys;
pub mod store;
pub mod util;
pub mod value;

use anyhow::{Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

pub use keys::{Identity, Recipient};

/// Default per-user key directory (relative to the config home).
pub fn default_key_dir() -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        })
        .join("openenvcrypt")
        .join("keys")
}

/// Atomic write: temp file in the same directory, fsync, rename.
fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".into());
    let tmp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut file, content)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Encrypt `content` and write it to `path` atomically for `recipients`.
pub fn encrypt(content: &str, path: &Path, recipients: &[String]) -> Result<()> {
    let text = store::encrypt(content, &store::recipients_from_strings(recipients)?)?;
    atomic_write(path, text.as_bytes())
}

/// Decrypt the file at `path` using identities from the environment and (when
/// `environment` is given) the default per-user key file for that environment.
pub fn decrypt_for(path: &Path, environment: Option<&str>) -> Result<String> {
    let mut identities = keys::identities_from_env();
    if let Some(name) = environment {
        let key_path = default_key_dir().join(format!("{name}.txt"));
        if key_path.is_file()
            && let Ok(identity) = keys::read_identity_file(&key_path)
        {
            identities.push(identity);
        }
    }
    if identities.is_empty() {
        anyhow::bail!(
            "no age identity available; set OPENENCRYPT_AGE_KEY/SOPS_AGE_KEY or a key file"
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read encrypted file {}", path.display()))?;
    store::decrypt(&text, &identities)
}

/// Decrypt the file at `path` using environment-supplied identities only.
pub fn decrypt(path: &Path) -> Result<String> {
    decrypt_for(path, None)
}

/// List the recipients recorded in the encrypted file at `path`.
pub fn recipients_of(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read encrypted file {}", path.display()))?;
    store::list_recipients(&text)
}

/// Generate a fresh age identity and write it to `path` (mode 0600).
/// Returns the full key-file text so callers can print the public key.
pub fn generate_key(path: &Path) -> Result<String> {
    let (text, _public) = keys::generate_identity()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text.as_bytes())
        .with_context(|| format!("write key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod key file {}", path.display()))?;
    }
    Ok(text)
}
