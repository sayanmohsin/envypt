//! SOPS-compatible dotenv store.
//!
//! Mirrors `github.com/getsops/sops/v3/stores/dotenv` with the
//! `MetadataFlattenFull` layout used by SOPS >= 3.9 for age-only files:
//! encrypted `KEY=ENC[...]` lines followed by flattened metadata lines
//! (`sops_age__list_0__map_enc`, `sops_mac`, ...). Files are interchangeable
//! with official `sops` output.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use zeroize::Zeroize;

use super::{
    keys::{self, Identity, Recipient},
    util, value,
};

/// SOPS version string written into the metadata (`sops_version`).
///
/// This pins the metadata layout (flattened `sops_` keys, timestamped MAC AAD)
/// that this crate implements; files remain readable by that sops version.
pub const SOPS_VERSION: &str = "3.13.3";

/// Default unencrypted suffix written into the metadata.
pub const UNENCRYPTED_SUFFIX: &str = "_unencrypted";

const METADATA_PREFIX: &str = "sops_";
/// AAD for top-level comment leaves: their tree path is empty, so the path
/// string is `":"`.
const COMMENT_AAD: &[u8] = b":";

/// Parsed metadata from an encrypted file.
#[derive(Debug, Clone)]
pub struct Metadata {
    pub version: Option<String>,
    pub lastmodified: Option<String>,
    pub unencrypted_suffix: Option<String>,
    /// `(recipient, armored encrypted data key)` entries.
    pub age: Vec<(String, String)>,
    pub mac: Option<String>,
}

impl Metadata {
    fn has_prefix(key: &str) -> bool {
        key.starts_with(METADATA_PREFIX)
    }
}

/// One logical line of a dotenv document.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Comment(String),
    Var { key: String, value: String },
}

/// A raw `sops_*` metadata leaf: `(flattened key, value)`.
type MetadataLeaf = (String, String);

fn unescape(value: &str) -> String {
    value.replace("\\n", "\n")
}

fn escape(value: &str) -> String {
    value.replace('\n', "\\n")
}

/// Parse a dotenv document into ordered entries plus any `sops_` metadata
/// leaves, in order.
fn parse_document(text: &str) -> Result<(Vec<Entry>, Vec<MetadataLeaf>)> {
    let mut entries = Vec::new();
    let mut metadata = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        if let Some(content) = line.strip_prefix('#') {
            entries.push(Entry::Comment(content.to_string()));
            continue;
        }
        let Some(pos) = line.find('=') else {
            bail!("invalid dotenv line (missing '='): {line}");
        };
        let key = line[..pos].to_string();
        let entry = Entry::Var {
            value: unescape(&line[pos + 1..]),
            key: key.clone(),
        };
        if Metadata::has_prefix(&key) {
            let value = match &entry {
                Entry::Var { value, .. } => value.clone(),
                Entry::Comment(_) => unreachable!(),
            };
            metadata.push((key, value));
        } else {
            entries.push(entry);
        }
    }
    Ok((entries, metadata))
}

/// Assemble the flattened metadata lines in canonical SOPS order.
fn flatten_metadata(metadata: &Metadata) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (index, (recipient, enc)) in metadata.age.iter().enumerate() {
        out.push((format!("sops_age__list_{index}__map_enc"), enc.clone()));
        out.push((
            format!("sops_age__list_{index}__map_recipient"),
            recipient.clone(),
        ));
    }
    if let Some(v) = &metadata.lastmodified {
        out.push(("sops_lastmodified".into(), v.clone()));
    }
    if let Some(v) = &metadata.mac {
        out.push(("sops_mac".into(), v.clone()));
    }
    if let Some(v) = &metadata.unencrypted_suffix {
        out.push(("sops_unencrypted_suffix".into(), v.clone()));
    }
    if let Some(v) = &metadata.version {
        out.push(("sops_version".into(), v.clone()));
    }
    out
}

fn parse_metadata(leaves: &[(String, String)]) -> Result<Metadata> {
    let mut seen = BTreeMap::new();
    let mut age = BTreeMap::new();
    for (key, value) in leaves {
        if let Some(rest) = key.strip_prefix(METADATA_PREFIX) {
            if let Some((index, field)) = rest
                .strip_prefix("age__list_")
                .and_then(|r| r.split_once("__map_"))
                .and_then(|(idx, field)| idx.parse::<usize>().ok().map(|i| (i, field)))
            {
                if seen.insert(key.clone(), ()).is_some() {
                    bail!("duplicate metadata key {key}");
                }
                let item = age.entry(index).or_insert_with(|| (None, None));
                match field {
                    "recipient" => item.0 = Some(value.clone()),
                    "enc" => item.1 = Some(value.clone()),
                    other => bail!("unsupported age metadata field: {other}"),
                }
            } else {
                if seen.insert(key.clone(), ()).is_some() {
                    bail!("duplicate metadata key {key}");
                }
            }
        }
    }
    let mut metadata = Metadata {
        version: None,
        lastmodified: None,
        unencrypted_suffix: None,
        age: Vec::new(),
        mac: None,
    };
    for (key, value) in leaves {
        let Some(rest) = key.strip_prefix(METADATA_PREFIX) else {
            continue;
        };
        match rest {
            "version" => metadata.version = Some(value.clone()),
            "lastmodified" => metadata.lastmodified = Some(value.clone()),
            "unencrypted_suffix" => metadata.unencrypted_suffix = Some(value.clone()),
            "mac" => metadata.mac = Some(value.clone()),
            _ => {}
        }
    }
    for (index, (recipient, enc)) in age {
        let (Some(_recipient), Some(_enc)) = (&recipient, &enc) else {
            bail!("incomplete age metadata entry at index {index}");
        };
        metadata.age.push((recipient.unwrap(), enc.unwrap()));
    }
    Ok(metadata)
}

/// Compute the SHA-512 MAC over plaintext leaf values in document order.
fn compute_mac<I>(values: I) -> String
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let mut hasher = Sha512::new();
    for value in values {
        hasher.update(&value);
    }
    hex::encode_upper(hasher.finalize())
}

/// Encrypt a plaintext dotenv document for `recipients`.
///
/// Returns the SOPS-encrypted dotenv text. Fails closed on a reserved `sops_`
/// key or an empty recipient list.
pub fn encrypt(plaintext: &str, recipients: &[Recipient]) -> Result<String> {
    if recipients.is_empty() {
        bail!("refusing to encrypt: no age recipients configured");
    }
    let (entries, metadata) = parse_document(plaintext)?;
    if !metadata.is_empty() {
        bail!(
            "refusing to encrypt: the input contains {METADATA_PREFIX}* keys reserved for SOPS metadata"
        );
    }

    let mut data_key = [0u8; 32];
    let mut rng = rand::rngs::SysRng;
    rand::TryRng::try_fill_bytes(&mut rng, &mut data_key)
        .map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;

    let mut mac_values = Vec::new();
    let mut lines = Vec::new();
    for entry in &entries {
        match entry {
            Entry::Comment(content) => {
                let encrypted =
                    value::encrypt_kind(content.as_bytes(), &data_key, COMMENT_AAD, "comment")
                        .context("encrypt comment")?;
                lines.push(format!("#{}", escape(&encrypted)));
            }
            Entry::Var { key, value } => {
                let unencrypted = key.ends_with(UNENCRYPTED_SUFFIX);
                mac_values.push(value.clone().into_bytes());
                if unencrypted {
                    lines.push(format!("{key}={}", escape(value)));
                } else {
                    let aad = format!("{key}:");
                    let encrypted = value::encrypt(value.as_bytes(), &data_key, aad.as_bytes())
                        .with_context(|| format!("encrypt value {key}"))?;
                    lines.push(format!("{key}={}", escape(&encrypted)));
                }
            }
        }
    }
    let mac = compute_mac(mac_values);
    let lastmodified = util::rfc3339_now();
    let mac_enc = value::encrypt(mac.as_bytes(), &data_key, lastmodified.as_bytes())
        .context("encrypt MAC")?;

    let mut age = Vec::new();
    for recipient in recipients {
        let enc = keys::wrap_data_key(&data_key, recipient)
            .with_context(|| format!("wrap data key for {recipient}"))?;
        age.push((recipient.to_string(), enc));
    }
    data_key.zeroize();

    let metadata = Metadata {
        version: Some(SOPS_VERSION.into()),
        lastmodified: Some(lastmodified),
        unencrypted_suffix: Some(UNENCRYPTED_SUFFIX.into()),
        age,
        mac: Some(mac_enc),
    };
    for (key, value) in flatten_metadata(&metadata) {
        lines.push(format!("{key}={}", escape(&value)));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// Decrypt a SOPS dotenv document with the provided identities.
///
/// Fails closed when no identity can unwrap the data key or when the MAC does
/// not match. Returns the plaintext dotenv text.
pub fn decrypt(encrypted: &str, identities: &[Identity]) -> Result<String> {
    let (entries, metadata_leaves) = parse_document(encrypted)?;
    let metadata = parse_metadata(&metadata_leaves)?;
    let lastmodified = metadata
        .lastmodified
        .as_deref()
        .context("missing sops_lastmodified metadata")?;
    let mac_enc = metadata
        .mac
        .as_deref()
        .context("missing sops_mac metadata")?;

    let enc_values: Vec<String> = metadata.age.iter().map(|(_, enc)| enc.clone()).collect();
    let mut data_key = keys::unwrap_data_key(&enc_values, identities)?;

    let suffix = metadata.unencrypted_suffix.as_deref().unwrap_or("");
    let mut mac_values = Vec::new();
    let mut lines = Vec::new();
    for entry in &entries {
        match entry {
            Entry::Comment(content) => {
                let plain = if content.starts_with("ENC[AES256_GCM,") {
                    match value::decrypt(content, &data_key, COMMENT_AAD) {
                        Ok(plain) => plain,
                        // SOPS tolerates plaintext comments that happen to look
                        // like ENC values; keep them verbatim.
                        Err(_) => content.clone(),
                    }
                } else {
                    content.clone()
                };
                lines.push(format!("#{}", escape(&plain)));
            }
            Entry::Var { key, value } => {
                let plain = if !suffix.is_empty() && key.ends_with(suffix) {
                    value.clone()
                } else {
                    let aad = format!("{key}:");
                    value::decrypt(value, &data_key, aad.as_bytes())
                        .with_context(|| format!("decrypt value {key}"))?
                };
                mac_values.push(plain.clone().into_bytes());
                lines.push(format!("{key}={}", escape(&plain)));
            }
        }
    }
    let computed = compute_mac(mac_values);
    let stored = value::decrypt(mac_enc, &data_key, lastmodified.as_bytes())
        .context("cannot decrypt MAC (wrong key?)")?;
    data_key.zeroize();

    if computed != stored {
        bail!("MAC mismatch: file is corrupted or was modified");
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// List the public recipients recorded in an encrypted document (no key needed).
pub fn list_recipients(encrypted: &str) -> Result<Vec<String>> {
    let (_, metadata_leaves) = parse_document(encrypted)?;
    let metadata = parse_metadata(&metadata_leaves)?;
    let recipients: Vec<String> = metadata.age.iter().map(|(r, _)| r.clone()).collect();
    if recipients.is_empty() {
        bail!("no age recipients found in metadata");
    }
    Ok(recipients)
}

/// Parse recipient strings.
pub fn recipients_from_strings(strings: &[String]) -> Result<Vec<Recipient>> {
    strings.iter().map(|s| keys::parse_recipient(s)).collect()
}
