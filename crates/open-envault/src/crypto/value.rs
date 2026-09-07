//! SOPS value encryption: the `ENC[AES256_GCM,...]` strings.
//!
//! Mirrors `github.com/getsops/sops/v3/aes` (v3.13.x). AES-256-GCM with a
//! 32-byte nonce, the authentication tag stored separately, and the AAD equal
//! to the value's tree path (e.g. `"KEY:"` for a top-level dotenv variable, or
//! `"sops_mac"`-style paths for the metadata MAC). An empty plaintext encrypts
//! to the empty string (no `ENC[...]` wrapper), exactly like SOPS.

use aes_gcm::aead::consts::U32;
use aes_gcm::{
    AesGcm,
    aead::{Aead, KeyInit, Nonce, Payload},
    aes::Aes256,
};
use anyhow::{Context, bail};
use base64::Engine;
use rand::{TryRng, rngs::SysRng};

type Cipher = AesGcm<Aes256, U32>;

const PREFIX: &str = "ENC[AES256_GCM,data:";

fn random_bytes<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut buf = [0u8; N];
    let mut rng = SysRng;
    rng.try_fill_bytes(&mut buf)
        .map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
    Ok(buf)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Encrypt `plain` under `key` with `aad`, returning the SOPS value string.
///
/// Returns the empty string when `plain` is empty (matching SOPS `isEmpty`).
pub fn encrypt(plain: &[u8], key: &[u8; 32], aad: &[u8]) -> anyhow::Result<String> {
    encrypt_kind(plain, key, aad, "str")
}

/// Like [`encrypt`] but with an explicit SOPS value type (e.g. `comment`).
pub fn encrypt_kind(
    plain: &[u8],
    key: &[u8; 32],
    aad: &[u8],
    kind: &str,
) -> anyhow::Result<String> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let cipher =
        Cipher::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES key length"))?;
    let iv = random_bytes::<32>().context("generate AES-GCM nonce")?;
    let nonce = Nonce::<Cipher>::try_from(iv.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid AES-GCM nonce length"))?;
    let encrypted = cipher
        .encrypt(&nonce, Payload { msg: plain, aad })
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;
    let split = encrypted
        .len()
        .checked_sub(16)
        .context("ciphertext shorter than GCM tag")?;
    let (data, tag) = encrypted.split_at(split);
    Ok(format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:{kind}]",
        b64(data),
        b64(&iv),
        b64(tag)
    ))
}

struct Parsed {
    data: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

fn parse(enc: &str) -> anyhow::Result<Parsed> {
    let rest = enc
        .strip_prefix(PREFIX)
        .with_context(|| "value is not in SOPS ENC format")?;
    let data_b64 = rest
        .split_once(",iv:")
        .context("malformed ENC value: missing iv")?
        .0;
    let (iv_b64, tag_and_type) = rest
        .split_once(",iv:")
        .context("malformed ENC value: missing iv")?
        .1
        .split_once(",tag:")
        .context("malformed ENC value: missing tag")?;
    let (tag_b64, kind) = tag_and_type
        .split_once(",type:")
        .context("malformed ENC value: missing type")?;
    let kind = kind
        .strip_suffix(']')
        .context("malformed ENC value: missing ]")?;
    if !matches!(kind, "str" | "comment") {
        bail!("unsupported SOPS value type: {kind}");
    }
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(Parsed {
        data: engine.decode(data_b64).context("invalid data base64")?,
        iv: engine.decode(iv_b64).context("invalid iv base64")?,
        tag: engine.decode(tag_b64).context("invalid tag base64")?,
    })
}

/// Decrypt a SOPS value string under `key` with `aad`.
///
/// An empty string decrypts to an empty plaintext (matching SOPS `isEmpty`).
pub fn decrypt(enc: &str, key: &[u8; 32], aad: &[u8]) -> anyhow::Result<String> {
    if enc.is_empty() {
        return Ok(String::new());
    }
    let parsed = parse(enc)?;
    if parsed.iv.len() != 32 {
        bail!("unexpected IV length {} (expected 32)", parsed.iv.len());
    }
    let cipher =
        Cipher::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES key length"))?;
    let mut combined = Vec::with_capacity(parsed.data.len() + parsed.tag.len());
    combined.extend_from_slice(&parsed.data);
    combined.extend_from_slice(&parsed.tag);
    let nonce = Nonce::<Cipher>::try_from(parsed.iv.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid AES-GCM nonce length"))?;
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &combined,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed (wrong key or corrupted value)"))?;
    String::from_utf8(plain).map_err(|_| anyhow::anyhow!("decrypted value was not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let plain = b"production";
        let enc = encrypt(plain, &key, b"APP_ENV:").unwrap();
        assert!(enc.starts_with(PREFIX));
        assert!(enc.ends_with(",type:str]"));
        assert_eq!(decrypt(&enc, &key, b"APP_ENV:").unwrap(), "production");
    }

    #[test]
    fn empty_plaintext_stays_empty() {
        let key = [1u8; 32];
        assert_eq!(encrypt(b"", &key, b"EMPTY:").unwrap(), "");
        assert_eq!(decrypt("", &key, b"EMPTY:").unwrap(), "");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [2u8; 32];
        let enc = encrypt(b"secret", &key, b"A:").unwrap();
        assert!(decrypt(&enc, &key, b"B:").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let enc = encrypt(b"secret", &[3u8; 32], b"A:").unwrap();
        assert!(decrypt(&enc, &[4u8; 32], b"A:").is_err());
    }
}
